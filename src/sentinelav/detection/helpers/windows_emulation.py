# Purpose: Bounded Unicorn execution with import dispatch and in-memory Win32 effects.
# Works with: detection.helpers.pe_image, detection.helpers.winapi_emulator, platform.core.emulation_support
# Used by: detection.helpers.emulation, tests.unit.test_integrated_analysis

"""Bounded Unicorn execution with import dispatch and in-memory Win32 effects."""

import hashlib
import time
from sentinelav.detection.helpers.pe_image import PEImage
from sentinelav.detection.helpers.winapi_emulator import WinAPIModel


def emulate_windows(data, metadata, analyze):
    """Run a Windows program in our minimal emulated Windows and scan what it produces.

    The program is mapped into a Unicorn CPU, its imports are wired to WinAPIModel stubs, and then
    its TLS callbacks and entry point are run within a tight time and instruction budget. Afterwards
    every changed memory page and every virtual file it wrote is scanned. The recorded API events
    (file, registry, network) are returned too, so the caller can spot suspicious behaviour.
    """
    try:
        import unicorn as uc
        from unicorn import x86_const as registers
    except ImportError:
        return dict(
            status='Unavailable',
            omissions=['Optional unicorn dependency unavailable'],
            findings=[],
            api_events=[],
        )
    from sentinelav.platform.core.emulation_support import compatibility

    support = compatibility(uc.__version__)
    if not support['available']:
        return dict(status='Unavailable', omissions=[support['reason']], findings=[], api_events=[])
    result = dict(
        status='Partial',
        omissions=[],
        findings=[],
        api_events=[],
        backend='minimal-unicorn',
        diagnostics=[],
        termination_reason='not_started',
        api_attempts=0,
    )
    if metadata.get('format') != 'PE':
        return dict(status='Not applicable', omissions=[], findings=[], api_events=[])
    try:
        image = PEImage(data, metadata)
        if metadata.get('machine') != ('0x8664' if image.wide else '0x14c'):
            raise ValueError('Architecture mismatch')
        if not image.entry or not 0 < image.entry < image.size or image.base % 4096:
            raise ValueError('Invalid entry/base')
        if image.base + image.size >= (0x600000000000 if image.wide else 0x70000000):
            raise ValueError('Image outside virtual range')
        machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64 if image.wide else uc.UC_MODE_32)
        used = [(image.base, image.base + ((image.size + 4095) & ~4095))]

        def reserve(candidates, size):
            """Pick the first candidate address range that does not overlap anything already mapped."""
            for address in candidates:
                if all(address + size <= begin or address >= end for begin, end in used):
                    used.append((address, address + size))
                    return address
            raise ValueError('No nonoverlapping virtual range')

        heap = reserve(
            (
                [0x300000000000, 0x400000000000, 0x500000000000]
                if image.wide
                else [0x30000000, 0x40000000, 0x50000000]
            ),
            32 * 1024 * 1024,
        )
        stubs = reserve(
            [0x600000000000, 0x610000000000] if image.wide else [0x6D000000, 0x6E000000], 65536
        )
        stack = reserve([0x700000000000] if image.wide else [0x7F000000], 1024 * 1024)
        machine.mem_map(image.base, (image.size + 4095) & ~4095)
        machine.mem_write(image.base, bytes(data[: image.headers]))
        for section in metadata['sections']:
            address = section['virtual_address']
            length = section['raw_bytes']
            if address + length > image.size:
                raise ValueError('Section exceeds image')
            if length:
                machine.mem_write(
                    image.base + address,
                    bytes(data[section['raw_offset'] : section['raw_offset'] + length]),
                )
        machine.mem_map(stack, 1024 * 1024)
        machine.mem_map(stubs, 65536)
        machine.mem_write(stubs, b'\x90' * 65536)
        shim = WinAPIModel(machine, image.wide, registers, stubs, heap, image.base)
        shim.files['c:\\sample\\subject.exe'] = bytearray(data)
        shim.file_bytes = len(data)
        # Point every import-table entry at a stub, so calls into Windows land in our model.
        for item in image.imports() + image.imports(delay=True):
            name = item['name'] or '#' + str(item['ordinal'])
            shim.module(item['library'])
            shim.store_pointer(image.base + item['iat_rva'], shim.bind(item['library'], name))
        sp = stack + 1024 * 1024 - 0x108
        sentinel = stubs + 65520
        # End the translated block before the mapped stub arena boundary.
        # A NOP-only sentinel can make Unicorn fetch the following unmapped
        # page before our code hook gets a chance to stop the routine.
        machine.mem_write(sentinel, b'\xcc')
        shim.store_pointer(sp, sentinel)
        machine.reg_write(registers.UC_X86_REG_RSP if image.wide else registers.UC_X86_REG_ESP, sp)
        dirty = set()
        outcome = {'returned': False, 'budget': False}
        steps = [0]

        def code(engine, address, size, context):
            """Per-instruction hook: stop when the routine returns to our sentinel address, and
            dispatch calls that land on an import stub.
            """
            steps[0] += 1
            if address == sentinel:
                outcome['returned'] = True
                engine.emu_stop()
                return
            if address in shim.stubs:
                result['api_attempts'] += 1
                try:
                    shim.dispatch(address)
                except (ValueError, uc.UcError) as error:
                    result['termination_reason'] = 'unsupported_api'
                    library, name = shim.stubs[address]
                    result['diagnostics'].append(
                        dict(
                            kind='api_stop',
                            library=library[:128],
                            api=name[:128],
                            ip_rva=None,
                            reason=str(error)[:180],
                        )
                    )
                    result['omissions'].append('API model stopped: ' + str(error)[:180])
                    engine.emu_stop()

        def invalid(engine, access, address, length, value, context):
            """Hook for invalid memory access: record where the fault happened and stop."""
            pc = engine.reg_read(
                registers.UC_X86_REG_RIP if image.wide else registers.UC_X86_REG_EIP
            )
            result['termination_reason'] = 'memory_fault'
            result['diagnostics'].append(
                dict(
                    kind='memory_fault',
                    access=int(access),
                    bytes=length,
                    ip_rva=pc - image.base if image.base <= pc < image.base + image.size else None,
                    address_region=(
                        'null'
                        if address < 4096
                        else (
                            'image'
                            if image.base <= address < image.base + image.size
                            else 'unmapped'
                        )
                    ),
                )
            )
            return False

        def written(engine, access, address, length, value, context):
            """Memory-write hook: remember changed pages in the image and heap, up to 256 of them."""
            if image.base <= address < image.base + image.size or heap <= address < shim.next_heap:
                for page in range(address & ~4095, (address + length + 4095) & ~4095, 4096):
                    if len(dirty) < 256:
                        dirty.add(page)
                    else:
                        outcome['budget'] = True
                        engine.emu_stop()

        machine.hook_add(uc.UC_HOOK_CODE, code)
        machine.hook_add(uc.UC_HOOK_MEM_WRITE, written)
        machine.hook_add(uc.UC_HOOK_MEM_INVALID, invalid)
        callbacks = image.tls_callbacks()
        deadline = time.monotonic() + 1.0
        # Run the TLS callbacks first (as Windows does), then the program's entry point, sharing one
        # overall budget.
        for index, routine in enumerate(callbacks + [image.base + image.entry]):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or steps[0] >= 200000:
                result['omissions'].append('Cumulative emulation budget reached')
                break
            outcome['returned'] = False
            machine.reg_write(
                registers.UC_X86_REG_RSP if image.wide else registers.UC_X86_REG_ESP, sp
            )
            shim.store_pointer(sp, sentinel)
            if index < len(callbacks):
                if image.wide:
                    machine.reg_write(registers.UC_X86_REG_RCX, image.base)
                    machine.reg_write(registers.UC_X86_REG_RDX, 1)
                    machine.reg_write(registers.UC_X86_REG_R8, 0)
                else:
                    for argument, value in enumerate((image.base, 1, 0)):
                        shim.store_pointer(sp + 4 + argument * 4, value)
            try:
                machine.emu_start(
                    routine,
                    0,
                    timeout=max(1, int(remaining * 1000000)),
                    count=max(1, 200000 - steps[0]),
                )
            except uc.UcError as error:
                if result['termination_reason'] == 'not_started':
                    result['termination_reason'] = 'cpu_fault'
                result['omissions'].append('CPU stopped: ' + str(error)[:180])
                break
            if shim.exited or not outcome['returned']:
                break
        if not shim.exited and not outcome['returned']:
            result['omissions'].append('Instruction/time/unsupported-path coverage incomplete')
        if outcome['budget']:
            result['omissions'].append('Changed-page budget reached')
        seen = set()
        for address in sorted(dirty):
            boundary = (
                image.base + image.size
                if image.base <= address < image.base + image.size
                else shim.next_heap
            )
            payload = bytes(machine.mem_read(address, min(8192, boundary - address)))
            digest = hashlib.sha256(payload).digest()
            if digest in seen:
                continue
            seen.add(digest)
            reasons, matches, errors = analyze(payload)
            result['omissions'].extend(errors)
            if reasons:
                result['findings'].append(
                    dict(virtual_address=hex(address), reasons=reasons, yara_matches=matches)
                )
        for path, content in shim.files.items():
            if path == 'c:\\sample\\subject.exe':
                continue
            reasons, matches, errors = analyze(bytes(content))
            result['omissions'].extend(errors)
            if reasons:
                result['findings'].append(
                    dict(virtual_file=path[:512], reasons=reasons, yara_matches=matches)
                )
        result.update(
            changed_pages=len(dirty),
            api_events=shim.events,
            api_calls=shim.calls,
            instructions_observed=steps[0],
            tls_callbacks_declared=len(callbacks),
        )
        if result['termination_reason'] == 'not_started':
            if shim.exited:
                result['termination_reason'] = 'exit'
            elif outcome['returned']:
                result['termination_reason'] = 'returned'
            elif outcome['budget']:
                result['termination_reason'] = 'changed_page_limit'
            elif steps[0] >= 200000:
                result['termination_reason'] = 'instruction_limit'
            elif time.monotonic() >= deadline:
                result['termination_reason'] = 'time_limit'
            else:
                result['termination_reason'] = 'incomplete_path'
        result['omissions'].extend(shim.omissions)
        result['omissions'].append(
            'Win32 subset: no full DLL loader, PEB/TEB, static TLS storage, multithreading or Windows exceptions'
        )
    except (ValueError, UnicodeError, uc.UcError) as error:
        result['termination_reason'] = 'invalid_image_or_mapping'
        result['omissions'].append(str(error)[:250])
    result['omissions'] = list(dict.fromkeys(result['omissions']))[:64]
    return result

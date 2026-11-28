# Purpose: Optional bounded Unicorn PE emulation. No guest instructions execute natively.
# Works with: detection.helpers.speakeasy_backend, detection.helpers.windows_emulation, platform.core.emulation_support
# Used by: detection.core.advanced_pipeline

"""Optional bounded Unicorn PE emulation. No guest instructions execute natively.

This is a CPU-level unpacking pass, not a complete Windows environment. Unhandled
imports, TLS, exceptions and instruction/time limits are explicit coverage gaps.
"""

import struct


def cpu_emulate(data, metadata, analyze):
    """Run the first part of a Windows program on a virtual CPU to catch code that unpacks itself.

    Many malicious programs are 'packed': the real code is compressed or encrypted and only appears
    in memory once the program starts. Here we load the program into the Unicorn CPU emulator
    (nothing runs on the real processor), let it execute for a very short, bounded time, and then
    scan every executable memory page it changed. If the unpacked code matches a detection rule, it
    is reported as a finding.

    Returns a dictionary with a status, the list of findings, and the omissions describing what was
    not covered.
    """
    try:
        import unicorn as uc
        from unicorn import x86_const as registers
    except ImportError:
        return dict(
            status='Unavailable',
            omissions=['Optional unicorn package is not installed'],
            findings=[],
        )
    from sentinelav.platform.core.emulation_support import compatibility

    support = compatibility(uc.__version__)
    if not support['available']:
        return dict(status='Unavailable', omissions=[support['reason']], findings=[])
    result = dict(
        status='Partial',
        omissions=['Windows APIs, TLS and exception dispatch are not emulated'],
        findings=[],
        changed_pages=0,
    )
    if metadata.get('format') != 'PE':
        return dict(status='Not applicable', omissions=[], findings=[])
    if metadata.get('machine') not in ('0x14c', '0x8664'):
        result['omissions'].append('Unsupported CPU architecture')
        return result
    # Read the bits of the PE header we need: 32 or 64-bit, preferred load address, image size and
    # entry point.
    offset = struct.unpack_from('<I', data, 0x3C)[0] + 24
    optional_size = struct.unpack_from('<H', data, offset - 4)[0]
    if optional_size < 64:
        result['omissions'].append('Incomplete PE optional header')
        return result
    magic = struct.unpack_from('<H', data, offset)[0]
    wide = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        return result
    base = struct.unpack_from('<Q' if wide else '<I', data, offset + (24 if wide else 28))[0]
    size, headers = struct.unpack_from('<II', data, offset + 56)
    entry = metadata.get('entrypoint_rva')
    if not entry or not 0 < entry < size or not 4096 <= size <= 64 * 1024 * 1024 or base % 4096:
        result['omissions'].append('Invalid/oversized image mapping')
        return result
    if not wide and base + size >= 0x70000000:
        result['omissions'].append('Image outside supported emulation range')
        return result
    if wide and base + size >= 0x600000000000:
        result['omissions'].append('Image outside supported emulation range')
        return result
    machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64 if wide else uc.UC_MODE_32)
    dirty = set()
    stack = 0x700000000000 if wide else 0x7F000000
    # Map the program into the emulator's memory the way Windows would: headers first, then each
    # section at its virtual address.
    try:
        machine.mem_map(base, (size + 4095) & ~4095)
        machine.mem_write(base, bytes(data[: min(headers, len(data), size)]))
        for section in metadata['sections']:
            address = section['virtual_address']
            length = section['raw_bytes']
            if address + length > size:
                raise ValueError('Section exceeds emulated image')
            if length:
                machine.mem_write(
                    base + address,
                    bytes(data[section['raw_offset'] : section['raw_offset'] + length]),
                )
        machine.mem_map(stack, 1024 * 1024)
        machine.reg_write(
            registers.UC_X86_REG_RSP if wide else registers.UC_X86_REG_ESP,
            stack + 1024 * 1024 - 0x100,
        )

        def written(engine, access, address, length, value, context):
            """Memory-write hook: remember which pages inside the program image were changed, stopping
            after 256.
            """
            if base <= address < base + size:
                for page in range(address & ~4095, (address + length + 4095) & ~4095, 4096):
                    if len(dirty) < 256:
                        dirty.add(page)
                    else:
                        engine.emu_stop()

        machine.hook_add(uc.UC_HOOK_MEM_WRITE, written)
        try:
            machine.emu_start(base + entry, base + size, timeout=500000, count=100000)
        except uc.UcError as error:
            result['omissions'].append('Emulation stopped: ' + str(error)[:160])
        # Only pages that belong to executable sections matter; changed data pages are ignored.
        for address in sorted(dirty):
            if not any(
                s['executable']
                and base + s['virtual_address'] <= address + 4095
                and address < base + s['virtual_address'] + max(s['virtual_bytes'], s['raw_bytes'])
                for s in metadata['sections']
            ):
                continue
            payload = bytes(machine.mem_read(address, min(4096, base + size - address)))
            reasons, matches, errors = analyze(payload)
            result['omissions'].extend(errors)
            if reasons:
                result['findings'].append(
                    dict(rva=address - base, reasons=reasons, yara_matches=matches)
                )
        result['changed_pages'] = len(dirty)
        result['omissions'].append(
            'CPU pass bounded to 100000 instructions, 0.5 seconds and 256 changed pages; completion does not prove safety'
        )
    except (uc.UcError, ValueError) as error:
        result['omissions'].append(str(error)[:200])
    return result


def emulate(data, metadata, analyze, backend='speakeasy', profile='background'):
    """Run the chosen emulator on a Windows program: 'speakeasy' (the fuller Windows model, the
    default) or 'minimal' (our own small model).
    """
    if backend == 'speakeasy':
        from sentinelav.detection.helpers.speakeasy_backend import emulate as run

        return run(data, metadata, analyze, profile)
    if backend != 'minimal':
        raise ValueError('Unsupported emulator backend')
    from sentinelav.detection.helpers.windows_emulation import emulate_windows

    return emulate_windows(data, metadata, analyze)

# Purpose: Strict, bounded Windows modeling. No mounted host volumes or API delegation.
# Works with: platform.emulation_support
# Used by: detection.emulation, tests.unit.test_speakeasy_backend

"""Strict, bounded Windows modeling. No mounted host volumes or API delegation."""

import hashlib
import threading
import types

PROFILES = {'background': (3, 1000000), 'deep': (15, 5000000), 'lab': (30, 10000000)}


def emulate(data, metadata, analyze, profile='background'):
    """Run a Windows program inside the Speakeasy Windows emulator and scan what it reveals.

    Speakeasy models a Windows environment in software, so the program's code runs without touching
    the real machine. We run it strictly: any Windows function Speakeasy only pretends to support
    stops the run instead of faking success. Afterwards we scan the memory pages the program changed
    and any files it 'wrote' to the virtual disk. The profile ('background', 'deep' or 'lab') sets
    the time and instruction budget.
    """
    if profile not in PROFILES:
        raise ValueError('Unknown emulator budget profile')
    result = dict(
        status='Partial',
        backend='speakeasy-strict-v1',
        omissions=[],
        findings=[],
        api_events=[],
        diagnostics=[],
        termination_reason='not_started',
        api_calls=0,
        api_attempts=0,
        instructions_observed=0,
        changed_pages=0,
    )
    if metadata.get('format') != 'PE':
        return {**result, 'status': 'Not applicable'}
    try:
        import unicorn
        from sentinelav.platform.emulation_support import compatibility

        support = compatibility(unicorn.__version__)
        if not support['available']:
            return {**result, 'status': 'Unavailable', 'omissions': [support['reason']]}
        import speakeasy
        from speakeasy.windows.api_resolution import (
            HandlerImplementation,
            UnsupportedImplementation,
        )
    except ImportError as error:
        return {
            **result,
            'status': 'Unavailable',
            'omissions': ['Speakeasy dependency unavailable: ' + str(error)],
        }
    seconds, instructions = PROFILES[profile]
    stop = threading.Event()
    engine = None
    dirty = {}
    seen = set()
    config = dict(
        max_run_time=seconds,
        max_total_time=seconds,
        max_instructions=instructions,
        max_api_calls=10000,
        random_seed=0,
        snapshot_memory_regions=False,
        analysis=dict(strings=False, memory_tracing=False, coverage=False),
        modules=dict(functions_always_exist=False, modules_always_exist=False),
    )
    try:
        engine = speakeasy.Speakeasy(config=config, exit_event=stop)
        module = engine.load_module(data=bytes(data), filename='subject.exe')
        resolver = engine.emu.resolve_api_implementation

        def strict_resolve(instance, dll, name):
            """Replacement for Speakeasy's API resolver: allow only fully implemented Windows functions
            and record each call.
            """
            result['api_attempts'] += 1
            implementation = resolver(dll, name)
            if not isinstance(implementation, HandlerImplementation):
                result['diagnostics'].append(
                    dict(kind='unsupported_api', library=str(dll)[:128], api=str(name)[:128])
                )
                result['termination_reason'] = 'unsupported_api'
                return UnsupportedImplementation()
            result['api_calls'] += 1
            if len(result['api_events']) < 64:
                result['api_events'].append(
                    dict(
                        kind='modeled_api',
                        library=str(dll)[:128],
                        api=str(name)[:128],
                        modeled=True,
                    )
                )
            return implementation

        engine.emu.resolve_api_implementation = types.MethodType(strict_resolve, engine.emu)

        def written(emulator, access, address, size, value):
            """Memory-write hook: remember the original contents of each page the first time it is
            written, up to 256 pages.
            """
            for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
                if page in dirty:
                    continue
                if len(dirty) >= 256:
                    result['termination_reason'] = 'changed_page_limit'
                    stop.set()
                    return
                try:
                    dirty[page] = engine.mem_read(page, 4096)
                except Exception:
                    dirty[page] = None

        engine.add_mem_write_hook(written)
        engine.run_module(module, all_entrypoints=False)
        report = engine.get_report().model_dump(mode='json')
        for entry in report.get('entry_points', []):
            result['instructions_observed'] += entry.get('instruction_count') or 0
            if entry.get('error'):
                result['diagnostics'].append(dict(kind='execution_stop', error=entry['error']))
        for address, before in dirty.items():
            try:
                payload = engine.mem_read(address, 4096)
            except Exception:
                continue
            if payload == before:
                continue
            result['changed_pages'] += 1
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
        expanded = 0
        for index, virtual in enumerate(engine.emu.get_dropped_files()):
            if index >= 64:
                result['omissions'].append('Virtual file count limit')
                break
            if (
                virtual.get_size() > 4 * 1024 * 1024
                or expanded + virtual.get_size() > 64 * 1024 * 1024
            ):
                result['omissions'].append('Virtual file byte limit')
                continue
            payload = bytes(virtual.get_contents())
            expanded += len(payload)
            reasons, matches, errors = analyze(payload)
            result['omissions'].extend(errors)
            if reasons:
                result['findings'].append(
                    dict(virtual_file_index=index, reasons=reasons, yara_matches=matches)
                )
        if result['termination_reason'] == 'not_started':
            if result['diagnostics']:
                result['termination_reason'] = 'execution_fault'
            elif result['instructions_observed'] >= instructions:
                result['termination_reason'] = 'instruction_limit'
            else:
                result['termination_reason'] = 'modeled_run_ended'
        result['omissions'].extend(
            'Speakeasy execution stop: ' + str(item)[:300] for item in result['diagnostics'][:16]
        )
        result['omissions'].append(
            'Modeled Windows environment; declaration-only API success stubs disabled. No general CLR, kernel or full Windows equivalence.'
        )
    except Exception as error:
        result['termination_reason'] = 'backend_error'
        result['omissions'].append('Speakeasy: ' + str(error)[:350])
    finally:
        if engine:
            try:
                engine.shutdown()
            except Exception as error:
                result['omissions'].append('Emulator shutdown: ' + str(error)[:160])
    result['diagnostics'] = result['diagnostics'][:32]
    result['omissions'] = list(dict.fromkeys(result['omissions']))[:64]
    return result

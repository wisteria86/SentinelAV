# Purpose: Explicit guest-only runtime orchestration. Never invoked by ordinary scanning.
# Works with: detection.inspection, lab.corpus_evaluation, monitoring.monitoring, monitoring.sequences,
#   updates.artifacts
# Used by: entrypoint, lab.qualification.guest_inventory, lab.qualification.guest_telemetry,
#   tests.unit.test_runtime_guards

"""Explicit guest-only runtime orchestration. Never invoked by ordinary scanning.

Requires an existing disposable offline Windows Sandbox. Reports stay guest-local;
the host reset controller must discard that guest after every runtime job.
"""

import ctypes
from ctypes import wintypes
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace
import time
import uuid
from sentinelav.lab.corpus_evaluation import verified_offline_guest, unlinked, MAX_BYTES

AUTHORIZATION = 'RUN_ONLY_IN_DISPOSABLE_OFFLINE_GUEST'


def resolve_sample(job, base):
    """Find the specimen file for a runtime job: an explicit path, or the guest corpus entry with the
    job's SHA-256.
    """
    if job.get('sample'):
        return Path(job['sample']).absolute()
    from sentinelav.updates.artifacts import bounded_json
    from sentinelav.lab.corpus_evaluation import load_manifest

    pointer = bounded_json(base / 'static-corpus-latest.json', 16384)
    report = Path(pointer['report']).absolute()
    unlinked(report)
    if not report.resolve().is_relative_to(base):
        raise ValueError('Corpus report escapes guest workspace')
    manifest = report.parent / 'corpus/manifest.json'
    inventory, _ = load_manifest(manifest)
    matches = [row for row in inventory['files'] if row['sha256'] == job['sha256']]
    if len(matches) != 1:
        raise ValueError('Select one existing guest corpus specimen by exact SHA-256')
    return manifest.parent / matches[0]['path']


def run_job(job, *, _guest_check=None, _health_check=None):
    """Run one malware specimen inside the disposable offline test guest and record what it does.

    The job must carry the explicit authorization string and we must really be inside the offline
    guest. The specimen is copied to a fresh folder, started suspended, placed in a job object
    (memory and process limits), then resumed and observed through Sysmon for the time budget.
    Finally it is stopped and a report is written. The guest must be discarded afterwards.
    """
    if (
        not isinstance(job, dict)
        or job.get('schema') != 1
        or set(job)
        - {'schema', 'authorization', 'sample', 'sha256', 'seconds', 'process_limit', 'arguments'}
    ):
        raise ValueError('Expected a schema 1 runtime job with explicit supported fields')
    if not isinstance(job.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', job['sha256']):
        raise ValueError('Expected lowercase specimen SHA-256')
    if job.get('authorization') != AUTHORIZATION or not (_guest_check or verified_offline_guest)():
        raise ValueError('Explicit authorization and verified offline guest required')
    base = Path('C:/SentinelAV-Test').resolve()
    sample = resolve_sample(job, base)
    unlinked(sample)
    if not sample.resolve().is_relative_to(base) or not sample.is_file():
        raise ValueError('Sample must already reside inside the guest test workspace')
    seconds = job.get('seconds', 30)
    if type(seconds) is not int or not 1 <= seconds <= 600:
        raise ValueError('Runtime budget must be 1..600 seconds')
    process_limit = job.get('process_limit', 2)
    if type(process_limit) is not int or not 1 <= process_limit <= 32:
        raise ValueError('Invalid runtime process limit')
    arguments = job.get('arguments', [])
    if (
        not isinstance(arguments, list)
        or len(arguments) > 16
        or any(not isinstance(a, str) or len(a) > 4096 or '\0' in a for a in arguments)
    ):
        raise ValueError('Invalid approved workflow arguments')
    with sample.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if (
        len(data) > MAX_BYTES
        or hashlib.sha256(data).hexdigest() != job['sha256']
        or not data.startswith(b'MZ')
    ):
        raise ValueError('Runtime sample identity/format mismatch')
    workspace = base / ('Runtime-' + uuid.uuid4().hex)
    unlinked(workspace)
    workspace.mkdir(exist_ok=False)
    target = workspace / 'subject.exe'
    with target.open('xb') as stream:
        stream.write(data)
    report = dict(
        schema=1,
        sample_sha256=job['sha256'],
        status='Starting',
        events=[],
        omissions=[],
        guest_disposal_required=True,
        automatic_response=False,
    )
    from sentinelav.monitoring.monitoring import SysmonReader
    from sentinelav.monitoring.sequences import BehaviorCorrelator, parse_event

    reader = SysmonReader()
    correlator = BehaviorCorrelator(lambda event: report['events'].append(event))
    try:
        reader.poll()
    except Exception as error:
        report['omissions'].append('Sysmon unavailable: ' + str(error)[:300])
        reader = None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)

    class Startup(ctypes.Structure):
        """STARTUPINFOW structure for CreateProcessW."""

        _fields_ = [
            ('cb', wintypes.DWORD),
            ('reserved', wintypes.LPWSTR),
            ('desktop', wintypes.LPWSTR),
            ('title', wintypes.LPWSTR),
            ('x', wintypes.DWORD),
            ('y', wintypes.DWORD),
            ('xs', wintypes.DWORD),
            ('ys', wintypes.DWORD),
            ('charsx', wintypes.DWORD),
            ('charsy', wintypes.DWORD),
            ('fill', wintypes.DWORD),
            ('flags', wintypes.DWORD),
            ('show', wintypes.WORD),
            ('reservedbytes', wintypes.WORD),
            ('reservedptr', ctypes.c_void_p),
            ('stdin', wintypes.HANDLE),
            ('stdout', wintypes.HANDLE),
            ('stderr', wintypes.HANDLE),
        ]

    class Info(ctypes.Structure):
        """PROCESS_INFORMATION structure filled in by CreateProcessW."""

        _fields_ = [
            ('process', wintypes.HANDLE),
            ('thread', wintypes.HANDLE),
            ('pid', wintypes.DWORD),
            ('tid', wintypes.DWORD),
        ]

    kernel.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(Startup),
        ctypes.POINTER(Info),
    ]
    kernel.CreateProcessW.restype = wintypes.BOOL
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.ResumeThread.restype = wintypes.DWORD
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    startup = Startup()
    startup.cb = ctypes.sizeof(startup)
    info = Info()
    owned_job = None
    try:
        # Suspended creation closes the launch-to-job-assignment escape window.
        import subprocess

        command_line = ctypes.create_unicode_buffer(
            subprocess.list2cmdline([str(target), *arguments])
        )
        if not kernel.CreateProcessW(
            str(target),
            command_line,
            None,
            None,
            False,
            0x4 | 0x08000000,
            None,
            str(workspace),
            ctypes.byref(startup),
            ctypes.byref(info),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        from sentinelav.detection.inspection import WindowsJob

        owned_job = WindowsJob(
            SimpleNamespace(_handle=info.process), memory=1024**3, process_limit=process_limit
        )
        if kernel.ResumeThread(info.thread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        report['status'] = 'Running'
        report['root_pid'] = info.pid
        process_guids = set()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if _health_check and not _health_check():
                raise RuntimeError('Required independent telemetry became unavailable')
            if reader:
                try:
                    for row in reader.poll():
                        event = parse_event(row['Xml'])
                        # The correlator emits only attributed chains; the
                        # report includes unfiltered guest telemetry as evidence.
                        if len(report['events']) < 1000:
                            report['events'].append(
                                dict(id=event['id'], record=event['record'], fields=event['fields'])
                            )
                        fields = event['fields']
                        guid = fields.get('ProcessGuid')
                        if event['id'] == 1 and (
                            fields.get('ParentProcessGuid') in process_guids
                            or (
                                fields.get('ProcessId') == str(info.pid)
                                and fields.get('Image', '').casefold() == str(target).casefold()
                            )
                        ):
                            process_guids.add(guid)
                        if guid and guid in process_guids:
                            correlator.consume(event)
                except Exception as error:
                    report['omissions'].append('Telemetry collection stopped: ' + str(error)[:300])
                    reader = None
            if kernel.WaitForSingleObject(info.process, 500) == 0:
                time.sleep(0.5)
        code = wintypes.DWORD()
        kernel.GetExitCodeProcess(info.process, ctypes.byref(code))
        report['root_exit_code'] = code.value
        report['status'] = 'Root exited' if code.value != 259 else 'Runtime budget reached'
        report['verdict'] = (
            'Review'
            if any(e.get('level') == 'Alert' for e in report['events'])
            else 'Indeterminate'
        )
        report['classification_limit'] = (
            'Runtime policy alerts are suspicion; no observed alert is not proof of safety.'
        )
        report['omissions'].append(
            'Guest-wide telemetry may include unrelated processes; absence of alerts is not a benign verdict. Job limits may prevent child behavior.'
        )
    except Exception as error:
        report['status'] = 'Incomplete'
        report['omissions'].append(str(error)[:500])
    finally:
        if owned_job:
            owned_job.close()
        elif info.process:
            kernel.TerminateProcess(info.process, 1)
        for handle in (info.thread, info.process):
            if handle:
                kernel.CloseHandle(handle)
        (workspace / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    result = dict(
        report=str(workspace / 'report.json'),
        status=report['status'],
        guest_disposal_required=True,
        verdict=report.get('verdict', 'Indeterminate'),
        alerts=sum(e.get('level') == 'Alert' for e in report['events']),
        event_count=len(report['events']),
        omissions=len(report['omissions']),
    )
    (base / 'runtime-latest.json').write_text(json.dumps(result), encoding='utf-8')
    return result

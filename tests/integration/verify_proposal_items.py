# Purpose: Check the proposal's remaining items end to end on harmless fixtures, with nothing mocked.
# Works with: monitoring.monitoring, monitoring.core.behavior, response.response, platform.runtime, data.reporting
# Used by: the CLI and docs/deliverables/RUNNING.md

"""Check the proposal's remaining items end to end on harmless fixtures, with nothing mocked.

The only program started is a private copy of Windows ping, so the safeguarded stop
can be proven on something harmless. Run with TEMP on the work drive.
"""

from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from sentinelav.data.reporting import render_report, snapshot
from sentinelav.data.storage import Store
from sentinelav.monitoring.core.behavior import create_canary
from sentinelav.monitoring.monitoring import Monitor
from sentinelav.paths import PROJECT_ROOT, RESOURCE_ROOT
from sentinelav.platform.runtime import ZONE, run_scheduled
from sentinelav.response.response import ResponseService

MARKER = 'SENTINELAV_DEMO_THREAT_7C23A'
results = []


def check(name, passed, detail=''):
    results.append(dict(check=name, passed=bool(passed)))
    print(
        ('PASS ' if passed else 'FAIL ') + name + (': ' + str(detail)[:220] if detail else ''),
        flush=True,
    )


def wait_for(condition, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.1)
    return None


def monitored(root, processes=False, **extra):
    folder = root / 'watched'
    folder.mkdir(exist_ok=True)
    state = root / 'state'
    state.mkdir(exist_ok=True)
    events = []
    config = dict(
        folders=[str(folder)],
        processes=processes,
        sysmon=False,
        behavior=True,
        network=False,
        signatures=RESOURCE_ROOT / 'signatures.json',
        rules=RESOURCE_ROOT / 'rules',
        max_mb=100,
        exclusions=[str(state)],
        trusted_hashes=[],
        inspection_options=dict(model=False, neural_gray=False),
        auto_response=dict(enabled=False),
        data_dir=str(state),
        **extra,
    )
    monitor = Monitor(config, events.append, lambda value: None)
    thread = threading.Thread(target=monitor.run, daemon=True)
    thread.start()
    wait_for(lambda: any(event['kind'] == 'Monitoring started' for event in events))
    return folder, events, monitor, thread


def stop(monitor, thread):
    monitor.stop.set()
    thread.join(30)


def ransomware(root):
    area = root / 'ransomware'
    area.mkdir()
    (area / 'watched').mkdir()
    canary = create_canary(area / 'watched')
    folder, events, monitor, thread = monitored(area, canaries=[canary])
    try:
        Path(canary['path']).write_text('changed by the test')
        changed = wait_for(
            lambda: [
                e
                for e in events
                if e['kind'] == 'Behavioral risk' and 'Canary changed' in e['details']
            ]
        )
        check(
            'Ransomware: changing a canary raises a warning',
            changed,
            changed and changed[0]['details'],
        )
        names = [folder / f'document{index}.txt' for index in range(45)]
        for path in names:
            path.write_text('ordinary content')
        for path in names:
            path.rename(path.with_suffix('.locked'))
        alert = wait_for(
            lambda: [e for e in events if e['kind'] == 'Behavioral risk' and e['level'] == 'Alert']
        )
        check(
            'Ransomware: canary plus a rename burst raises an alert with a score',
            alert and alert[0].get('score', 0) >= 70,
            alert and alert[0]['details'],
        )
    finally:
        stop(monitor, thread)


def process_tracking(root):
    area = root / 'processes'
    area.mkdir()
    folder, events, monitor, thread = monitored(area, processes=True)
    child = None
    try:
        wait_for(lambda: monitor.seen_processes is not None)
        child = subprocess.Popen(
            [str(Path(os.environ['SystemRoot']) / 'System32/PING.EXE'), '-n', '20', '127.0.0.1'],
            stdout=subprocess.DEVNULL,
        )
        seen = wait_for(
            lambda: [
                e
                for e in events
                if e.get('pid') == child.pid
                and e['kind'] in ('Process started', 'Process start event')
            ]
        )
        check(
            'Processes: a new process and its parent are observed',
            seen and seen[0].get('parent') == os.getpid(),
            seen and seen[0]['details'],
        )
    finally:
        if child:
            child.kill()
            child.wait()
        stop(monitor, thread)


def safeguarded_stop(root):
    area = root / 'stop'
    area.mkdir()
    resources = area / 'resources'
    resources.mkdir()
    program = area / 'harmless-copy.exe'
    shutil.copy2(Path(os.environ['SystemRoot']) / 'System32/PING.EXE', program)
    shutil.copytree(RESOURCE_ROOT / 'rules', resources / 'rules')
    (resources / 'signatures.json').write_text('{}', encoding='utf-8')
    store = Store(area / 'sentinelav.db')
    store.set('inspection_options', dict(model=False, neural_gray=False))
    service = ResponseService(store, resources)
    identity = hashlib.sha256(program.read_bytes()).hexdigest()
    child = subprocess.Popen([str(program), '-n', '60', '127.0.0.1'], stdout=subprocess.DEVNULL)
    try:
        import psutil

        created = psutil.Process(child.pid).create_time()
        detection = dict(path=str(program), sha256=identity, reasons=['Fixture'])
        try:
            service.terminate(child.pid, created, detection)
            refused = False
        except ValueError:
            refused = True
        check(
            'Stop: refused without a fresh file verdict, and the process survives',
            refused and child.poll() is None,
        )
        (resources / 'signatures.json').write_text(
            json.dumps({identity: 'Evaluation fixture'}), encoding='utf-8'
        )
        try:
            service.terminate(child.pid, created + 5, detection)
            identity_guard = False
        except ValueError:
            identity_guard = True
        check(
            'Stop: refused when the process identity does not match',
            identity_guard and child.poll() is None,
        )
        result = service.terminate(child.pid, created, detection)
        check(
            'Stop: a verified process is stopped and audited',
            result['state'] == 'Terminated'
            and child.wait(5) is not None
            and any(e['kind'] == 'Process terminated' for e in store.events(50)),
        )
        try:
            service.terminate(os.getpid(), psutil.Process().create_time(), detection)
            self_guard = False
        except ValueError:
            self_guard = True
        check('Stop: SentinelAV cannot be made to stop itself', self_guard)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        store.db.close()


def scheduled_and_reports(root):
    area = root / 'schedule'
    area.mkdir()
    folder = area / 'scan'
    folder.mkdir()
    data = area / 'state'
    data.mkdir()
    (folder / 'demo.txt').write_text(MARKER)
    (
        (folder / '<script>x.txt').write_text('ordinary')
        if os.name != 'nt'
        else (folder / 'note.txt').write_text('ordinary')
    )
    store = Store(data / 'sentinelav.db')
    store.set('inspection_options', dict(model=False, neural_gray=False))
    due = (datetime.now(ZONE) - timedelta(minutes=5)).isoformat()
    store.set(
        'schedule',
        dict(
            enabled=True,
            hour=1,
            minute=0,
            kind='Folder',
            folder=str(folder),
            next_run=due,
            windows_task=False,
        ),
    )
    store.db.close()
    run_scheduled(data)
    store = Store(data / 'sentinelav.db')
    try:
        history = store.history()
        check(
            'Schedule: a due scan runs headless and records history',
            history and history[0]['scanned'] == 2 and len(history[0]['detections']) == 1,
        )
        check(
            'Schedule: the next run moves forward',
            datetime.fromisoformat(store.get('schedule', {})['next_run']) > datetime.now(ZONE),
        )
        check(
            'Schedule: completion is logged as an event',
            any(
                e['kind'] == 'Scheduled scan completed' and e['level'] == 'Alert'
                for e in store.events(20)
            ),
        )
        data_snapshot = snapshot(store)
        html = render_report(data_snapshot, 'html')
        csv = render_report(data_snapshot, 'csv')
        raw = render_report(data_snapshot, 'json')
        check(
            'Reports: HTML explains verdict, score and reason',
            'Why it was flagged' in html and 'Malicious' in html and 'demo.txt' in html,
        )
        check(
            'Reports: CSV has scan totals',
            'Suspicious' in csv.splitlines()[0] and len(csv.splitlines()) >= 2,
        )
        check(
            'Reports: JSON keeps full evidence',
            json.loads(raw)['scans'][0]['detections'][0]['indicators'],
        )
    finally:
        store.db.close()


def command_line(root):
    area = root / 'cli'
    area.mkdir()
    (area / 'scan').mkdir()
    (area / 'scan' / 'demo.txt').write_text(MARKER)
    (area / 'clean').mkdir()
    (area / 'clean' / 'note.txt').write_text('ordinary notes')

    def run(target):
        return subprocess.run(
            [
                sys.executable,
                str(PROJECT_ROOT / 'app.py'),
                '--scan',
                str(target),
                '--data-dir',
                str(area / 'state'),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

    flagged = run(area / 'scan')
    report = json.loads(flagged.stdout)
    check(
        'Command line: findings exit 1 and print explained JSON',
        flagged.returncode == 1
        and report['detections'][0]['score'] == 100
        and report['detections'][0]['reasons'],
        report['detections'][0].get('threat_name'),
    )
    check('Command line: a clean folder exits 0', run(area / 'clean').returncode == 0)
    check('Command line: a bad target exits 2', run('not-absolute').returncode == 2)


def main():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for step in (
            ransomware,
            process_tracking,
            safeguarded_stop,
            scheduled_and_reports,
            command_line,
        ):
            try:
                step(root)
            except Exception as error:
                check(step.__name__ + ' completed', False, f'{type(error).__name__}: {error}')
    failed = [item for item in results if not item['passed']]
    print(json.dumps(dict(checks=len(results), failed=len(failed))))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())

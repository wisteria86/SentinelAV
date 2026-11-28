# Purpose: Safe behavioral-rule evaluation; no malware, network traffic or process response.
# Works with: lab.lab, monitoring.core.behavior, paths
# Used by: tests.unit.test_advanced_evaluation

"""Safe behavioral-rule evaluation; no malware, network traffic or process response."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import uuid
from sentinelav.lab.lab import SimulationRunner, PROFILES
from sentinelav.monitoring.core.behavior import BehaviorEngine, create_canary
from sentinelav.paths import PROJECT_ROOT, RESOURCE_ROOT


def controls(workspace):
    """Label injected telemetry honestly; these checks do not validate collection."""
    rows = []

    def check(name, action, expected):
        events = []
        engine = BehaviorEngine(events.append, clock=lambda: 100)
        action(engine)
        observed = [event['level'] for event in events]
        rows.append(
            dict(
                name=name,
                expected_levels=expected,
                observed_levels=observed,
                passed=observed == expected,
                evidence=events,
                telemetry='Synthetic rule input',
            )
        )

    root = workspace.resolve()
    check(
        'Repeated changes to one file are not a distinct-file burst',
        lambda e: [e.file_event('modified', root / 'one.txt', [root], []) for _ in range(50)],
        [],
    )
    check(
        'Ordinary batch writing alone requires corroboration before an alert',
        lambda e: [e.file_event('modified', root / f'file-{i}.txt', [root], []) for i in range(35)],
        ['Warning'],
    )
    check(
        'Excluded activity produces no warning',
        lambda e: [
            e.file_event('modified', root / f'file-{i}.txt', [root], [root]) for i in range(35)
        ],
        [],
    )
    check(
        'Ordinary process metadata produces no warning',
        lambda e: e.process(
            dict(
                pid=1, create_time=1, name='notepad.exe', exe='C:/Windows/notepad.exe', cmdline=[]
            ),
            'explorer.exe',
        ),
        [],
    )
    # No command is executed: these strings are injected records only.
    check(
        'Office child and encoded-command metadata correlate',
        lambda e: e.process(
            dict(
                pid=2,
                create_time=1,
                name='powershell.exe',
                exe='C:/Temp/powershell.exe',
                cmdline=['powershell.exe', '-enc', 'harmless-placeholder'],
            ),
            'winword.exe',
        ),
        ['Warning', 'Alert'],
    )
    canary = create_canary(root)
    events = []
    engine = BehaviorEngine(events.append, canaries=[canary])
    engine.check_canaries([root], [])
    rows.append(
        dict(
            name='Unchanged real canary produces no warning',
            passed=not events,
            expected_levels=[],
            observed_levels=[e['level'] for e in events],
            evidence=events,
            telemetry='Actual generated canary read',
        )
    )
    return rows


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    output = PROJECT_ROOT / 'artifacts/evaluations' / ('behavior-' + stamp)
    output.mkdir(parents=True, exist_ok=False)
    parent = PROJECT_ROOT / 'artifacts/lab/behavior-evaluation'
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='controls-', dir=parent) as temporary:
        negative_controls = controls(Path(temporary))
    run = SimulationRunner(RESOURCE_ROOT, parent).run(list(PROFILES))
    report = dict(
        created_utc=datetime.now(timezone.utc).isoformat(),
        simulation=run,
        controls=negative_controls,
        passed=run['status'] == 'Checks passed' and all(c['passed'] for c in negative_controls),
        malicious_processes_launched=False,
        network_connections_made=False,
        response_actions=False,
        limitations=[
            'Injected process/network/file events validate scoring, not telemetry collection.',
            'Real edits are confined to generated temporary text/canary files.',
            'A warning on a bulk write is a heuristic review signal, not confirmed malware.',
            'No ransomware prevention or malware protection rate is established.',
        ],
    )
    (output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(
        json.dumps(
            dict(
                passed=report['passed'],
                profiles=[
                    dict(profile=r['profile'], passed=r['passed'], telemetry=r['telemetry'])
                    for r in run['results']
                ],
                controls=len(negative_controls),
                workspace_reset=run['workspace_reset'],
                report=str(output / 'report.json'),
            ),
            indent=2,
        )
    )
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

# Purpose: Measure guest deployment, paired workloads, and long-running continuity.
# Works with: data.storage, lab.qualification.guest_context, lab.qualification.guest_support,
#   lab.qualification.reporting, lab.qualification.telemetry
# Used by: lab.qualification.guest

"""Typed guest-only case executor. Never accepts arbitrary commands or binaries."""

import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from .reporting import redact

BASE = Path('C:/SentinelAV-Test')
from .guest_context import ps
from .guest_support import start_engine


def deployment(root):
    """Install, upgrade, repair and uninstall the app in the guest, checking that user data is kept and
    Defender settings are not touched.
    """
    installer = Path('C:/SentinelAV-Input/Installer.exe')
    if not installer.exists():
        raise FileNotFoundError('Frozen installer not staged')
    destination = root / 'Installed'
    control = root / 'protected-control.txt'
    control.write_text('preserve')
    before = ps(
        'Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,ExclusionPath,ExclusionProcess | ConvertTo-Json -Compress'
    )
    previous = Path('C:/SentinelAV-Input/PreviousInstaller.exe')
    stages = (
        [('fresh', previous), ('upgrade', installer), ('repair', installer)]
        if previous.exists()
        else [('fresh', installer), ('repair', installer)]
    )
    from sentinelav.data.storage import Store

    user = Store(Path(os.environ['LOCALAPPDATA']) / 'SentinelAV/sentinelav.db')
    key = 'evaluation-preserve-' + uuid.uuid4().hex
    user.set(key, 'retained')
    user.db.close()
    for stage, package in stages:
        p = subprocess.run(
            [
                str(package),
                '/VERYSILENT',
                '/SUPPRESSMSGBOXES',
                '/NORESTART',
                '/DIR=' + str(destination),
            ],
            timeout=600,
        )
        if p.returncode or not (destination / 'SentinelAV.exe').exists():
            raise RuntimeError('Installer ' + stage + ' failed')
    p = subprocess.run(
        [str(destination / 'unins000.exe'), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'],
        timeout=300,
    )
    after = ps(
        'Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,ExclusionPath,ExclusionProcess | ConvertTo-Json -Compress'
    )
    user = Store(Path(os.environ['LOCALAPPDATA']) / 'SentinelAV/sentinelav.db')
    retained = user.get(key, None) == 'retained'
    user.db.close()
    return dict(
        lifecycle_verified=p.returncode == 0
        and not (destination / 'SentinelAV.exe').exists()
        and before == after
        and retained
        and previous.exists(),
        protected_controls_changed=int(control.read_text() != 'preserve' or not retained),
        upgrade_verified=previous.exists(),
        skipped=0 if previous.exists() else 1,
        reason=(
            'Fresh/upgrade/repair/uninstall and user-data retention measured'
            if previous.exists()
            else 'Distinct prior-version installer needed for upgrade'
        ),
    )


def performance(root, context):
    """Measure how much real-time protection slows a fixed file workload (five paired runs), plus idle
    CPU and memory use.
    """
    import statistics
    import psutil

    process, data, watch, app = start_engine(root, 'normal', context)
    from sentinelav.monitoring.background import request

    try:
        pairs = []
        payload = b'ordinary file workload\n' * 4096
        for i in range(5):
            values = []
            for enabled in ((False, True) if i % 2 == 0 else (True, False)):
                request(data, 'start' if enabled else 'stop')
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    state = request(data, 'status')
                    if state.get('state') == ('Active' if enabled else 'Off'):
                        break
                    if state.get('state') == 'Failed':
                        raise RuntimeError('Engine failed during workload setup')
                    time.sleep(0.2)
                else:
                    raise RuntimeError('Protected/baseline engine state not established')
                target = watch / f'workload-{i}-{enabled}.txt'
                start = time.perf_counter()
                with target.open('wb') as f:
                    for _ in range(64):
                        f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())
                values.append((enabled, time.perf_counter() - start))
            values = dict(values)
            pairs.append(
                dict(
                    baseline=values[False],
                    protected=values[True],
                    slowdown=values[True] / values[False] - 1,
                )
            )
        p = psutil.Process(process.pid)
        cpu = []
        rss = []
        request(data, 'start')
        watched = {process.pid: p}
        for _ in range(30):
            for child in p.children(recursive=True):
                watched.setdefault(child.pid, child)
            total_cpu = 0
            total_rss = 0
            for pid, child in list(watched.items()):
                try:
                    total_cpu += child.cpu_percent()
                    total_rss += child.memory_info().rss
                except psutil.NoSuchProcess:
                    watched.pop(pid, None)
            cpu.append(total_cpu / (os.cpu_count() or 1))
            rss.append(total_rss)
            time.sleep(1)
        budgets = context['performance_budgets']
        slow = statistics.median(r['slowdown'] for r in pairs)
        return dict(
            pairs=5,
            paired_workloads=pairs,
            median_slowdown=slow,
            slowdown_stddev=statistics.pstdev(r['slowdown'] for r in pairs),
            workload_p95=sorted(r['protected'] for r in pairs)[-1],
            idle_cpu_p95=sorted(cpu)[int(0.95 * len(cpu)) - 1],
            idle_cpu_median=statistics.median(cpu),
            idle_rss_peak=max(rss),
            budgets_passed=slow <= budgets['max_workload_slowdown']
            and statistics.median(cpu) <= budgets['max_idle_cpu_percent']
            and max(rss) <= budgets['max_idle_rss_bytes'],
            qualification_evidence=False,
            skipped=1,
            reason='Fixed file workload only; application launch/install workload inventory required',
        )
    finally:
        try:
            request(data, 'shutdown')
        finally:
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def soak(root, case, context):
    """Keep background protection running for the case duration, checking health, memory and telemetry
    continuity every couple of seconds.
    """
    from .telemetry import TelemetrySession
    from sentinelav.monitoring.background import request

    process, data, watch, app = start_engine(root, 'normal', context)
    collector = (
        Path(os.environ['ProgramFiles']) / 'SentinelAV-Lab-Collector/SentinelAV.Telemetry.exe'
    )
    session = None
    began = time.monotonic()
    samples = []
    total = 0
    last_probe = began
    last_checkpoint = began
    try:
        session = TelemetrySession(collector, root, rolling_summary=True)
        session.probe()
        while time.monotonic() - began < case.seconds:
            if not session.healthy() or process.poll() is not None:
                raise RuntimeError('Protection/telemetry continuity lost')
            result = request(data, 'status')
            if result.get('state') != 'Active':
                raise RuntimeError('Background protection stopped during soak')
            import psutil

            parent = psutil.Process(process.pid)
            rss = sum(
                p.memory_info().rss
                for p in [parent] + parent.children(recursive=True)
                if p.is_running()
            )
            if rss > 1024**3:
                raise RuntimeError(
                    'Background process-tree memory exceeded frozen 1 GiB soak budget'
                )
            total += 1
            samples.append(
                dict(elapsed=time.monotonic() - began, state=result['state'], rss_bytes=rss)
            )
            if len(samples) > 1000:
                samples = samples[-1000:]
            if time.monotonic() - last_probe >= 300:
                session.probe()
                last_probe = time.monotonic()
            if time.monotonic() - last_checkpoint >= 60:
                (root / 'soak-checkpoint.json').write_text(
                    json.dumps(
                        dict(checks=total, recent=samples, health=redact(session.snapshot(0)))
                    )
                )
                last_checkpoint = time.monotonic()
            time.sleep(2)
        m = session.snapshot()
        m.update(
            soak_verified=True,
            seconds=time.monotonic() - began,
            checkpoints=total,
            recent_resource_samples=samples[-20:],
            memory_budget_bytes=1024**3,
        )
        return m, True
    finally:
        if session:
            session.close()
        try:
            request(data, 'shutdown')
        except Exception:
            pass
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

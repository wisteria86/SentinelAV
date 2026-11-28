# Purpose: Probe independent collectors and product monitoring before any live case.
# Works with: lab.qualification.backends, lab.qualification.disk_pressure, lab.qualification.guest_context,
#   lab.qualification.guest_support, lab.qualification.reporting
# Used by: lab.qualification.guest

"""Typed guest-only case executor. Never accepts arbitrary commands or binaries."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from .reporting import redact
from sentinelav.paths import RESOURCE_ROOT

BASE=Path('C:/SentinelAV-Test')
from .guest_context import ps, guard
from .guest_support import selftest,start_engine,prepare


def telemetry_case(root,case,context):
    """Run a telemetry, recovery or live-sample case in the guest, with independent collectors
    watching.

    All three first prove the packaged baseline works, start the background engine and confirm it
    actually inspects a probe file. Then 'telemetry' deliberately kills the collector to check the
    loss is noticed; 'recovery' checks continuity after a GUI close, a worker crash, a service
    restart and a full disk; 'live' runs a sample under observation. Returns (measurements,
    complete).
    """
    from .telemetry import TelemetrySession
    from sentinelav.monitoring.background import request
    collector=Path(os.environ['ProgramFiles'])/'SentinelAV-Lab-Collector/SentinelAV.Telemetry.exe'
    if not collector.exists():raise FileNotFoundError('Protected ETW collector not staged')
    def phase(name):
        """Record the current stage, so a failure report says where it stopped."""
        (root/'probe-phase.json').write_text(json.dumps(dict(stage=name)))
    phase('packaged-baseline');baseline=selftest(root)
    if not baseline['selftest_passed']:raise RuntimeError('Packaged protection/response baseline failed')
    phase('background-engine')
    process,data,watch,app=start_engine(root,case.mode,context,filesystem_only=case.action=='telemetry')
    session=None;writer=None
    try:
        phase('independent-collectors')
        if case.action=='telemetry':
            from .probe_writer import ProbeWriter
            writer=ProbeWriter(root,collector)
        session=TelemetrySession(collector,root,probe_pid=writer.process.pid if writer else None)
        phase('independent-event-probes');session.probe(writer=writer)
        phase('product-monitor-probe')
        deadline=time.monotonic()+45
        while True:
            state=request(data,'status')
            if state.get('state')=='Active' and state.get('stats',{}).get('folders')==1:break
            if state.get('state') in ('Off','Failed') or time.monotonic()>=deadline:
                raise RuntimeError('Product filesystem watcher did not become ready: '+str(state.get('error') or state.get('state')))
            time.sleep(.5)
        probe=watch/'monitor-probe.txt';probe.write_text('ordinary monitored file')
        deadline=time.monotonic()+45;events=[];cursor=0;epoch='';product_gap=False;attestations=[]
        while time.monotonic()<deadline:
            state=request(data,'status');batch=request(data,'poll',cursor=cursor,epoch=epoch)
            events.extend(batch.get('events',[]));cursor=batch['cursor'];epoch=batch['epoch'];product_gap=product_gap or batch.get('gap',False) or bool(batch.get('dropped'))
            attestations=[e['event'] for e in events if e['event'].get('kind')=='Inspection policy attestation'
                and os.path.normcase(e['event'].get('path',''))==os.path.normcase(str(probe))]
            if attestations or state.get('state') in ('Off','Failed') or product_gap:break
            time.sleep(.5)
        if product_gap or state.get('state')!='Active' or not attestations or attestations[-1].get('scanned')!=1:
            diagnostic=dict(state=state.get('state'),error=state.get('error'),stats=state.get('stats'),
                product_gap=product_gap,attestation=attestations[-1] if attestations else None,
                warnings=[e['event'].get('details','')[:160] for e in events if e['event'].get('level')=='Warning'][-8:])
            (root/'probe-phase.json').write_text(json.dumps(dict(stage='product-monitor-probe',diagnostic=diagnostic)))
            raise RuntimeError('Product filesystem inspection was not attested')
        policy=attestations[-1].get('signature_policy',{})
        if policy.get('signature_free') is not (case.mode=='signature_free'):raise RuntimeError('Background scanner mode mismatch')
        if case.mode=='signature_free' and any(policy.get(k) is not False for k in ('hashes','yara','test_markers','amsi','reputation')):raise RuntimeError('Background scanner signature-free policy contaminated')
        m=session.snapshot();m.update(probes_passed=all(session.probes.values()),response_journal_probe_passed=True,
            monitor_state=state,monitor_events=events[-30:],active_auto_response=False,engine_launch=process.evaluation_launch)
        if case.action=='telemetry':
            phase('collector-loss-check')
            # Deliberately stop the owned ETW process; health must reject it.
            session.etw.process.terminate();session.etw.process.wait(5);time.sleep(.5)
            m['loss_failure_detected']=not session.healthy()
            return m,True
        if case.action=='recovery':
            ui=subprocess.Popen([sys.executable,'--data-dir',str(data)],creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(3);ui.terminate();ui.wait(10)
            state=request(data,'status');before=state.get('stats',{}).get('checked',0)
            (watch/'after-gui-close.txt').write_text('harmless continuity fixture')
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                state=request(data,'status')
                if state.get('stats',{}).get('checked',0)>before:break
                time.sleep(.5)
            gui_ok=process.poll() is None and state.get('stats',{}).get('checked',0)>before
            import psutil
            children=psutil.Process(process.pid).children(recursive=True)
            killed=[]
            for child in children:
                try:
                    if '--inspection-worker' in child.cmdline():child.kill();killed.append(child.pid)
                except (psutil.NoSuchProcess,psutil.AccessDenied):pass
            before=state.get('stats',{}).get('checked',0)
            (watch/'after-worker-crash.txt').write_text('harmless worker recovery fixture')
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                state=request(data,'status')
                if state.get('stats',{}).get('checked',0)>before:break
                time.sleep(.5)
            worker_ok=bool(killed) and state.get('stats',{}).get('checked',0)>before
            installer=RESOURCE_ROOT/'Install-ProtectionService.ps1'
            service_ok=False;service_error='';service_probe={}
            try:
                from .backends import quote
                service_ok=ps("if(Get-Service SentinelAVProtection -ErrorAction SilentlyContinue){throw 'Existing service preserved'};& "+quote(installer)+" -WatchFolders @("+quote(watch)+") -PackageRoot 'C:/SentinelAV-Test/App';Restart-Service SentinelAVProtection;Start-Sleep -Seconds 3;if((Get-Service SentinelAVProtection).Status -ne 'Running'){throw 'Service restart failed'};'PASS'",120).endswith('PASS')
                status_path=Path(os.environ['ProgramData'])/'SentinelAVProtection/data/status.json'
                deadline=time.monotonic()+30
                while not status_path.exists() and time.monotonic()<deadline:time.sleep(.5)
                prior=json.loads(status_path.read_text());checked=prior.get('stats',{}).get('checked',0)
                probe_path=watch/'after-protected-service-restart.txt';probe_path.write_text('harmless protected service continuity probe')
                while time.monotonic()<deadline:
                    service_probe=json.loads(status_path.read_text())
                    if service_probe.get('stats',{}).get('checked',0)>checked:break
                    time.sleep(.5)
                service_ok=service_ok and service_probe.get('account')=='LocalService' and time.time()-service_probe.get('heartbeat',0)<6 and service_probe.get('stats',{}).get('checked',0)>checked and service_probe.get('dropped_service_events',0)==0
            except Exception as e:service_error=str(e)
            from .disk_pressure import test as disk_pressure_test
            try:disk=disk_pressure_test(root,context)
            except Exception as e:disk=dict(disk_full_verified=False,error=type(e).__name__+': '+str(e))
            m.update(recovery_verified=gui_ok and worker_ok and service_ok and disk.get('disk_full_verified',False),gui_continuity=gui_ok,worker_recovered=worker_ok,
                killed_owned_workers=killed,service_restart_verified=service_ok,service_error=service_error,service_probe=service_probe,
                disk_pressure=disk,protected_controls_changed=disk.get('protected_controls_changed',0),
                skipped=1,reason='GUI, worker, service and owned-volume disk-full trials recorded. Physical sleep/resume is not inferred from VM pause/resume.')
            return m,session.healthy()
        manifest=prepare(context,context['group']);entries=json.loads(manifest.read_text())['files']
        target=next((e for e in entries if e['path']==case.parameters['sample']+'.bin'),None)
        if target is None:raise ValueError('Approved specimen could not be imported')
        if not session.healthy():raise RuntimeError('Telemetry lost before specimen staging')
        source=manifest.parent/target['path'];staged=watch/'subject.exe'
        if hashlib.sha256(source.read_bytes()).hexdigest()!=target['sha256']:raise ValueError('Specimen identity changed')
        shutil.copyfile(source,staged)
        time.sleep(5)
        if not staged.exists():
            m.update(staging_removed=True,protection_verified=False,reason='Staging removed; attribution requires response receipt')
            return m,False
        from sentinelav.lab.runtime_job import run_job,AUTHORIZATION
        def runtime_health():
            """Poll the engine for new events and report whether telemetry and protection are still
            healthy.
            """
            nonlocal cursor,epoch,product_gap
            batch=request(data,'poll',cursor=cursor,epoch=epoch);cursor=batch['cursor'];epoch=batch['epoch']
            events.extend(batch.get('events',[]));product_gap=product_gap or batch.get('gap',False) or bool(batch.get('dropped'))
            if len(events)>2000:product_gap=True;del events[:-2000]
            return session.healthy() and batch.get('state')=='Active' and not product_gap
        result=run_job(dict(schema=1,authorization=AUTHORIZATION,sample=str(staged),sha256=target['sha256'],seconds=case.seconds,process_limit=32),
            _guest_check=lambda:guard(context),_health_check=runtime_health)
        m=session.snapshot();m.update(runtime=result,protection_verified=False,
            reason='Observed runtime without independent expected-harm manifest; no prevention success inferred',
            privilege=ps('[Security.Principal.WindowsIdentity]::GetCurrent().Name'),active_auto_response=False,
            monitor_events=events[-64:],product_event_gap=product_gap,background_signature_policy=policy)
        return m,False
    finally:
        if session:
            if 'm' not in locals():(root/'telemetry-failure.json').write_text(json.dumps(redact(session.snapshot(16))))
            session.close()
            if 'm' in locals():m.update(session.snapshot())
        if writer:writer.close()
        try:request(data,'shutdown')
        except Exception:pass
        try:process.wait(10)
        except subprocess.TimeoutExpired:process.kill();process.wait()

"""Allowlisted harmless lab profiles. No sample ingestion or arbitrary execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import uuid
from sentinelav.monitoring.behavior import BehaviorEngine,create_canary
from sentinelav.detection.engine import Scanner

PROFILES={
    'signature':('Demo signature','Scan an ordinary text marker using the actual detection engine.'),
    'benign':('Benign documents','Scan generated normal text files and check for unwanted detections.'),
    'behavior':('Canary and file burst','Edit generated canary/text files; feed explicitly synthetic file events to the scorer.'),
    'network':('Network indicator rules','Evaluate synthetic connection records; no network connections are made.'),
}


def capabilities():
    result=dict(platform=os.name,hyperv_tools=False,vm_service='Unknown',vm_configured=False,
                mode='Local safe simulations',network_policy='No connections made by simulation profiles')
    if os.name!='nt':
        result['note']='Windows VM backend requires Windows. Harmless rule simulations remain available.'
        return result
    script=("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            "$vm=Get-Service vmms -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{hyperv_tools=[bool](Get-Command Get-VM -ErrorAction SilentlyContinue);"
            "vm_service=if($vm){[string]$vm.Status}else{'Not detected or inaccessible'}} | ConvertTo-Json -Compress")
    try:
        output=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
                              capture_output=True,encoding='utf-8-sig',errors='replace',timeout=10,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        if output.returncode:
            raise RuntimeError(output.stderr.strip()[:500] or 'System check failed')
        if len(output.stdout)>4096:
            raise ValueError('System-check response exceeded its limit')
        values=json.loads(output.stdout)
        result['hyperv_tools']=bool(values['hyperv_tools'])
        result['vm_service']=str(values['vm_service'])[:80]
        result['note']='No VM is configured or isolation verified. Feature availability is not proof of containment.'
    except Exception as error:
        result['note']='VM readiness could not be verified: '+str(error)
    return result


class SimulationRunner:
    def __init__(self,root,workspace,emit=lambda _:None,stop=None):
        self.root,self.workspace=Path(root),Path(workspace).absolute()
        self.emit,self.stop=emit,stop or threading.Event()

    def check(self):
        if self.stop.is_set():
            raise InterruptedError('Simulation cancelled')
        if time.monotonic()-self.started>15:
            raise TimeoutError('Simulation exceeded its 15-second limit')

    def activity(self,kind,details,**extra):
        self.check()
        event=dict(time=time.strftime('%H:%M:%S'),kind=kind,details=details,simulation=True,**extra)
        self.events.append(event)
        self.emit(event)

    def run(self,profiles):
        # Validate the complete request before creating or changing anything.
        if not profiles or len(profiles)>len(PROFILES) or len(set(profiles))!=len(profiles) or any(p not in PROFILES for p in profiles):
            raise ValueError('Choose distinct allowlisted simulation profiles')
        for part in [self.workspace,*self.workspace.parents]:
            if part.is_symlink() or part.is_junction():
                raise ValueError('Lab workspace cannot contain linked path components')
        self.workspace.mkdir(parents=True,exist_ok=True)
        self.events=[]
        self.started=time.monotonic()
        run=dict(id=uuid.uuid4().hex,date=time.strftime('%Y-%m-%d %H:%M:%S'),mode='local_safe_simulation',
                 isolated=False,guest_executed=False,profiles=list(profiles),results=[],events=self.events,
                 status='Running',workspace_reset=False)
        try:
            with tempfile.TemporaryDirectory(prefix='run-',dir=self.workspace) as temp:
                folder=Path(temp).resolve()
                if not folder.is_relative_to(self.workspace.resolve()):
                    raise ValueError('Temporary run escaped the lab workspace')
                self.activity('Preparing','Created fresh, app-owned harmless fixtures. This is not a VM.')
                for profile in profiles:
                    self.check()
                    area=folder/profile
                    area.mkdir()
                    self.activity('Running',PROFILES[profile][0])
                    result=self.profile(profile,area)
                    run['results'].append(dict(profile=profile,**result))
                    self.activity('Check finished',result['summary'],profile=profile,passed=result['passed'])
                run['status']='Checks passed' if all(r['passed'] for r in run['results']) else 'Review required'
        except InterruptedError:
            run['status']='Cancelled'
        except Exception as error:
            run['status']='Failed'
            run['error']=str(error)
        finally:
            run['elapsed']=round(time.monotonic()-self.started,3)
            # Only the run-specific TemporaryDirectory is disposed, never user paths.
            run['workspace_reset']=not any(self.workspace.glob('run-*')) if 'folder' not in locals() else not folder.exists()
        return run

    def profile(self,profile,folder):
        if profile in ('signature','benign'):
            count=1 if profile=='signature' else 20
            for index in range(count):
                self.check()
                (folder/f'fixture-{index}.txt').write_text('SENTINELAV_DEMO_THREAT_7C23A' if profile=='signature' else f'Ordinary demonstration document {index}.')
            cancelled=lambda:self.stop.is_set() or time.monotonic()-self.started>15
            scan=Scanner(self.root/'signatures.json',self.root/'rules',max_mb=1).scan([folder],cancelled,lambda *a:None)
            self.check()
            expected=1 if profile=='signature' else 0
            passed=scan['scanned']==count and len(scan['detections'])==expected and not scan['errors']
            return dict(passed=passed,summary=f"{scan['scanned']} generated files scanned; {len(scan['detections'])} detections (expected {expected}).",
                        evidence=scan,telemetry='Actual scan of generated fixtures')
        evidence=[]
        def record(event):
            evidence.append(event)
            self.activity(event['kind'],event['details'],telemetry='Synthetic rule input')
        if profile=='behavior':
            canary=create_canary(folder)
            engine=BehaviorEngine(record,canaries=[canary])
            engine.check_canaries([folder],[])
            Path(canary['path']).write_text('Harmless canary edit in a generated fixture.')
            engine.check_canaries([folder],[])
            for index in range(30):
                self.check()
                path=folder/f'ordinary-{index}.txt'
                path.write_text('Harmless simulation text; no encryption.')
                engine.file_event('modified',path,[folder],[])
            passed=any(e['level']=='Warning' for e in evidence) and any(e['level']=='Alert' and e.get('score')==100 for e in evidence)
            return dict(passed=passed,summary='Canary warning and combined-risk alert observed.' if passed else 'Expected rule outcome was not observed.',evidence=evidence,telemetry='Actual harmless file edits; synthetic file events')
        engine=BehaviorEngine(record,networks=['192.0.2.10/32'])
        info=dict(pid=4242,create_time=1,name='synthetic-demo.exe',exe='C:/Temp/synthetic-demo.exe',cmdline=[])
        engine.process(info)
        connection=SimpleNamespace(pid=4242,status='ESTABLISHED',raddr=SimpleNamespace(ip='192.0.2.10',port=443))
        engine.network([connection],{4242:info})
        passed=any(e['level']=='Alert' and e.get('score')==95 for e in evidence)
        return dict(passed=passed,summary='Synthetic process/network indicators produced the expected score.' if passed else 'Expected network rule outcome was not observed.',evidence=evidence,telemetry='Synthetic metadata only; no process launched or connection made')

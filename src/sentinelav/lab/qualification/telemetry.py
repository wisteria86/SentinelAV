# Purpose: Independent guest observers. No event absence is a benign verdict.
# Works with: monitoring.kernel_telemetry, monitoring.sequences
# Used by: lab.qualification.guest_lifecycle, lab.qualification.guest_telemetry

"""Independent guest observers. No event absence is a benign verdict."""
from collections import Counter,deque
from dataclasses import dataclass,asdict
from pathlib import Path
import os
import subprocess
import threading
import time
import uuid
from datetime import datetime,timezone
from sentinelav.monitoring.sequences import parse_event


@dataclass
class TelemetryEventV1:
    source: str
    event_type: str
    timestamp: float
    process: dict
    resource: str
    attribution: str
    fields: dict
    record_id: int | None = None
    collected: float = 0
    schema: int = 1


@dataclass
class TelemetryHealthV1:
    source: str
    ready: bool = False
    last_observation: float = 0
    lost: int = 0
    error: str = ''
    schema: int = 1


class SysmonObserver:
    def __init__(self):
        import win32evtlog
        self.api=win32evtlog;self.cursor=0;self.health=TelemetryHealthV1('Sysmon')
        self.channel='Microsoft-Windows-Sysmon/Operational'
        self.cursor=self.latest();self.health.ready=True

    def latest(self):
        a=self.api;handle=a.EvtQuery(self.channel,a.EvtQueryReverseDirection,'*')
        try:
            try:events=a.EvtNext(handle,1)
            except Exception as e:
                if getattr(e,'winerror',None)==259:return 0
                raise
            try:return parse_event(a.EvtRender(events[0],a.EvtRenderEventXml))['record'] if events else 0
            finally:
                for event in events:event.Close()
        finally:handle.Close()

    def poll(self):
        a=self.api
        if self.latest()<self.cursor:
            self.health.lost+=1;self.health.ready=False;raise RuntimeError('Sysmon log reset')
        handle=a.EvtQuery(self.channel,a.EvtQueryForwardDirection,f'*[System[EventRecordID > {self.cursor}]]')
        result=[]
        try:
            while len(result)<2048:
                try:events=a.EvtNext(handle,min(128,2048-len(result)))
                except Exception as e:
                    if getattr(e,'winerror',None)==259:break
                    raise
                if not events:break
                try:
                    for event in events:
                        row=parse_event(a.EvtRender(event,a.EvtRenderEventXml))
                        if row['record']<=self.cursor:continue
                        if row['record']!=self.cursor+1 and self.cursor:self.health.lost+=row['record']-self.cursor-1
                        self.cursor=row['record'];fields=row['fields']
                        observed=datetime.fromisoformat(fields['UtcTime']).replace(tzinfo=timezone.utc).timestamp() if fields.get('UtcTime') else time.time()
                        result.append(asdict(TelemetryEventV1('Sysmon',str(row['id']),observed,
                            dict(guid=fields.get('ProcessGuid'),pid=fields.get('ProcessId'),parent_guid=fields.get('ParentProcessGuid')),
                            fields.get('TargetFilename',fields.get('TargetObject',fields.get('Image',''))),
                            'verified' if fields.get('ProcessGuid') else 'unattributed',fields,row['record'],time.time())))
                finally:
                    for event in events:event.Close()
            if result:self.health.last_observation=time.time()
            return result
        finally:handle.Close()


class TelemetrySession:
    def __init__(self,collector,root,max_events=20000,rolling_summary=False,probe_pid=None):
        self.root=Path(root);self.events=deque(maxlen=max_events);self.counts=Counter();self.probes={};self.probe_evidence=[]
        self.stop=threading.Event();self.error='';self.truncated=False;self.lock=threading.Lock()
        self.rolling_summary=rolling_summary;self.retention_evicted=0
        self.owned_guids=set();self.owned_pids=set();self.started=time.time()
        self.registry_probe=None
        self.sysmon=SysmonObserver()
        from sentinelav.monitoring.kernel_telemetry import KernelFileEvents
        self.etw=KernelFileEvents(collector,probe_pid=probe_pid)
        self.thread=threading.Thread(target=self.collect,daemon=True);self.thread.start()

    def collect(self):
        while not self.stop.wait(.2):
            try:
                events=self.sysmon.poll()
                for e in self.etw.poll():
                    events.append(asdict(TelemetryEventV1('ETW','file_write',e.get('timestamp',time.time()),
                        e.get('identity',{}),e.get('path',''),'verified' if e.get('identity') else 'unattributed',e,collected=time.time())))
                with self.lock:
                    for e in events:
                        self.counts[(e['source'],e['event_type'])]+=1
                        f=e['fields'];p=e['process']
                        related=e['resource'].casefold().startswith('c:\\sentinelav-test\\') or e['resource'].casefold().startswith('c:/sentinelav-test/')
                        if e['source']=='Sysmon':
                            related=related or p.get('guid') in self.owned_guids or p.get('parent_guid') in self.owned_guids or str(p.get('pid')) in self.owned_pids
                            probe=self.registry_probe
                            if probe and e['event_type'] in ('12','13'):
                                suffix,writer,started=probe
                                related=related or (e['resource'].casefold().endswith(suffix)
                                    and str(p.get('pid'))==writer and e['timestamp']>=started)
                            if related and e['event_type']=='1':
                                if p.get('guid'):self.owned_guids.add(p['guid'])
                                if p.get('pid'):self.owned_pids.add(str(p['pid']))
                            if e['event_type']=='5':self.owned_pids.discard(str(p.get('pid')))
                        else:
                            related=related or str(p.get('pid')) in self.owned_pids or str(f.get('process',{}).get('exe','')).casefold().startswith('c:\\sentinelav-test\\')
                        if not related:continue
                        if len(self.events)==self.events.maxlen:
                            self.retention_evicted+=1
                            if not self.rolling_summary:self.truncated=True
                        self.events.append(e)
                if self.etw.error:raise RuntimeError('ETW observer: '+self.etw.error)
            except Exception as e:
                self.error=type(e).__name__+': '+str(e)[:300];self.sysmon.health.ready=False;return

    def etw_loss_counts(self):
        return dict(reader_drops=self.etw.dropped,native_queue_drops=self.etw.native_dropped,
            provider_losses=self.etw.etw_lost,unresolved_paths=self.etw.unresolved_paths,
            unresolved_identities=self.etw.unresolved_identities)

    def healthy(self):
        return not self.error and self.thread.is_alive() and self.sysmon.health.ready and self.etw.ready and self.etw.last_heartbeat>0 and time.time()-self.etw.last_heartbeat<6 and not any(self.etw_loss_counts().values()) and not self.sysmon.health.lost and not self.truncated

    def probe(self,timeout=20,writer=None):
        import winreg
        start=time.monotonic()
        path=writer.path if writer else self.root/('SentinelAVLabProbe-'+uuid.uuid4().hex+'.txt')
        name=path.stem;keypath=r'Software\Microsoft\Windows\CurrentVersion\Run'
        while not self.etw.ready and not self.error and time.monotonic()-start<5:time.sleep(.1)
        if not self.etw.ready:raise RuntimeError('ETW did not become ready')
        command=[str(Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'),'-NoProfile','-NonInteractive','-Command','& "$env:WINDIR/System32/whoami.exe" | Out-Null']
        observed_after=time.time()-.001
        process=subprocess.Popen(command,creationflags=subprocess.CREATE_NO_WINDOW)
        self.owned_pids.add(str(process.pid))
        self.registry_probe=('\\'+keypath.casefold()+'\\'+name.casefold(),str(os.getpid()),observed_after)
        try:
            if writer:writer.write()
            else:
                with path.open('xb') as f:f.write(b'harmless collector probe');f.flush();os.fsync(f.fileno())
                with path.open('ab') as f:f.write(b' modified');f.flush();os.fsync(f.fileno())
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,keypath) as key:
                winreg.SetValueEx(key,name,0,winreg.REG_SZ,'harmless-probe-one')
                winreg.SetValueEx(key,name,0,winreg.REG_SZ,'harmless-probe-two')
                winreg.DeleteValue(key,name)
            process.wait(timeout=10)
            while time.monotonic()-start<timeout:
                with self.lock:events=[e for e in self.events if observed_after<=e['timestamp']<=time.time()]
                roots={e['process'].get('guid') for e in events if e['source']=='Sysmon' and e['event_type']=='1' and str(e['process'].get('pid'))==str(process.pid)}
                checks=dict(process=bool(roots),child=any(e['source']=='Sysmon' and e['event_type']=='1' and e['process'].get('parent_guid') in roots for e in events),
                    termination=any(e['source']=='Sysmon' and e['event_type']=='5' and e['process'].get('guid') in roots for e in events),
                    file_create=any(e['source']=='Sysmon' and e['event_type']=='11' and name in e['resource'] for e in events),
                    file_write=any(e['source']=='ETW' and name in e['resource'] for e in events),
                    registry_change=any(e['source']=='Sysmon' and e['event_type']=='13' and name in e['resource'] for e in events),
                    registry_remove=any(e['source']=='Sysmon' and e['event_type']=='12' and name in e['resource'] for e in events))
                self.probes=checks
                if all(checks.values()) and self.healthy():
                    selected=[e for e in events if name in e['resource'] or e['process'].get('guid') in roots or e['process'].get('parent_guid') in roots]
                    self.probe_evidence=[{k:e.get(k) for k in ('source','event_type','timestamp','record_id','process','resource','attribution')} for e in selected[-32:]]
                    return checks
                if self.error:break
                time.sleep(.2)
            raise RuntimeError('Telemetry probe incomplete: '+str(checks))
        finally:
            self.registry_probe=None
            if process.poll() is None:process.kill();process.wait()
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,keypath,0,winreg.KEY_SET_VALUE) as k:winreg.DeleteValue(k,name)
            except FileNotFoundError:pass
            if not writer:path.unlink(missing_ok=True)

    def snapshot(self,limit=32):
        with self.lock:events=list(self.events)
        losses=self.etw_loss_counts()
        etw_lost=sum(losses.values())
        return dict(telemetry=events[-limit:] if limit else [],telemetry_export_truncated=len(events)>limit,
            unfiltered_counts={s+':'+t:n for (s,t),n in self.counts.items()},
            telemetry_health=[asdict(self.sysmon.health),dict(schema=1,source='ETW',ready=self.etw.ready,last_observation=self.etw.last_heartbeat,lost=etw_lost,loss_counts=losses,error=self.etw.error,collection_closed=self.stop.is_set())],
            etw_scope=dict(probe_pid=self.etw.probe_pid,outside_scope_events=self.etw.outside_probe_scope),
            probes=self.probes,probe_evidence=self.probe_evidence,losses=etw_lost+self.sysmon.health.lost,truncated=self.truncated,
            retention_policy='rolling-summary' if self.rolling_summary else 'complete-case',retention_evicted=self.retention_evicted)

    def close(self):
        self.stop.set();self.thread.join(10);self.etw.close()

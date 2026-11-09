# Purpose: Bounded, read-only monitoring. No files are removed and no processes are stopped.
# Works with: detection.inspection, monitoring.behavior, monitoring.event_sources, monitoring.monitor_loop,
#   monitoring.process_telemetry
# Used by: lab.runtime_job, monitoring.background, platform.windows_service, ui.protection

"""Bounded, read-only monitoring. No files are removed and no processes are stopped."""
import json
import os
import subprocess
import threading
import time
import queue
from collections import OrderedDict
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import psutil
from sentinelav.detection.inspection import IsolatedScanner as Scanner
from sentinelav.monitoring.behavior import BehaviorEngine
from sentinelav.monitoring.process_telemetry import ProcessEvents,ProcessGraph


from .monitor_loop import MonitorLoopMixin

from .event_sources import PendingFiles,Changes,SysmonReader

class Monitor(MonitorLoopMixin):
    def __init__(self, config, emit, status):
        self.config, self.emit, self.status = config, emit, status
        self.stop = threading.Event()
        self.pending = PendingFiles()
        self.seen_processes = None
        self.alerted = OrderedDict()
        self.checked = 0
        self.process_count = 0
        self.process_infos = {}
        self.behavior = None
        self.activity = queue.Queue(maxsize=2048)
        self.network_count = 0
        self.process_graph=ProcessGraph()
        self.event_identities=OrderedDict()
        self.uninspected_process_events=0
        self.process_event_drops=0
        self.reported_process_event_drops=0
        self.responder=None
        self.inspection_error=''
        from sentinelav.monitoring.sequences import BehaviorCorrelator
        self.sequences=BehaviorCorrelator(self.emit)
        self.kernel_reader=None
        self.network_reputation=None
        self.artifact_updater=None
        self.change_monitor=None
        from .health import MonitoringHealth
        self.health=MonitoringHealth()

    def file_activity(self,kind,path):
        try:
            self.activity.put_nowait((kind,path))
        except queue.Full:
            with self.pending.lock:
                self.pending.dropped += 1

    def event(self, kind, details, source, level='Info', **extra):
        self.emit(dict(time=time.strftime('%Y-%m-%d %H:%M:%S'), kind=kind,
                       details=details, source=source, level=level, **extra))

    def processes(self):
        current = set()
        new = []
        denied = 0
        infos = {}
        for process in psutil.process_iter(['pid','ppid','name','exe','create_time','cmdline']):
            if self.stop.is_set():
                return
            try:
                info = process.info
                key = (info['pid'], info['create_time'])
                current.add(key)
                infos[info['pid']] = info
                if self.seen_processes is not None and key not in self.seen_processes:
                    new.append(info)
                if not info['exe']:
                    denied += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                denied += 1
        self.process_count = len(current)
        self.seen_processes = current
        self.process_infos = infos
        for info in infos.values(): self.process_graph.observe(info)
        visible={(value['pid'],value['create_time']) for value in infos.values()}
        if self.behavior:
            for info in infos.values():
                if info.get('exe') and not self.behavior.excluded(info['exe'],self.exclusions):
                    ancestors=self.process_graph.ancestors(info)
                    verified=[]
                    for ancestor in ancestors:
                        if (ancestor['pid'],ancestor['create_time']) not in visible: break
                        verified.append(ancestor)
                    self.behavior.process(info,(verified[0].get('name') or '') if verified else '',context_only=not self.config.get('behavior'),ancestors=verified)
        for info in new:
            if not self.config['processes']:
                continue
            self.event('Process started', f"{info['name']} · PID {info['pid']} · parent {info['ppid']}",
                       'Processes', pid=info['pid'], parent=info['ppid'], path=info['exe'])
            if info['exe']:
                self.pending.add(info['exe'], 'Process executable')
        return denied

    def process_event(self,event):
        try:
            process=psutil.Process(event['pid'])
            info=process.as_dict(attrs=['pid','ppid','name','exe','create_time','cmdline'])
            if not isinstance(info.get('create_time'),(int,float)): raise ValueError('Process creation time is unavailable')
            observed=int(event['timestamp'])/10_000_000-11644473600
            if abs(info['create_time']-observed)>2: raise ValueError('PID identity no longer matches process-start event')
            key=(info['pid'],info['create_time'])
            if key in self.event_identities: return
            self.event_identities[key]=True
            while len(self.event_identities)>4096: self.event_identities.popitem(last=False)
            self.process_graph.observe(info)
            ancestors=[]
            parent=info.get('ppid'); child_time=info['create_time']; visited={info['pid']}
            for _ in range(8):
                if not parent or parent in visited: break
                try: ancestor=psutil.Process(parent).as_dict(attrs=['pid','ppid','name','exe','create_time'])
                except psutil.Error: break
                if not isinstance(ancestor.get('create_time'),(int,float)) or ancestor['create_time']>child_time: break
                self.process_graph.observe(ancestor); ancestors.append(ancestor); visited.add(parent)
                parent,child_time=ancestor.get('ppid'),ancestor['create_time']
            if self.behavior: self.behavior.process(info,ancestors[0]['name'] if ancestors else '',ancestors=ancestors)
            self.event('Process start event',f"{info['name']} · PID {info['pid']}",'WMI process events',pid=info['pid'],parent=info['ppid'],path=info.get('exe') or '',ancestry=ancestors)
            if info.get('exe'): self.pending.add(info['exe'],'Process event executable')
        except (psutil.Error,OSError,ValueError):
            self.uninspected_process_events+=1
            self.event('Short-lived/unavailable process observed',f"{event['name']} · PID {event['pid']}; executable could not be verified",'WMI process events','Warning',pid=event['pid'])

    def sysmon_event(self,row):
        if self.change_monitor:self.change_monitor.observe_sysmon(row)
        self.event(f'Sysmon event {row["Id"]}',(row.get('Message') or '')[:4000],
                   'Sysmon',record_id=row['RecordId'])
        if not self.config.get('behavior'): return
        from sentinelav.monitoring.sequences import parse_event
        try:
            event=parse_event(row.get('Xml'))
            if event['record']!=int(row['RecordId']) or event['id']!=int(row['Id']):
                raise ValueError('Event identity mismatch')
            image=event['fields'].get('Image')
            if image and self.behavior and self.behavior.excluded(image,self.exclusions): return
            target=event['fields'].get('TargetFilename')
            if target and self.behavior and self.behavior.excluded(target,self.exclusions): return
            self.sequences.consume(event)
            if event['id']==22 and self.network_reputation:
                match=self.network_reputation.lookup_domain(event['fields'].get('QueryName',''))
                if match and match['verdict'] in ('malicious','suspicious'):
                    self.event('DNS reputation review','Signed reputation entry for '+match['value'],
                        'Sysmon DNS','Warning',process_guid=event['fields'].get('ProcessGuid'),
                        path=event['fields'].get('Image',''),reputation=match,automatic_response_eligible=False)
        except (ValueError,TypeError,KeyError) as error:
            self.event('Sysmon correlation omitted',str(error),'Sysmon','Warning')

    def inspect(self, scanner, path, source):
        if source == 'Filesystem' and not any(Path(path).resolve().is_relative_to(r) for r in self.allowed_roots):
            return
        if not Path(path).is_file() or scanner.excluded(Path(path)):
            return
        result = scanner.scan([path], self.stop.is_set, lambda *args: None)
        if self.config.get('evaluation_attestation'):
            self.event('Inspection policy attestation','Evaluation-only scanner mode evidence',source,
                       path=str(path),signature_policy=result.get('signature_policy',{}),scanned=result.get('scanned',0),status=result.get('status'))
        self.inspection_error=('Latest file inspection incomplete; review warnings and rescan omitted files'
                               if result['status'] not in ('Complete','Cancelled') else '')
        if result.get('worker_restarted'):
            self.event('Inspection worker restarted',
                       'Worker recovered. Earlier incomplete inspections still require a rescan.',source,'Warning')
        self.checked += result['scanned']
        for detection in result['detections']:
            key = (detection['path'], detection['sha256'])
            now = time.monotonic()
            if now - self.alerted.get(key, -1000) < 60:
                continue
            self.alerted[key] = now
            if len(self.alerted) > 2048:
                self.alerted.popitem(last=False)
            self.event('Threat detected', '; '.join(detection['reasons']), source, 'Alert', **detection)
            if self.responder: self.responder.submit(detection)
        for error in result['errors']:
            self.event('Inspection failed', error, source, 'Warning')
        for item in result.get('advanced_reviews',[]):
            self.event('Experimental analysis review','; '.join(item['reasons']),source,'Warning',
                       path=item['path'],sha256=item['sha256'],automatic_response_eligible=False)
        if result['skipped']:
            self.event('File skipped', f'Size limit exceeded: {path}', source, 'Warning')

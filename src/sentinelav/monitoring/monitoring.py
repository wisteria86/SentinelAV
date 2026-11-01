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


class PendingFiles:
    def __init__(self, capacity=1024, delay=.7):
        self.capacity, self.delay = capacity, delay
        self.items = OrderedDict()
        self.lock = threading.Lock()
        self.dropped = 0

    def add(self, path, source='Filesystem'):
        with self.lock:
            key = os.path.normcase(os.path.abspath(path))
            if key not in self.items and len(self.items) >= self.capacity:
                self.dropped += 1
                return
            self.items[key] = (time.monotonic(), source)

    def pop(self):
        with self.lock:
            for path, (stamp, source) in self.items.items():
                if time.monotonic() - stamp >= self.delay:
                    del self.items[path]
                    return path, source
        return None


class Changes(FileSystemEventHandler):
    def __init__(self, queue, activity=None):
        self.queue = queue
        self.activity = activity or (lambda *args:None)

    def on_created(self, event):
        if not event.is_directory:
            self.queue.add(event.src_path)
            self.activity('modified',event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.queue.add(event.src_path)
            self.activity('modified',event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.queue.add(event.dest_path)
            self.activity('moved',event.dest_path)

    def on_deleted(self,event):
        if not event.is_directory:
            self.activity('deleted',event.src_path)


class SysmonReader:
    """Read an existing Sysmon channel; never install or change Windows logging."""
    def __init__(self):
        self.cursor = None

    def poll(self):
        if os.name != 'nt':
            raise RuntimeError('Sysmon requires Windows')
        if self.cursor is None:
            query = "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop"
        else:
            query = ("Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                     f"-FilterXPath '*[System[EventRecordID > {int(self.cursor)}]]' "
                     '-Oldest -MaxEvents 100 -ErrorAction Stop')
        script = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; try { @(" + query +
                  " | Select-Object RecordId,Id,@{N='Message';E={$_.Message}}) | ConvertTo-Json -Compress "
                  "} catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { '[]' } "
                  "else { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } }")
        completed = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
                                   capture_output=True, encoding='utf-8-sig', errors='replace',
                                   timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip() or 'Sysmon channel is unavailable')
        rows = json.loads(completed.stdout.strip() or '[]')
        if isinstance(rows, dict):
            rows = [rows]
        baseline = self.cursor is None
        if rows:
            self.cursor = max(int(r['RecordId']) for r in rows)
        elif baseline:
            self.cursor = 0
        return [] if baseline else rows


class Monitor:
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
                    self.behavior.process(info,(infos.get(info['ppid']) or {}).get('name') or '',context_only=not self.config.get('behavior'),ancestors=verified)
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

    def inspect(self, scanner, path, source):
        if source == 'Filesystem' and not any(Path(path).resolve().is_relative_to(r) for r in self.allowed_roots):
            return
        if not Path(path).is_file() or scanner.excluded(Path(path)):
            return
        result = scanner.scan([path], self.stop.is_set, lambda *args: None)
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
        if result['skipped']:
            self.event('File skipped', f'Size limit exceeded: {path}', source, 'Warning')

    def run(self):
        observer = Observer()
        try:
            scanner = Scanner(self.config['signatures'], self.config['rules'],
                              self.config['max_mb'], self.config['exclusions'],self.config.get('trusted_hashes',[]),
                              options=self.config.get('inspection_options'),persistent=True)
            for warning in scanner.warnings:
                self.event('Engine warning', warning, 'Engine', 'Warning')
            roots = []
            for item in self.config['folders']:
                original = Path(item)
                root = original.resolve()
                if not root.is_dir() or original.is_symlink() or original.is_junction():
                    raise ValueError(f'Monitor folder is unavailable or a link: {root}')
                if scanner.excluded(root):
                    raise ValueError(f'Monitor folder is excluded: {root}')
                # Collapse nested roots so watchdog cannot schedule duplicate trees.
                if not any(root == r or r in root.parents for r in roots):
                    roots = [r for r in roots if root not in r.parents]
                    roots.append(root)
            self.allowed_roots = roots
            self.exclusions = scanner.exclusions
            policy=self.config.get('auto_response',{})
            if policy.get('enabled') and self.config.get('data_dir'):
                from sentinelav.response.auto_response import AutoResponder
                self.responder=AutoResponder(self.config['data_dir'],Path(self.config['signatures']).parent,policy,self.emit)
            if self.config.get('behavior') or self.config.get('network'):
                self.behavior = BehaviorEngine(self.emit,self.config.get('canaries',[]),self.config.get('network_indicators',[]))
            if not roots and not self.config['processes'] and not self.config['sysmon'] and not self.config.get('network'):
                raise ValueError('Choose at least one monitoring source')
            for root in roots:
                observer.schedule(Changes(self.pending,self.file_activity if self.behavior else None), str(root), recursive=True)
            if roots:
                observer.start()
            self.event('Monitoring started', f'{len(roots)} folder(s); process tracking: {self.config["processes"]}', 'Protection')
            reader = SysmonReader() if self.config['sysmon'] else None
            process_reader=None
            if self.config['processes'] and self.config.get('event_processes',False):
                try:
                    process_reader=ProcessEvents(); process_reader.start()
                except Exception as error:
                    self.event('Process event source unavailable',str(error),'WMI process events','Warning')
                    if process_reader: process_reader.close()
                    process_reader=None
            next_process = next_sysmon = next_status = next_network = next_canary = 0
            network_available = self.config.get('network',False)
            denied = 0
            while not self.stop.is_set():
                now = time.monotonic()
                if process_reader:
                    try:
                        for event in process_reader.poll(): self.process_event(event)
                        self.process_event_drops=process_reader.dropped
                    except Exception as error:
                        self.event('Process event source unavailable',str(error)+'; snapshot polling remains active','WMI process events','Warning')
                        process_reader.close(); process_reader=None
                if (self.config['processes'] or network_available) and now >= next_process:
                    denied = self.processes() or 0
                    next_process = now + 3
                if reader and now >= next_sysmon:
                    try:
                        for row in reader.poll():
                            self.event(f'Sysmon event {row["Id"]}', (row.get('Message') or '')[:4000], 'Sysmon', record_id=row['RecordId'])
                    except Exception as error:
                        self.event('Sysmon unavailable', str(error), 'Sysmon', 'Warning')
                        reader = None
                        if not roots and not self.config['processes'] and not network_available:
                            raise RuntimeError('No monitoring sources remain available. Add a watched folder or enable process tracking.')
                    next_sysmon = now + 15
                if self.behavior:
                    for _ in range(100):
                        try:
                            kind,path = self.activity.get_nowait()
                        except queue.Empty:
                            break
                        if self.config.get('behavior'):
                            self.behavior.file_event(kind,path,roots,self.exclusions)
                    if self.config.get('behavior') and now >= next_canary:
                        self.behavior.check_canaries(roots,self.exclusions)
                        next_canary = now + 2
                    if network_available and now >= next_network:
                        try:
                            connections = psutil.net_connections(kind='inet')
                            self.network_count = sum(c.status=='ESTABLISHED' for c in connections)
                            visible = {pid:info for pid,info in self.process_infos.items() if not info.get('exe') or not self.behavior.excluded(info['exe'],self.exclusions)}
                            self.behavior.network(connections,visible)
                        except (psutil.Error, OSError, RuntimeError) as error:
                            self.event('Network telemetry unavailable',str(error),'Network','Warning')
                            network_available = False
                            if not roots and not self.config['processes'] and not reader:
                                raise RuntimeError('No monitoring sources remain available')
                        next_network = now + 5
                item = self.pending.pop()
                if item:
                    self.inspect(scanner, *item)
                if now >= next_status:
                    self.status(dict(checked=self.checked, processes=self.process_count,
                                     denied=denied, queued=len(self.pending.items), folders=len(roots),
                                     dropped=self.pending.dropped, sysmon=reader is not None,
                                     network=network_available,connections=self.network_count,
                                     behavior=self.config.get('behavior',False),
                                     signature_count=len(scanner.signatures),
                                     yara_research_rules=scanner.rule_summary['research_rules'],
                                     yara_public_rules=scanner.rule_summary['public_rules'],
                                     process_event_source='WMI subscribed' if process_reader and process_reader.ready else 'Polling only',
                                     process_event_drops=self.process_event_drops,
                                     uninspected_process_events=self.uninspected_process_events,
                                     inspection_isolation='Separate process with Windows job limits',
                                     automatic_response=bool(self.responder and self.responder.ready and self.responder.enabled),
                                     signature_database=scanner.signatures.metadata.get('database') if scanner.signatures.metadata else 'Local JSON'))
                    if self.pending.dropped:
                        self.event('Monitoring backlog', f'{self.pending.dropped} file events dropped; run an on-demand scan to cover omissions.', 'Filesystem', 'Warning')
                        self.pending.dropped = 0
                    next_status = now + 2
                if not item:
                    self.stop.wait(.1)
        finally:
            if self.responder: self.responder.close(); self.responder=None
            if 'process_reader' in locals() and process_reader: process_reader.close()
            if 'scanner' in locals(): scanner.close()
            if observer.is_alive():
                observer.stop()
                observer.join(timeout=5)
            self.event('Monitoring stopped', 'This monitoring session has stopped.', 'Protection')

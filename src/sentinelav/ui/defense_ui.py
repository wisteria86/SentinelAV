"""Honest layer status, bounded manual inspection, and opt-in response policy."""
import json
import os
from pathlib import Path
import re
import psutil
from PySide6.QtCore import QThread,Signal,QTimer
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QTabWidget,QCheckBox,QPlainTextEdit,QFileDialog,QInputDialog,QMessageBox,QHeaderView
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.detection.preexecution import verdict
from sentinelav.platform.windows_service import read_health


class InspectionWorker(QThread):
    completed=Signal(dict)
    failed=Signal(str)
    def __init__(self,root,kind,target,options):
        super().__init__()
        self.root,self.kind,self.target,self.options=root,kind,target,options
    def run(self):
        scanner=None
        try:
            scanner=IsolatedScanner(self.root/'signatures.json',self.root/'rules',options=self.options)
            if self.kind=='memory':
                pid,creation=self.target
                result=scanner.scan_memory(pid,creation,self.isInterruptionRequested)
            else:
                report=scanner.scan([self.target],self.isInterruptionRequested,lambda *a:None)
                result=dict(scope='Manual pre-execution inspection; no file was launched',verdict=verdict(self.target,report),scan=report)
            self.completed.emit(result)
        except Exception as error: self.failed.emit(str(error))
        finally:
            if scanner: scanner.close()


class DefenseMixin:
    def settings_page(self):
        super().settings_page()
        outer_tabs=self.stack.widget(5).findChild(QTabWidget)
        wrapper=QWidget(); wrapper_layout=QVBoxLayout(wrapper); wrapper_layout.setContentsMargins(0,0,0,0)
        self.defense_tabs=QTabWidget(); wrapper_layout.addWidget(self.defense_tabs)
        outer_tabs.addTab(wrapper,'Defense')
        tabs=self.defense_tabs
        page=QWidget(); layout=QVBoxLayout(page); layout.setContentsMargins(14,10,14,10)
        self.layer_table=self.table(['Layer','State / scope'])
        self.layer_table.setFixedHeight(175)
        self.layer_table.setStyleSheet('QTableWidget::item {padding:1px;}')
        self.layer_table.horizontalHeader().setFixedHeight(26)
        self.layer_table.verticalHeader().setMinimumSectionSize(20)
        self.layer_table.verticalHeader().setDefaultSectionSize(20)
        self.layer_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents)
        self.layer_table.cellDoubleClicked.connect(self.show_layer_details)
        layout.addWidget(self.layer_table)
        row=QHBoxLayout(); self.action(row,'Refresh Layer Status',self.refresh_defense_layers); row.addStretch(); layout.addLayout(row)
        tabs.addTab(page,'Layers')
        page=QWidget(); layout=QVBoxLayout(page); layout.setContentsMargins(14,12,14,12)
        options=self.store.get('inspection_options',{})
        self.archive_option=QCheckBox('Inspect files inside ZIP archives with bounded expansion')
        self.archive_option.setChecked(options.get('archives',True))
        self.amsi_option=QCheckBox('Inspect script files using installed Windows AMSI providers')
        self.amsi_option.setChecked(options.get('amsi',False))
        self.event_option=QCheckBox('Subscribe to process-start events; retain polling as reconciliation')
        self.event_option.setChecked(self.store.get('event_processes',True))
        for item in (self.archive_option,self.amsi_option,self.event_option): layout.addWidget(item)
        note=QLabel('AMSI is a consumer bridge to existing protection, not a registered SentinelAV provider.\nMemory inspection is read-only, limited to your account, and saves no raw memory.',objectName='small')
        note.setWordWrap(True); layout.addWidget(note)
        row=QHBoxLayout()
        self.memory_button=self.action(row,'Inspect Process Memory…',lambda:self.begin_bounded_inspection('memory'))
        self.prelaunch_button=self.action(row,'Check File Before Execution…',lambda:self.begin_bounded_inspection('file'))
        layout.addLayout(row)
        self.inspection_note=QLabel('No process memory or pre-execution inspection has run. Files are never launched here.',objectName='small')
        self.inspection_note.setWordWrap(True); layout.addWidget(self.inspection_note)
        row=QHBoxLayout(); self.action(row,'View Last Inspection',self.show_inspection_details); row.addStretch(); layout.addLayout(row)
        layout.addStretch(); tabs.addTab(page,'Inspection')
        page=QWidget(); layout=QVBoxLayout(page); layout.setContentsMargins(14,10,14,10)
        policy=self.store.get('auto_response',{})
        self.auto_response_option=QCheckBox('Automatically quarantine explicitly approved exact-hash detections')
        self.auto_response_option.setChecked(policy.get('enabled',False)); layout.addWidget(self.auto_response_option)
        layout.addWidget(QLabel('Approved SHA-256 hashes — one per line (maximum 256)',objectName='small'))
        self.response_hashes=QPlainTextEdit('\n'.join(policy.get('approved_hashes',[]))); self.response_hashes.setFixedHeight(45); layout.addWidget(self.response_hashes)
        layout.addWidget(QLabel('Allowed local folders — one per line (maximum 32)',objectName='small'))
        self.response_roots=QPlainTextEdit('\n'.join(policy.get('roots',[]))); self.response_roots.setFixedHeight(45); layout.addWidget(self.response_roots)
        note=QLabel('Default is off. Approved matches move to encrypted quarantine after fresh verification.\nMaximum three attempts/minute; no automatic process termination or member response.\nSave and restart to enable/change scope. Disabling stops queued actions; an active action may finish.',objectName='small')
        note.setWordWrap(True); layout.addWidget(note); layout.addStretch(); tabs.addTab(page,'Response Policy')
        self.last_inspection=None
        self.last_protection_state={}
        self.refresh_defense_layers()

    def refresh_defense_layers(self):
        service=read_health()
        active=self.last_protection_state
        policy=self.store.get('auto_response',{})
        self.layer_details=[
            dict(layer='Windows service',state=service['state'],detail=service,remaining='Admin deployment/start is required. Install-ProtectionService.ps1 stages protected code/policy. Refresh and view these details for bounded recent service alerts. Existing per-user background mode remains separate.'),
            dict(layer='Process telemetry',state=active.get('process_event_source','Available; monitoring not verified'),remaining='WMI start events plus reconciliation polling; no guarantee of complete visibility.'),
            dict(layer='Script / AMSI',state='Consumer available; native provider not deployed',remaining='Native x64 provider and protected-service buffer broker are implemented for local harness testing. Signing, protected provider registration, real LocalService integration, and VM/host validation remain. No native provider is registered by the app; existing providers remain enabled.'),
            dict(layer='Pre-execution',state='Manual verdict only; global enforcement unavailable',remaining='System-wide interception needs reviewed native integration such as a signed minifilter; Windows SDK/WDK, signing, deployment and recovery validation are prerequisites. No driver is installed.'),
            dict(layer='Archives / formats',state='ZIP and bounded PE inspection available',remaining='ZIP: depth 2, 128 entries, 8 MiB/member, 32 MiB expansion, 100:1 ratio. Encrypted/unsupported content reports omissions.'),
            dict(layer='Memory inspection',state='Manual, same-account executable regions',remaining='32 MiB/128 regions/5-second scope. File-oriented rules can miss memory-only threats. Private executable memory may be legitimate JIT code.'),
            dict(layer='Behavior correlation',state='PID/creation-time ancestry and combined indicators',remaining='Files are not attributed to processes without causal telemetry. These heuristics are unvalidated against broad evasion.'),
            dict(layer='Installation / tamper',state='Protected deployment staged; per-user mode remains writable' if service['state']!='Running' else 'Service ACL deployment; no PPL/kernel protection',remaining='Service uses admin-owned Program Files/policy and startup integrity checks. No resistance to an administrator or kernel attacker is claimed.'),
            dict(layer='Containment policy',state='Active approved-hash quarantine' if active.get('automatic_response') else 'Configured; restart/verify monitoring' if policy.get('enabled') else 'Manual response; automatic policy off',remaining='Automatic actions require both an exact-hash detection and explicit hash/folder approval. Fresh scan, protected-path checks, encryption, audit, cooldown and rate limits apply.'),
            dict(layer='Scan worker isolation',state=active.get('inspection_isolation','Separate scan process with Windows job limits'),remaining='768 MiB job cap, two-process cap for venv compatibility, bounded JSON, timeouts and cancellation. Fault isolation is not a VM/AppContainer sandbox. Update conversion and trusted rule-review tooling have separate boundaries.')]
        self.fill(self.layer_table,[(r['layer'],r['state']) for r in self.layer_details])

    def show_layer_details(self,row,column):
        if 0<=row<len(self.layer_details):
            item=self.layer_details[row]
            box=QMessageBox(self); box.setWindowTitle(item['layer']); box.setText(item['state'])
            box.setInformativeText(item['remaining']); box.setDetailedText(json.dumps(item,indent=2)); box.exec()

    def save_settings(self):
        hashes=[h.strip().lower() for h in self.response_hashes.toPlainText().splitlines() if h.strip()]
        roots=[p.strip() for p in self.response_roots.toPlainText().splitlines() if p.strip()]
        if (len(hashes)>256 or len(set(hashes))!=len(hashes) or any(not re.fullmatch(r'[0-9a-f]{64}',h) for h in hashes)
                or len(roots)>32 or any(not Path(p).is_absolute() or not Path(p).is_dir() or (os.name=='nt' and len(Path(p).drive)!=2) for p in roots)
                or self.auto_response_option.isChecked() and not (hashes and roots)):
            QMessageBox.warning(self,'Invalid response policy','Use distinct SHA-256 hashes and existing local folders. Enabling automatic response requires both.')
            return
        self.store.set('inspection_options',dict(archives=self.archive_option.isChecked(),amsi=self.amsi_option.isChecked()))
        self.store.set('event_processes',self.event_option.isChecked())
        self.store.set('auto_response',dict(enabled=self.auto_response_option.isChecked(),approved_hashes=hashes,roots=roots))
        super().save_settings()
        self.refresh_defense_layers()

    def begin_bounded_inspection(self,kind):
        if self.inspection_worker or self.worker or self.response_worker or self.definition_worker:
            self.inspection_note.setText('Wait for the active scan/update/response operation first.'); return
        if kind=='memory':
            pid,okay=QInputDialog.getInt(self,'Read-only process inspection','PID owned by your Windows account:',os.getpid(),5,2**31-1)
            if not okay: return
            try: target=(pid,psutil.Process(pid).create_time())
            except psutil.Error as error: self.inspection_note.setText(str(error)); return
        else:
            target,_=QFileDialog.getOpenFileName(self,'Inspect file without executing it')
            if not target: return
        from sentinelav.ui.application import ROOT
        self.last_inspection=None
        self.inspection_worker=InspectionWorker(ROOT,kind,target,self.store.get('inspection_options',{}))
        self.inspection_worker.completed.connect(self.bounded_inspection_done)
        self.inspection_worker.failed.connect(lambda error:self.inspection_note.setText('Inspection failed / incomplete: '+error))
        self.inspection_worker.finished.connect(self.bounded_inspection_finished)
        self.memory_button.setEnabled(False); self.prelaunch_button.setEnabled(False)
        self.inspection_note.setText('Read-only inspection running in a limited worker…')
        self.inspection_worker.start()

    def bounded_inspection_done(self,result):
        self.last_inspection=result
        if 'verdict' in result: message=result['verdict']['decision']+' — '+result['verdict']['reason']+'. No file was launched.'
        elif result.get('status')=='Cancelled': message='Inspection cancelled; coverage is incomplete.'
        else: message=f"Read {result.get('bytes',0):,} bytes across {result.get('regions',0)} executable regions; {len(result.get('findings_requiring_review',[]))} findings; {len(result.get('omissions',[]))} omissions. Review details."
        self.inspection_note.setText(message)
        try:
            import time
            if 'scan' in result:
                report=dict(result['scan'],kind='Manual pre-execution check',guard_decision=result['verdict'])
                if result['verdict']['decision']=='Indeterminate' and report['status']=='Complete':
                    report['status']='Complete with omissions'
                    report['errors']=list(report['errors'])+[result['verdict']['reason']]
                self.store.save_scan(report)
            self.store.save_event(dict(time=time.strftime('%Y-%m-%d %H:%M:%S'),kind='Manual inspection completed',
                details=message,source='Manual inspection',level='Info',pid=result.get('pid')))
            self.refresh()
        except Exception: self.inspection_note.setText(message+' Audit recording failed.')

    def bounded_inspection_finished(self):
        self.inspection_worker.deleteLater(); self.inspection_worker=None
        self.memory_button.setEnabled(True); self.prelaunch_button.setEnabled(True)

    def show_inspection_details(self):
        if self.last_inspection:
            box=QMessageBox(self); box.setWindowTitle('Bounded inspection result'); box.setText(self.inspection_note.text())
            box.setDetailedText(json.dumps(self.last_inspection,indent=2)); box.exec()

    def receive_status(self,state):
        self.last_protection_state=dict(state)
        super().receive_status(state)

    def ready_for_response(self):
        if self.inspection_worker:
            self.response_status.setText('Wait for the manual inspection to finish.')
            return False
        return super().ready_for_response()

    def protection_finished(self):
        self.last_protection_state={}
        super().protection_finished()
        self.refresh_defense_layers()

    def navigate(self,index):
        super().navigate(index)
        if index==5 and hasattr(self,'layer_table'): self.refresh_defense_layers()

    def closeEvent(self,event):
        if self.inspection_worker:
            self.inspection_worker.requestInterruption(); event.ignore(); QTimer.singleShot(100,self.close); return
        super().closeEvent(event)

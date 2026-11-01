"""Explicit response actions; no automatic quarantine or process termination."""
import json
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtWidgets import (QLabel,QTabWidget,QWidget,QVBoxLayout,QHBoxLayout,
    QMessageBox,QFileDialog,QListWidget,QInputDialog,QTableWidget)
import psutil
from sentinelav.data.storage import Store
from sentinelav.response.response import ResponseService


class ResponseWorker(QThread):
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self,path,root,method,args):
        super().__init__()
        self.path,self.root,self.method,self.args = path,root,method,args

    def run(self):
        store = None
        try:
            store = Store(self.path)
            service = ResponseService(store,self.root)
            result = getattr(service,self.method)(*self.args)
            self.completed.emit(result)
        except Exception as error:
            if store:
                try:
                    ResponseService(store,self.root).audit('Response failed',f'{self.method}: {error}','Warning')
                except Exception:
                    pass
            self.failed.emit(str(error))
        finally:
            if store:
                store.db.close()


class ResponseMixin:
    def future_page(self,title,subtitle,body):
        if title!='Quarantine':
            return super().future_page(title,subtitle,body)
        layout = self.page('Quarantine','Review signature detections and manage encrypted, isolated files.')
        self.response_status = QLabel('Actions require review. Behavior warnings are not automatically quarantined.',objectName='small')
        self.response_status.setWordWrap(True)
        layout.addWidget(self.response_status)
        tabs = QTabWidget()
        pending = QWidget()
        pl = QVBoxLayout(pending)
        self.pending_table = self.table(['File','Detection','SHA-256'])
        self.pending_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.pending_table.setMinimumHeight(140)
        pl.addWidget(self.pending_table)
        row = QHBoxLayout()
        self.quarantine_button = self.action(row,'Quarantine Selected',self.quarantine_selected,True)
        self.action(row,'Trust Exact File',self.trust_selected)
        pl.addLayout(row)
        row = QHBoxLayout()
        self.action(row,'Exclude File Path',self.exclude_selected)
        self.action(row,'Terminate Matching Process…',self.terminate_selected)
        pl.addLayout(row)
        tabs.addTab(pending,'Detected Files')
        isolated = QWidget()
        il = QVBoxLayout(isolated)
        self.quarantine_table = self.table(['Name','Threat','Date','State'])
        self.quarantine_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        il.addWidget(self.quarantine_table)
        actions = QHBoxLayout()
        self.action(actions,'Restore…',lambda:self.restore_selected(False))
        self.action(actions,'Restore and Trust…',lambda:self.restore_selected(True))
        self.action(actions,'Permanently Delete',self.delete_selected)
        il.addLayout(actions)
        self.action(il,'Recover Interrupted Action',self.recover_selected)
        tabs.addTab(isolated,'Isolated Files')
        tabs.setFixedHeight(330)
        layout.addWidget(tabs)
        label = QLabel('Quarantine is encrypted for your Windows account. Restore never overwrites a file.\nStop scanning and monitoring before response actions. All actions appear under Reports → Protection Events.',objectName='small')
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addStretch()

    def settings_page(self):
        super().settings_page()
        tabs = self.stack.widget(5).findChild(QTabWidget)
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel('Exact SHA-256 trust overrides signature matches only. It does not suppress behavior warnings. Remove trust to scan that content normally again.',objectName='small')
        label.setWordWrap(True)
        layout.addWidget(label)
        self.trusted_list = QListWidget()
        self.trusted_list.addItems(self.store.get('trusted_hashes',[]))
        layout.addWidget(self.trusted_list)
        self.action(layout,'Remove Selected Trust',self.remove_trust)
        tabs.addTab(page,'Trusted Files')

    def refresh(self):
        super().refresh()
        if not hasattr(self,'pending_table'):
            return
        trusted = set(self.store.get('trusted_hashes',[]))
        records = self.store.quarantine()
        isolated = {(r['original'],r['sha256']) for r in records if r['state'] in ('Preparing','Quarantined','Delete pending','Restore pending')}
        items = {}
        for scan in reversed(self.store.history()):
            for detection in scan['detections']:
                items[(detection['path'],detection['sha256'])]=detection
        for event in reversed(self.store.events(5000)):
            if event['kind']=='Threat detected' and event.get('sha256'):
                items[(event['path'],event['sha256'])]=dict(path=event['path'],sha256=event['sha256'],reasons=event['reasons'])
        self.pending_detections = [d for key,d in items.items() if key not in isolated and d['sha256'] not in trusted and Path(d['path']).is_file()]
        self.fill(self.pending_table,[(d['path'],'; '.join(d['reasons']),d['sha256']) for d in self.pending_detections])
        self.quarantine_records = records
        self.fill(self.quarantine_table,[(Path(r['original']).name,'; '.join(r['reasons']),r['date'],r['state']) for r in records])

    def ready_for_response(self):
        if self.worker or self.protection_worker or self.response_worker or self.monitor_state=='Unknown':
            QMessageBox.information(self,'Workers active','Stop monitoring and wait for scans or response actions to finish first.')
            return False
        return True

    def selected_detection(self):
        row = self.pending_table.currentRow()
        if row<0:
            self.response_status.setText('Select a detected file first.')
            return None
        return self.pending_detections[row]

    def selected_quarantine(self):
        row = self.quarantine_table.currentRow()
        if row<0:
            self.response_status.setText('Select an isolated file first.')
            return None
        record = self.quarantine_records[row]
        if record['state'] not in ('Preparing','Quarantined','Restore pending','Delete pending'):
            self.response_status.setText('This item has already been restored or deleted.')
            return None
        return record

    def confirm(self,title,text):
        return QMessageBox.question(self,title,text,QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)==QMessageBox.StandardButton.Yes

    def launch_response(self,method,*args,trust_hash=None):
        from sentinelav.ui.application import ROOT
        self.response_status.setText('Working…')
        self.restore_trust_hash = trust_hash
        self.response_worker = ResponseWorker(self.store.path,ROOT,method,args)
        self.response_worker.completed.connect(self.response_completed)
        self.response_worker.failed.connect(self.response_failed)
        self.response_worker.finished.connect(self.response_finished)
        self.quarantine_button.setEnabled(False)
        self.response_worker.start()

    def response_completed(self,result):
        if self.restore_trust_hash:
            self.trust_hash(self.restore_trust_hash)
        self.response_status.setText(result.get('state','Complete') + '. Response action recorded.')
        self.refresh()

    def response_failed(self,error):
        self.response_status.setText('Action failed: '+error)
        self.refresh()

    def response_finished(self):
        self.response_worker.deleteLater()
        self.response_worker=None
        self.quarantine_button.setEnabled(True)

    def quarantine_selected(self):
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if detection and self.confirm('Quarantine file?',f"Encrypt and isolate this file, removing its original copy?\n\n{detection['path']}"):
            self.launch_response('quarantine_file',detection)

    def restore_selected(self,trust):
        if not self.ready_for_response():
            return
        record = self.selected_quarantine()
        if not record:
            return
        target,_ = QFileDialog.getSaveFileName(self,'Choose restore destination (no overwrite)',record['original'])
        if target and self.confirm('Restore detected file?',f"Restore this detected content to:\n{target}\n\nIt may be unsafe. " + ('Its exact SHA-256 will be trusted in future scans.' if trust else 'It may trigger detection again.')):
            self.launch_response('restore',record['id'],target,trust_hash=record['sha256'] if trust else None)

    def delete_selected(self):
        if not self.ready_for_response():
            return
        record = self.selected_quarantine()
        if record and self.confirm('Permanently delete?',f"Delete the encrypted quarantine copy of {record['original']}?\nThis cannot be restored by SentinelAV."):
            self.launch_response('delete',record['id'])

    def recover_selected(self):
        if not self.ready_for_response():
            return
        record = self.selected_quarantine()
        if record and self.confirm('Recover interrupted action?', 'Verify the pending operation and reconcile its recorded state? A verified restored copy may allow removal of its redundant encrypted backup.'):
            self.launch_response('recover',record['id'])

    def trust_hash(self,sha):
        hashes = self.store.get('trusted_hashes',[])
        if sha not in hashes:
            hashes.append(sha)
            self.store.set('trusted_hashes',hashes)
            self.trusted_list.addItem(sha)
            self.audit_response('Exact hash trusted',sha)

    def audit_response(self,kind,details):
        from sentinelav.ui.application import ROOT
        ResponseService(self.store,ROOT).audit(kind,details)

    def trust_selected(self):
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if detection and self.confirm('Trust exact file content?',f"Suppress signature matches for this exact SHA-256 on future scans?\n{detection['sha256']}\nBehavior warnings remain enabled."):
            self.trust_hash(detection['sha256'])
            self.refresh()

    def exclude_selected(self):
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if detection and self.confirm('Exclude file path?',f"Skip future inspection of this path, including changed content?\n{detection['path']}"):
            paths = self.store.get('exclusions',[])
            if detection['path'] not in paths:
                paths.append(detection['path'])
                self.store.set('exclusions',paths)
                self.exclusions.setPlainText('\n'.join(paths))
            self.audit_response('File path excluded',detection['path'])
            self.refresh()

    def remove_trust(self):
        if not self.ready_for_response():
            return
        row = self.trusted_list.currentRow()
        if row>=0:
            hashes = self.store.get('trusted_hashes',[])
            removed = hashes.pop(row)
            self.store.set('trusted_hashes',hashes)
            self.trusted_list.takeItem(row)
            self.audit_response('Hash trust removed',removed)
            self.refresh()

    def terminate_selected(self):
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if not detection:
            return
        matches = {}
        for process in psutil.process_iter(['pid','name','exe','create_time']):
            info = process.info
            if info.get('exe') and Path(info['exe']).resolve()==Path(detection['path']).resolve():
                matches[f"{info['name']} — PID {info['pid']}"]=info
        if not matches:
            self.response_status.setText('No accessible running process matches the selected executable.')
            return
        selected,ok = QInputDialog.getItem(self,'Select process','Matching executable:',list(matches),0,False)
        if ok and self.confirm('Terminate process?',f"Terminate {selected}? Unsaved work may be lost.\nThe executable must still match a detection; protected processes are blocked."):
            info = matches[selected]
            self.launch_response('terminate',info['pid'],info['create_time'],detection)

    def start_scan(self,roots,kind):
        if self.response_worker:
            self.response_status.setText('Wait for the response operation to finish.')
            self.navigate(3)
            return
        super().start_scan(roots,kind)

    def begin_protection(self):
        if self.response_worker:
            self.response_status.setText('Wait for the response operation to finish.')
            self.navigate(3)
            return
        super().begin_protection()

    def closeEvent(self,event):
        if self.response_worker:
            event.ignore()
            QTimer.singleShot(100,self.close)
            return
        super().closeEvent(event)

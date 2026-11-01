"""Definition maintenance in the existing Settings UI; file work stays off Qt UI."""
from pathlib import Path
import threading
from PySide6.QtCore import QThread,Signal,QTimer
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QTabWidget,QFileDialog
from sentinelav.updates.definition_updates import load_active,freshness,import_recent,apply_signed,apply_changes,read_json,rollback,MAX_PAYLOAD
from sentinelav.updates.hash_archive import import_archive


class DefinitionWorker(QThread):
    completed=Signal(dict)
    failed=Signal(str)
    progress=Signal(str)

    def __init__(self,root,kind,path=None):
        super().__init__()
        self.root,self.kind,self.path=Path(root),kind,path
        self.cancelled=threading.Event()

    def run(self):
        folder=self.root/'signature-data'
        try:
            if self.kind=='recent': result=import_recent(folder,self.path)
            elif self.kind=='signed': result=apply_signed(folder,self.path,self.root/'trusted-update-keys.json')
            elif self.kind=='corrections': result=apply_changes(folder,read_json(self.path,MAX_PAYLOAD),'Manual explicit corrections; not publisher-authenticated')
            elif self.kind=='rollback': result=rollback(folder)
            elif self.kind=='full':
                def report(count):
                    if self.cancelled.is_set(): raise InterruptedError('Import cancelled before activation')
                    self.progress.emit(f'Validated {count:,} CSV rows…')
                result=import_archive(self.path,folder,True,report)
            else: raise ValueError('Unsupported definition operation')
            self.completed.emit(result)
        except Exception as error:
            self.failed.emit(str(error))


class UpdatesMixin:
    def settings_page(self):
        super().settings_page()
        tabs=self.stack.widget(5).findChild(QTabWidget)
        page=QWidget()
        layout=QVBoxLayout(page)
        layout.setContentsMargins(16,12,16,12)
        self.definition_health=QLabel(objectName='small')
        self.definition_health.setWordWrap(True)
        layout.addWidget(self.definition_health)
        self.definition_buttons=[]
        for specs in [[('Import recent CSV…','recent'),('Import full CSV ZIP…','full')],
                      [('Apply signed package…','signed'),('Apply reviewed corrections…','corrections'),('Roll Back Last Update','rollback')]]:
            row=QHBoxLayout()
            for title,kind in specs:
                self.definition_buttons.append(self.action(row,title,lambda checked=False,k=kind:self.begin_definition_update(k)))
            layout.addLayout(row)
        self.definition_result=QLabel('Updates are manual. No publisher key or remote update server is configured by default.',objectName='small')
        self.definition_result.setWordWrap(True)
        layout.addWidget(self.definition_result)
        note=QLabel('Recent imports never remove hashes just because they are absent. Explicit corrections can revoke hashes.\nChanges apply to new scans; restart monitoring to load the new snapshot.',objectName='small')
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch()
        tabs.addTab(page,'Definitions')
        self.refresh_definition_health()

    def refresh_definition_health(self):
        from sentinelav.ui.application import ROOT
        try:
            metadata=load_active(ROOT/'signature-data')
            state,hours=freshness(metadata)
            age=f'{hours:g} hours' if hours is not None else 'unknown'
            self.definition_health.setText(f"{metadata['unique_sha256']:,} full-feed hashes · {state} · import age: {age}\n"
                f"Source: {metadata.get('source','Unknown')} · {metadata.get('update_method','Manual full export import')}\n"
                'Signed publisher: '+('configured' if read_json(ROOT/'trusted-update-keys.json').get('keys') else 'not configured'))
        except Exception as error:
            self.definition_health.setText('Definition status unavailable: '+str(error))

    def begin_definition_update(self,kind):
        if self.definition_worker or self.worker or self.response_worker or self.lab_worker or self.preferences_worker:
            self.definition_result.setText('Finish the current scan, response, lab, or settings operation first.')
            return
        path=None
        if kind!='rollback':
            filters={'recent':'CSV files (*.csv)','full':'ZIP archives (*.zip)','signed':'Signed update packages (*.zip)','corrections':'Reviewed corrections (*.json)'}
            path,_=QFileDialog.getOpenFileName(self,'Select definition update',filter=filters[kind])
            if not path: return
        from sentinelav.ui.application import ROOT
        self.definition_worker=DefinitionWorker(ROOT,kind,path)
        self.definition_worker.completed.connect(self.definition_update_done)
        self.definition_worker.failed.connect(lambda error:self.definition_result.setText('Update failed; active definitions were preserved. '+error))
        self.definition_worker.progress.connect(self.definition_result.setText)
        self.definition_worker.finished.connect(self.definition_update_finished)
        for button in self.definition_buttons: button.setEnabled(False)
        self.definition_result.setText('Validating and preparing definition snapshot…')
        self.definition_worker.start()

    def definition_update_done(self,metadata):
        self.refresh_definition_health()
        self.definition_result.setText(f"Activated {metadata['unique_sha256']:,} full-feed hashes. New scans use this version; restart monitoring to reload. Prior snapshot retained for rollback.")
        try:
            import time
            self.store.save_event(dict(time=time.strftime('%Y-%m-%d %H:%M:%S'),kind='Definitions updated',
                details=metadata.get('update_method','Manual full CSV import')+' · '+metadata['database'],source='Definitions',level='Info'))
        except Exception:
            self.definition_result.setText(self.definition_result.text()+' Local audit recording failed.')

    def definition_update_finished(self):
        self.definition_worker.deleteLater()
        self.definition_worker=None
        for button in self.definition_buttons: button.setEnabled(True)

    def ready_for_response(self):
        if self.definition_worker:
            self.response_status.setText('Wait for the definition update to finish.')
            return False
        return super().ready_for_response()

    def start_scan(self,roots,kind):
        if self.definition_worker:
            self.statusBar().showMessage('Wait for the definition update to finish.',5000)
            return
        super().start_scan(roots,kind)

    def begin_protection(self):
        if self.definition_worker:
            self.statusBar().showMessage('Wait for the definition update to finish.',5000)
            return
        super().begin_protection()

    def start_lab(self):
        if self.definition_worker:
            self.lab_note.setText('Wait for the definition update to finish.')
            return
        super().start_lab()

    def check_schedule(self):
        if not self.definition_worker: super().check_schedule()

    def closeEvent(self,event):
        if self.definition_worker:
            self.definition_worker.cancelled.set()
            event.ignore()
            QTimer.singleShot(100,self.close)
            return
        super().closeEvent(event)

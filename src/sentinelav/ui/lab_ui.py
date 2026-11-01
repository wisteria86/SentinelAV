"""Familiar lab UI. This milestone exposes no live-sample or VM execution path."""
import json
import threading
from pathlib import Path
from PySide6.QtCore import QThread,Signal,QTimer,Qt
from PySide6.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QTabWidget,
    QTableWidgetItem,QFileDialog,QMessageBox,QPushButton,QHeaderView)
from sentinelav.lab.lab import PROFILES,SimulationRunner,capabilities
from sentinelav.ui.design import icon


class LabWorker(QThread):
    activity=Signal(dict)
    completed=Signal(dict)
    failed=Signal(str)

    def __init__(self,root,workspace,profiles):
        super().__init__()
        self.runner=SimulationRunner(root,workspace,self.activity.emit)
        self.profiles=profiles

    def run(self):
        try:
            self.completed.emit(self.runner.run(self.profiles))
        except Exception as error:
            self.failed.emit(str(error))


class CapabilityWorker(QThread):
    completed=Signal(dict)

    def run(self):
        self.completed.emit(capabilities())


class LabMixin:
    def lab_page(self):
        layout=self.page('Malware Lab','Prepare a future VM lab and verify SentinelAV with harmless tests.')
        badge=QLabel('SAFE SIMULATIONS · LOCAL · NO VM CONFIGURED')
        badge.setStyleSheet('color:#995319;font-weight:600;background:#f9e8cf;border-radius:5px;padding:9px;')
        layout.addWidget(badge)
        self.lab_tabs=QTabWidget()
        self.lab_tabs.setMinimumHeight(350)
        self.lab_tabs.setMaximumHeight(410)
        overview=QWidget()
        ol=QVBoxLayout(overview)
        ol.setContentsMargins(16,16,16,16)
        self.lab_state=QLabel('Ready for safe simulations',objectName='value')
        ol.addWidget(self.lab_state)
        description=QLabel('These tests use generated text files and synthetic records. They do not execute malware, launch samples, or establish VM isolation.',objectName='muted')
        description.setWordWrap(True)
        ol.addWidget(description)
        self.lab_readiness=QLabel('VM readiness has not been checked. No dedicated test VM has been registered.',objectName='small')
        self.lab_readiness.setWordWrap(True)
        ol.addWidget(self.lab_readiness)
        actions=QHBoxLayout()
        self.lab_check=self.action(actions,'Check System',self.check_lab_system)
        setup=self.action(actions,'VM Setup — Not Configured',lambda:None)
        setup.setEnabled(False)
        setup.setToolTip('A dedicated Windows VM and verified clean baseline are required in a later milestone.')
        ol.addLayout(actions)
        ol.addWidget(QLabel('Workflow: choose tests → run simulations → review evidence.\nTemporary test files are removed after each run.',objectName='small'))
        ol.addStretch()
        self.lab_tabs.addTab(overview,'Overview')
        queue=QWidget()
        ql=QVBoxLayout(queue)
        self.lab_queue=self.table(['Run','Test profile','What it checks'])
        self.lab_queue.setRowCount(len(PROFILES))
        self.lab_queue.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.ResizeToContents)
        self.lab_queue.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.ResizeToContents)
        self.lab_queue.setWordWrap(True)
        self.lab_queue.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.lab_queue.horizontalHeader().sectionResized.connect(lambda *args:self.lab_queue.resizeRowsToContents())
        for row,(key,(name,detail)) in enumerate(PROFILES.items()):
            item=QTableWidgetItem('')
            item.setFlags(Qt.ItemFlag.ItemIsUserCheckable|Qt.ItemFlag.ItemIsEnabled)
            item.setCheckState(Qt.CheckState.Checked if row==0 else Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole,key)
            self.lab_queue.setItem(row,0,item)
            for column,text in [(1,name),(2,detail)]:
                cell=QTableWidgetItem(text)
                cell.setToolTip(text)
                self.lab_queue.setItem(row,column,cell)
        QTimer.singleShot(0,self.lab_queue.resizeRowsToContents)
        ql.addWidget(self.lab_queue)
        note=QLabel('Only the listed profiles are supported. Synthetic telemetry checks rules, not real malware behavior or VM containment.',objectName='small')
        note.setWordWrap(True)
        ql.addWidget(note)
        self.lab_tabs.addTab(queue,'Test Queue')
        live=QWidget()
        ll=QVBoxLayout(live)
        self.lab_activity_table=self.table(['Time','Stage','Details'])
        ll.addWidget(self.lab_activity_table)
        self.lab_tabs.addTab(live,'Live Activity')
        results=QWidget()
        rl=QVBoxLayout(results)
        self.lab_results_table=self.table(['Date','Tests','Outcome','Cleanup'])
        self.lab_results_table.cellDoubleClicked.connect(self.show_lab_result)
        rl.addWidget(self.lab_results_table)
        row=QHBoxLayout()
        self.action(row,'View Details',self.show_lab_result)
        self.action(row,'Export Selected JSON',self.export_lab_result)
        rl.addLayout(row)
        self.lab_tabs.addTab(results,'Results')
        layout.addWidget(self.lab_tabs)
        controls=QHBoxLayout()
        self.lab_start=self.action(controls,'Run Selected Safe Tests',self.start_lab,True)
        self.lab_stop=self.action(controls,'Stop',self.stop_lab)
        self.lab_stop.setEnabled(False)
        layout.addLayout(controls)
        self.lab_note=QLabel('Lab results stay separate from real protection alerts and scan history.',objectName='small')
        self.lab_note.setWordWrap(True)
        layout.addWidget(self.lab_note)
        layout.addStretch()
        self.lab_activity=[]
        self.refresh_lab_results()

    def check_lab_system(self):
        if self.capability_worker:
            return
        self.lab_check.setEnabled(False)
        self.lab_readiness.setText('Checking available Windows tools. No settings will be changed…')
        self.capability_worker=CapabilityWorker()
        self.capability_worker.completed.connect(self.lab_capabilities)
        self.capability_worker.finished.connect(self.capability_finished)
        self.capability_worker.start()

    def lab_capabilities(self,result):
        self.lab_readiness.setText(f"Hyper-V tools: {'available' if result['hyperv_tools'] else 'unavailable'} · VM service: {result['vm_service']}\n"+result['note'])

    def capability_finished(self):
        self.capability_worker.deleteLater()
        self.capability_worker=None
        self.lab_check.setEnabled(True)

    def start_lab(self):
        if self.lab_worker or self.worker or self.response_worker or self.preferences_worker:
            self.lab_note.setText('Finish the current scan or response/settings operation before starting a lab run.')
            return
        profiles=[self.lab_queue.item(row,0).data(Qt.ItemDataRole.UserRole) for row in range(self.lab_queue.rowCount()) if self.lab_queue.item(row,0).checkState()==Qt.CheckState.Checked]
        if not profiles:
            self.lab_tabs.setCurrentIndex(1)
            self.lab_note.setText('Select at least one harmless test in Test Queue.')
            return
        from sentinelav.ui.application import ROOT
        self.lab_activity=[]
        self.lab_activity_table.setRowCount(0)
        self.lab_state.setText('Running safe simulations')
        self.lab_note.setText('Generated fixtures only. No VM, sample execution, or real network traffic.')
        self.lab_start.setEnabled(False)
        self.lab_queue.setEnabled(False)
        self.lab_stop.setEnabled(True)
        self.lab_tabs.setCurrentIndex(2)
        self.lab_worker=LabWorker(ROOT,self.store.path.parent/'lab-workspaces',profiles)
        self.lab_worker.activity.connect(self.lab_activity_event)
        self.lab_worker.completed.connect(self.lab_completed)
        self.lab_worker.failed.connect(self.lab_failed)
        self.lab_worker.finished.connect(self.lab_finished)
        self.lab_worker.start()

    def stop_lab(self):
        if self.lab_worker:
            self.lab_worker.runner.stop.set()
            self.lab_stop.setEnabled(False)
            self.lab_state.setText('Stopping and cleaning temporary fixtures…')

    def lab_activity_event(self,event):
        self.lab_activity.append(event)
        self.lab_activity=self.lab_activity[-200:]
        self.fill(self.lab_activity_table,[(e['time'],e['kind'],e['details']) for e in self.lab_activity])

    def lab_completed(self,run):
        self.store.save_lab_run(run)
        self.audit_response('Safe lab simulation completed',f"{run['id']}: {run['status']}; fixture cleanup: {run['workspace_reset']}")
        self.lab_state.setText('Simulation: '+run['status'])
        self.lab_cleanup_ok=run['workspace_reset']
        self.lab_note.setText(('Fixture cleanup verified. ' if run['workspace_reset'] else 'Fixture cleanup failed; further runs are blocked. ')+run.get('error','Results are simulation evidence, not a malware-detection or containment certification.'))
        self.refresh_lab_results()
        self.lab_tabs.setCurrentIndex(3)

    def lab_failed(self,error):
        self.lab_state.setText('Simulation could not start')
        self.lab_note.setText(error)

    def lab_finished(self):
        self.lab_worker.deleteLater()
        self.lab_worker=None
        self.lab_stop.setEnabled(False)
        self.lab_queue.setEnabled(True)
        self.lab_start.setEnabled(self.lab_cleanup_ok)

    def refresh_lab_results(self):
        self.lab_runs=self.store.lab_runs()
        self.fill(self.lab_results_table,[(r['date'],len(r['profiles']),r['status'],'Verified' if r['workspace_reset'] else 'Failed') for r in self.lab_runs])

    def selected_lab_run(self,row=None):
        row=self.lab_results_table.currentRow() if row is None or isinstance(row,bool) else row
        if row<0 or row>=len(self.lab_runs):
            self.lab_note.setText('Select a saved simulation result first.')
            return None
        return self.lab_runs[row]

    def show_lab_result(self,row=None,column=None):
        run=self.selected_lab_run(row)
        if run:
            box=QMessageBox(self)
            box.setWindowTitle('Safe simulation evidence')
            box.setText(run['status']+' · local simulation, no VM execution')
            box.setDetailedText(json.dumps(run,indent=2)[:512000])
            box.exec()

    def export_lab_result(self):
        run=self.selected_lab_run()
        if not run:
            return
        path,_=QFileDialog.getSaveFileName(self,'Export safe simulation evidence','sentinelav-lab-'+run['id']+'.json','JSON (*.json)')
        if path:
            try:
                Path(path).write_text(json.dumps(run,indent=2),encoding='utf-8')
            except OSError as error:
                self.lab_note.setText('Export failed: '+str(error))

    def ready_for_response(self):
        if self.lab_worker:
            self.response_status.setText('Finish or stop the safe simulation first.')
            return False
        return super().ready_for_response()

    def start_scan(self,roots,kind):
        if self.lab_worker:
            self.navigate(6)
            self.lab_note.setText('Finish or stop the current lab simulation before scanning.')
            return
        super().start_scan(roots,kind)

    def check_schedule(self):
        if not self.lab_worker:
            super().check_schedule()

    def closeEvent(self,event):
        if self.lab_worker or self.capability_worker:
            self.stop_lab()
            event.ignore()
            QTimer.singleShot(100,self.close)
            return
        super().closeEvent(event)

# Purpose: Explicit response actions; no automatic quarantine or process termination.
# Works with: data.storage, response.response, ui.application, ui.response_actions, ui.response_pages
# Used by: ui.application

"""Explicit response actions; no automatic quarantine or process termination."""
import json
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QTimer,Qt
from PySide6.QtWidgets import (QLabel,QTabWidget,QWidget,QVBoxLayout,QHBoxLayout,
    QMessageBox,QFileDialog,QListWidget,QInputDialog,QTableWidget,QPushButton,QMenu,QDialog,QDialogButtonBox,QTableWidgetItem)
import psutil
from sentinelav.data.storage import Store
from sentinelav.response.response import ResponseService


from .response_ui_workers import ResponseWorker
from .response_pages import ResponsePagesMixin
from .response_actions import ResponseActionsMixin

class ResponseMixin(ResponsePagesMixin, ResponseActionsMixin):


    def ready_for_response(self):
        # Monitoring keeps running: threats must be removable while protection is on, and the vault waits out brief file locks.
        if self.worker or self.response_worker:
            QMessageBox.information(self,'Operation active','Wait for the scan or response action to finish first.')
            return False
        return True


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
        if 'process_tree_plan' in result:
            self.response_status.setText('Process tree collected. No process has been terminated.')
            self.show_process_tree_plan(result['process_tree_plan'])
            return
        if self.restore_trust_hash:
            self.trust_hash(self.restore_trust_hash)
        self.response_status.setText(result.get('state','Complete') + '. Response action recorded.')
        self.refresh()
        if 'process_tree_result' in result:
            box=QMessageBox(self); box.setWindowTitle('Process-tree response')
            box.setText(result['state']); box.setDetailedText(json.dumps(result['process_tree_result'],indent=2)); box.exec()

    def review_process_tree(self):
        if not self.ready_for_response(): return
        pid,okay=QInputDialog.getInt(self,'Review process tree','Root PID (planning does not terminate anything):',0,1,2**31-1)
        if not okay: return
        try: creation=psutil.Process(pid).create_time()
        except psutil.Error as error: self.response_status.setText(str(error)); return
        self.launch_response('plan_process_tree',pid,creation)

    def show_process_tree_plan(self,plan):
        dialog=QDialog(self); dialog.setWindowTitle('Review process-tree response'); dialog.resize(800,440)
        layout=QVBoxLayout(dialog)
        note=QLabel('Select processes you explicitly approve for termination. Each still requires a fresh signature detection.\nUnselected processes stay untouched. The plan expires after two minutes.')
        note.setWordWrap(True); layout.addWidget(note)
        table=self.table(['Approve','PID','Executable','SHA-256']); table.setMinimumHeight(220)
        table.setRowCount(len(plan['processes']))
        for row,item in enumerate(plan['processes']):
            checkbox=QTableWidgetItem(); checkbox.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsUserCheckable)
            checkbox.setCheckState(Qt.CheckState.Unchecked); table.setItem(row,0,checkbox)
            for column,key in ((1,'pid'),(2,'path'),(3,'sha256')):
                cell=QTableWidgetItem(str(item[key])); cell.setToolTip(str(item[key])); table.setItem(row,column,cell)
        layout.addWidget(table)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText('Terminate Approved')
        buttons.rejected.connect(dialog.reject)
        def approve():
            selected=[item for row,item in enumerate(plan['processes']) if table.item(row,0).checkState()==Qt.CheckState.Checked]
            if not selected: return
            if not self.ready_for_response(): return
            if not self.confirm('Terminate approved processes?',f'Terminate {len(selected)} selected process(es) after fresh identity and detection checks?'): return
            subset=dict(plan,processes=selected)
            dialog.accept(); self.launch_response('respond_process_tree',subset,list({item['sha256'] for item in selected}))
        buttons.accepted.connect(approve); layout.addWidget(buttons); dialog.exec()

    def response_failed(self,error):
        self.response_status.setText('Action failed: '+error)
        self.refresh()

    def response_finished(self):
        self.response_worker.deleteLater()
        self.response_worker=None
        self.quarantine_button.setEnabled(True)


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

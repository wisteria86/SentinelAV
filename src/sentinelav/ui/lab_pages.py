# Purpose: Build harmless-lab controls and show system prerequisite checks.
# Works with: lab.lab, ui.lab_ui_workers, ui.runtime_ui
# Used by: ui.lab_ui

"""Safe simulations plus a separately confirmed, offline guest-only runtime path."""
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QTableWidgetItem, QHeaderView
from sentinelav.lab.lab import PROFILES
from .lab_ui_workers import CapabilityWorker


class LabPagesMixin:
    """Builds the Malware Lab page."""
    def lab_page(self):
        """Build the Malware Lab page: Overview, Test Queue, Live Activity, Results and Runtime tabs,
        plus run and stop buttons.
        """
        layout=self.page('Malware Lab','Run harmless local simulations or explicitly controlled offline guest jobs.')
        badge=QLabel('SAFE SIMULATIONS · SEPARATE OFFLINE GUEST JOBS')
        badge.setStyleSheet('color:#995319;font-weight:600;background:#f9e8cf;border-radius:8px;padding:9px 12px;')
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
        self.lab_readiness=QLabel('Registered guest readiness has not been checked in this session.',objectName='small')
        self.lab_readiness.setWordWrap(True)
        ol.addWidget(self.lab_readiness)
        actions=QHBoxLayout()
        self.lab_check=self.action(actions,'Check System',self.check_lab_system)
        setup=self.action(actions,'Prepare Guest Kit…',lambda:self.prepare_guest_kit())
        self.action(actions,'Start Registered Guest…',lambda:self.start_registered_guest())
        setup.setToolTip('Prepare the source-workspace read-only lab kit from a built package. Does not execute specimens.')
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
        from sentinelav.ui.runtime_ui import add_runtime_tab
        add_runtime_tab(self,self.lab_tabs)
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
        """Check which virtualisation tools are available, in a background worker."""
        if self.capability_worker:
            return
        self.lab_check.setEnabled(False)
        self.lab_readiness.setText('Checking available Windows tools. No settings will be changed…')
        self.capability_worker=CapabilityWorker()
        self.capability_worker.completed.connect(self.lab_capabilities)
        self.capability_worker.finished.connect(self.capability_finished)
        self.capability_worker.start()

    def lab_capabilities(self,result):
        """Show the result of the system check."""
        self.lab_readiness.setText(f"Hyper-V tools: {'available' if result['hyperv_tools'] else 'unavailable'} · VM service: {result['vm_service']}\n"+result['note'])

    def capability_finished(self):
        """Tidy up after the system check and re-enable its button."""
        self.capability_worker.deleteLater()
        self.capability_worker=None
        self.lab_check.setEnabled(True)

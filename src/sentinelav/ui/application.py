from sentinelav.paths import RESOURCE_ROOT
import json
import os
import sys
import time
from pathlib import Path
from PySide6.QtCore import QThread, Signal, Qt, QTimer, QSize
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout,
    QVBoxLayout, QLabel, QPushButton, QStackedWidget, QFrame, QFileDialog,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QSpinBox, QPlainTextEdit, QSizePolicy)
from sentinelav.detection.inspection import IsolatedScanner as Scanner
from sentinelav.data.storage import Store

ROOT = RESOURCE_ROOT


class ScanWorker(QThread):
    progress = Signal(str, int, int)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, roots, max_mb, exclusions, trusted_hashes=(),options=None):
        super().__init__()
        self.roots, self.max_mb, self.exclusions = roots, max_mb, exclusions
        self.trusted_hashes = trusted_hashes
        self.options=options

    def run(self):
        try:
            engine = Scanner(ROOT/'signatures.json', ROOT/'rules', self.max_mb, self.exclusions,self.trusted_hashes,self.options)
            last = [0.0]
            def report(path, scanned, threats):
                if time.monotonic() - last[0] > .1:
                    self.progress.emit(path, scanned, threats)
                    last[0] = time.monotonic()
            self.completed.emit(engine.scan(self.roots, self.isInterruptionRequested, report))
        except Exception as error:
            self.failed.emit(str(error))


class BaseWindow(QMainWindow):
    def __init__(self, data_dir=None):
        super().__init__()
        self.setWindowTitle('SentinelAV')
        self.resize(1000, 620)
        self.setMinimumSize(960, 600)
        self.setWindowIcon(icon('shield'))
        self.store = Store((data_dir or Path(os.getenv('LOCALAPPDATA', str(ROOT/'data')))/'SentinelAV')/'sentinelav.db')
        self.worker = None
        central = QWidget()
        self.setCentralWidget(central)
        row = QHBoxLayout(central)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        side = QFrame(objectName='sidebar')
        side.setFixedWidth(210)
        nav = QVBoxLayout(side)
        nav.setContentsMargins(7, 21, 7, 18)
        nav.setSpacing(5)
        brand = QHBoxLayout()
        brand.setContentsMargins(12,0,0,0)
        brand.addWidget(art('shield', 27, filled=True))
        brand.addWidget(QLabel('SentinelAV', objectName='brand'))
        brand.addStretch()
        nav.addLayout(brand)
        nav.addSpacing(19)
        self.stack = QStackedWidget()
        self.buttons = []
        for i, title in enumerate(['Dashboard', 'Scan', 'Real-Time Protection', 'Quarantine', 'Reports', 'Settings','Malware Lab']):
            button = QPushButton(title)
            button.setCheckable(True)
            button.setIcon(icon(['home','scan','shield','box','report','settings','lab'][i], '#fff0d9'))
            button.setIconSize(QSize(18,18))
            button.clicked.connect(lambda checked=False, index=i: self.navigate(index))
            self.buttons.append(button)
            nav.addWidget(button)
        nav.addStretch()
        footer = QLabel('On-demand prototype', objectName='small')
        footer.setContentsMargins(12,0,0,0)
        nav.addWidget(footer)
        row.addWidget(side)
        row.addWidget(self.stack, 1)
        self.dashboard()
        self.scan_page()
        self.future_page('Real-Time Protection', 'Continuous monitoring is planned for Phase 3.',
                         'Filesystem monitoring\nProcess monitoring\nWindows event integration\n\nStatus: not implemented. Closing this app stops all activity.')
        self.future_page('Quarantine', 'Threat isolation and recovery are planned for Phase 5.',
                         'Scans are read-only. Detected files stay in their original locations.\n\nRestore, delete, and process termination are not available yet.')
        self.reports_page()
        self.settings_page()
        self.lab_page()
        self.refresh()
        self.navigate(0)


    def card(self, layout):
        frame = QFrame(objectName='card')
        inner = QVBoxLayout(frame)
        inner.setContentsMargins(22, 22, 22, 22)
        inner.setSpacing(12)
        inner.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(frame)
        return inner

    def action(self, layout, text, callback, primary=False):
        button = QPushButton(text, objectName='primary' if primary else '')
        button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        button.clicked.connect(callback)
        layout.addWidget(button)
        return button



    def table(self, headings):
        table = QTableWidget(0, len(headings))
        table.setHorizontalHeaderLabels(headings)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        table.verticalHeader().setDefaultSectionSize(36)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.verticalHeader().hide()
        table.setWordWrap(False)
        return table




    def navigate(self, index):
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.buttons):
            button.setChecked(i == index)

    def save_settings(self):
        paths = [p.strip() for p in self.exclusions.toPlainText().splitlines() if p.strip()]
        if any(not Path(p).is_absolute() for p in paths):
            QMessageBox.warning(self, 'Invalid exclusion', 'Use absolute paths for exclusions.')
            return
        self.store.set('max_mb', self.limit.value())
        self.store.set('exclusions', paths)
        QMessageBox.information(self, 'Settings saved', 'Settings apply to the next scan.')

    def quick_scan(self):
        roots = [p for p in [Path.home()/'Downloads', Path(os.getenv('TEMP', str(Path.home()/'AppData/Local/Temp'))) ] if p.is_dir()]
        self.start_scan(roots, 'Quick Scan')

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose folder')
        if path:
            self.start_scan([path], 'Custom Folder')

    def choose_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Choose files')
        if paths:
            self.start_scan(paths, 'Selected Files')

    def start_scan(self, roots, kind):
        self.navigate(1)
        if self.worker is not None:
            QMessageBox.information(self, 'Scan active', 'Wait for the active scan or cancel it first.')
            return
        self.kind = kind
        self.select_scan_tab(0 if kind == 'Quick Scan' else 2)
        self.scan_start.setEnabled(False)
        self.select_files_button.setEnabled(False)
        for tab in self.scan_tabs:
            tab.setEnabled(False)
        self.scan_started = time.monotonic()
        self.live_stats[0].setText('0')
        self.live_stats[1].setText('0')
        self.live_stats[2].setText('00:00:00')
        self.elapsed_timer.start(1000)
        self.results.setRowCount(0)
        self.scan_status.setText('Scanning…')
        self.progress.setRange(0, 0)
        self.cancel.setEnabled(True)
        self.worker = ScanWorker(roots, self.store.get('max_mb', 100), self.store.get('exclusions', [])+[str(self.store.path.parent)],self.store.get('trusted_hashes',[]),self.store.get('inspection_options',{}))
        self.worker.progress.connect(self.update_scan)
        self.worker.completed.connect(self.finished_scan)
        self.worker.failed.connect(self.failed_scan)
        self.worker.finished.connect(self.release_worker)
        self.worker.start()

    def update_scan(self, path, scanned, threats):
        self.path_label.setText(path)
        self.count.setText(f'{scanned:,} files inspected • {threats} detections')
        self.live_stats[0].setText(f'{scanned:,}')
        self.live_stats[1].setText(str(threats))

    def cancel_scan(self):
        if self.worker:
            self.worker.requestInterruption()
            self.cancel.setEnabled(False)
            self.scan_status.setText('Cancelling…')

    def release_worker(self):
        self.worker.deleteLater()
        self.worker = None
        self.scan_start.setEnabled(True)
        self.select_files_button.setEnabled(True)
        for tab in self.scan_tabs:
            tab.setEnabled(True)

    def failed_scan(self, error):
        self.elapsed_timer.stop()
        self.scan_status.setText('Scan failed')
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.cancel.setEnabled(False)
        self.path_label.setText(error)

    def finished_scan(self, result):
        self.elapsed_timer.stop()
        self.live_stats[0].setText(f"{result['scanned']:,}")
        self.live_stats[1].setText(str(len(result['detections'])))
        self.live_stats[2].setText(time.strftime('%H:%M:%S', time.gmtime(result['elapsed'])))
        result['kind'] = self.kind
        try:
            self.store.save_scan(result)
        except Exception as error:
            QMessageBox.warning(self, 'History write failed', str(error))
        self.scan_status.setText(result['status'])
        self.progress.setRange(0, 100)
        self.progress.setValue(0 if result['status'] == 'Cancelled' else 100)
        self.cancel.setEnabled(False)
        self.count.setText(f"{result['scanned']:,} inspected • {len(result['detections'])} detections • {result['skipped']} oversized • {len(result['errors'])} errors • {result['elapsed']}s")
        self.path_label.setText('Files remain unchanged. Review detections and scan coverage below.')
        rows = [(d['path'], '; '.join(d['reasons'])) for d in result['detections']]
        rows += [('Unreadable / omitted', e) for e in result['errors']]
        rows += [('Engine warning', w) for w in result['warnings']]
        self.fill(self.results, rows)
        self.refresh()

    def fill(self, table, rows):
        table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                table.setItem(i, j, item)


    def show_report(self, row, column):
        report = self.store.history()[row]
        box = QMessageBox(self)
        box.setWindowTitle('Scan report')
        box.setText(f"{report['started']} — {report['status']}")
        box.setDetailedText(json.dumps(report, indent=2))
        box.exec()

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export report', 'sentinelav-report.json', 'JSON (*.json)')
        if path:
            try:
                Path(path).write_text(json.dumps(self.store.history(), indent=2), encoding='utf-8')
            except OSError as error:
                QMessageBox.warning(self, 'Export failed', str(error))

    def closeEvent(self, event):
        if self.worker is not None:
            self.cancel_scan()
            QMessageBox.information(self, 'Finishing scan', 'Cancellation requested. Close the window after the scan stops.')
            event.ignore()
        else:
            self.store.db.close()
            event.accept()


from sentinelav.ui.design import DesignMixin, STYLE, icon, art
from sentinelav.ui.protection import ProtectionMixin
from sentinelav.ui.response_ui import ResponseMixin
from sentinelav.ui.finalization import FinalizationMixin
from sentinelav.ui.lab_ui import LabMixin
from sentinelav.ui.updates_ui import UpdatesMixin
from sentinelav.ui.yara_ui import YaraMixin
from sentinelav.ui.defense_ui import DefenseMixin


class Window(DefenseMixin,YaraMixin,UpdatesMixin,LabMixin,FinalizationMixin, ResponseMixin, ProtectionMixin, DesignMixin, BaseWindow):
    def __init__(self, data_dir=None):
        self.protection_worker = None
        self.monitor_state = 'Off'
        self.session_events = []
        self.closing = False
        self.tray = None
        self.response_worker = None
        self.preferences_worker = None
        self.definition_worker = None
        self.rules_worker = None
        self.inspection_worker = None
        self.lab_worker=None
        self.capability_worker=None
        self.lab_cleanup_ok=True
        super().__init__(data_dir)
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.timeout.connect(self.update_elapsed)
        self.close_timer = QTimer(self)
        self.close_timer.timeout.connect(self.close)
        self.schedule_timer=QTimer(self)
        self.schedule_timer.timeout.connect(self.check_schedule)
        self.schedule_timer.start(30000)
        QTimer.singleShot(1000,self.check_schedule)
        QTimer.singleShot(0,self.validate_yara_rules)
        if self.store.get('background_engine',False):
            QTimer.singleShot(0,self.reconnect_background)
        if self.store.get('resume_protection',False):
            QTimer.singleShot(1500,self.begin_protection)
        from PySide6.QtWidgets import QSystemTrayIcon
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(icon('shield'),self)
            self.tray.setToolTip('SentinelAV — check Real-Time Protection for monitoring mode')
            self.tray.show()

    def update_elapsed(self):
        self.live_stats[2].setText(time.strftime('%H:%M:%S', time.gmtime(time.monotonic() - self.scan_started)))

    def navigate(self, index):
        super().navigate(index)
        for i, button in enumerate(self.buttons):
            button.setIcon(icon(['home','scan','shield','box','report','settings','lab'][i], '#241a12' if i == index else '#fff0d9'))


if __name__ == '__main__':
    from sentinelav.entrypoint import main
    sys.exit(main())

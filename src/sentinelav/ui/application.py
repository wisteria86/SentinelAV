# Purpose: Compose the desktop window, feature mixins, and navigation.
# Works with: data.storage, detection.inspection, entrypoint, paths, ui.app_changes_ui
# Used by: entrypoint, ui.defense_settings, ui.defense_ui, ui.lab_ui

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


from .application_workers import ScanWorker
from .scan_actions import ScanActionsMixin
from .window_widgets import WindowWidgetsMixin

class BaseWindow(ScanActionsMixin, WindowWidgetsMixin, QMainWindow):
    def __init__(self, data_dir=None):
        super().__init__()
        self.resource_root = ROOT
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
        for i, title in enumerate(['Dashboard', 'Scan', 'Real-Time Protection', 'Quarantine', 'Reports', 'Settings','Malware Lab','App Changes']):
            button = QPushButton(title)
            button.setCheckable(True)
            button.setIcon(icon(['home','scan','shield','box','report','settings','lab','report'][i], '#fff0d9'))
            button.setIconSize(QSize(18,18))
            button.clicked.connect(lambda checked=False, index=i: self.navigate(index))
            self.buttons.append(button)
            nav.addWidget(button)
        nav.addStretch()
        footer = QLabel('Version '+__version__, objectName='small')
        footer.setContentsMargins(12,0,0,0)
        nav.addWidget(footer)
        row.addWidget(side)
        row.addWidget(self.stack, 1)
        self.dashboard()
        self.scan_page()
        self.protection_page()
        self.quarantine_page()
        self.reports_page()
        self.settings_page()
        self.lab_page()
        self.app_changes_page()
        self.refresh()
        self.navigate(0)


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


    def closeEvent(self, event):
        if self.worker is not None:
            self.cancel_scan()
            QMessageBox.information(self, 'Finishing scan', 'Cancellation requested. Close the window after the scan stops.')
            event.ignore()
        else:
            self.store.db.close()
            event.accept()


from sentinelav import __version__
from sentinelav.ui.design import DesignMixin, STYLE, icon, art
from sentinelav.ui.protection import ProtectionMixin
from sentinelav.ui.response_ui import ResponseMixin
from sentinelav.ui.finalization import FinalizationMixin
from sentinelav.ui.lab_ui import LabMixin
from sentinelav.ui.updates_ui import UpdatesMixin
from sentinelav.ui.yara_ui import YaraMixin
from sentinelav.ui.defense_ui import DefenseMixin
from sentinelav.ui.app_changes_ui import AppChangesMixin


class Window(AppChangesMixin,DefenseMixin,YaraMixin,UpdatesMixin,LabMixin,FinalizationMixin, ResponseMixin, ProtectionMixin, DesignMixin, BaseWindow):
    def __init__(self, data_dir=None, protect_by_default=False):
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
        if self.store.get('resume_protection',protect_by_default):
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
            button.setIcon(icon(['home','scan','shield','box','report','settings','lab','report'][i], '#241a12' if i == index else '#fff0d9'))


if __name__ == '__main__':
    from sentinelav.entrypoint import main
    sys.exit(main())

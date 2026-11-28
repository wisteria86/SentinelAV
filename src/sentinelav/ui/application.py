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
    """The main window's skeleton: the sidebar with its navigation buttons and the stack of pages.

    Each page is built by a method from one of the mixins (dashboard(), scan_page(), ...). The full
    Window class below adds every feature mixin on top of this.
    """
    def __init__(self, data_dir=None):
        """Open the database, build the sidebar and every page, and show the Dashboard."""
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
        nav.setContentsMargins(12, 24, 12, 18)
        nav.setSpacing(4)
        brand = QHBoxLayout()
        brand.setContentsMargins(8,0,0,0)
        brand.setSpacing(8)
        brand.addWidget(art('shield', 27, filled=True))
        brand.addWidget(QLabel('SentinelAV', objectName='brand'))
        brand.addStretch()
        nav.addLayout(brand)
        nav.addSpacing(24)
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
        footer.setContentsMargins(10,0,0,0)
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
        """Show the page at `index` and highlight its sidebar button."""
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.buttons):
            button.setChecked(i == index)

    def save_settings(self):
        """Save the size limit and exclusions from the Settings page (exclusions must be absolute
        paths).
        """
        paths = [p.strip() for p in self.exclusions.toPlainText().splitlines() if p.strip()]
        if any(not Path(p).is_absolute() for p in paths):
            QMessageBox.warning(self, 'Invalid exclusion', 'Use absolute paths for exclusions.')
            return
        self.store.set('max_mb', self.limit.value())
        self.store.set('exclusions', paths)
        QMessageBox.information(self, 'Settings saved', 'Settings apply to the next scan.')


    def closeEvent(self, event):
        """When the window closes, cancel a running scan first (the user closes again once it stops),
        otherwise shut down cleanly.
        """
        if self.worker is not None:
            self.cancel_scan()
            QMessageBox.information(self, 'Finishing scan', 'Cancellation requested. Close the window after the scan stops.')
            event.ignore()
        else:
            if hasattr(self,'stop_clamav'):self.stop_clamav()
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
from sentinelav.ui.honeypot_ui import HoneypotMixin
from sentinelav.ui.deception_ui import DeceptionMixin


class Window(DeceptionMixin,HoneypotMixin,AppChangesMixin,DefenseMixin,YaraMixin,UpdatesMixin,LabMixin,FinalizationMixin, ResponseMixin, ProtectionMixin, DesignMixin, BaseWindow):
    """The complete SentinelAV window: BaseWindow plus every feature mixin (scanning, protection,
    quarantine, lab, updates, app changes, deception and more).

    Python combines the mixins from left to right, so several of them extend the same method (for
    example settings_page) and call super() to let the others add their parts too.
    """
    def __init__(self, data_dir=None, protect_by_default=False):
        """Set up worker slots and timers, start ClamAV in the background, reconnect or resume
        protection if configured, and show the tray icon.
        """
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
        self.clamav_service=None
        QTimer.singleShot(0,self.start_clamav)
        if self.store.get('background_engine',False):
            QTimer.singleShot(0,self.reconnect_background)
        if self.store.get('resume_protection',protect_by_default):
            QTimer.singleShot(1500,self.begin_protection)
        from PySide6.QtWidgets import QSystemTrayIcon
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(icon('shield'),self)
            self.tray.setToolTip('SentinelAV — check Real-Time Protection for monitoring mode')
            self.tray.show()

    def start_clamav(self):
        """Loading ClamAV signatures takes seconds, so it happens off the interface thread."""
        import threading
        from sentinelav.detection.clamav_engine import ensure_service
        enabled=self.store.get('inspection_options',{}).get('clamav',True)
        def run():
            """Start ClamAV and remember the service (or the problem) for later."""
            self.clamav_service,self.clamav_problem=ensure_service(enabled)
        threading.Thread(target=run,daemon=True,name='clamd-start').start()

    def stop_clamav(self):
        """Stop the ClamAV service started by this window, if any."""
        if getattr(self,'clamav_service',None):self.clamav_service.stop()

    def update_elapsed(self):
        """Refresh the elapsed-time counter shown during a scan."""
        self.live_stats[2].setText(time.strftime('%H:%M:%S', time.gmtime(time.monotonic() - self.scan_started)))

    def navigate(self, index):
        """Switch page and recolour the sidebar icons so the selected one stands out."""
        super().navigate(index)
        for i, button in enumerate(self.buttons):
            button.setIcon(icon(['home','scan','shield','box','report','settings','lab','report'][i], '#241a12' if i == index else '#fff0d9'))


if __name__ == '__main__':
    from sentinelav.entrypoint import main
    sys.exit(main())

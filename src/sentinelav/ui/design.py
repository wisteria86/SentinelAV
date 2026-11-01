"""Reference-inspired desktop components; all icons are resolution-independent SVGs."""
from sentinelav.paths import RESOURCE_ROOT
from PySide6.QtCore import Qt, QSize, QByteArray, QRectF
from pathlib import Path
import json
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QWidget, QLabel, QFrame, QPushButton, QHBoxLayout,
    QVBoxLayout, QTabWidget, QProgressBar, QSpinBox, QPlainTextEdit, QComboBox,
    QSizePolicy, QScrollArea, QListView)


class InactiveSwitch(QWidget):
    """Draw the unavailable switch without relying on a font glyph."""
    def __init__(self):
        super().__init__()
        self.active = False
        self.setFixedSize(39, 22)
        self.setToolTip('Not available in this prototype')
        self.setAccessibleName('Protection off; feature not available')

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QColor('#d6c3ab'))
        painter.setBrush(QColor('#ee8129' if self.active else '#e9ddcc'))
        painter.drawRoundedRect(QRectF(1, 1, 37, 20), 10, 10)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor('#fffaf2'))
        painter.drawEllipse(QRectF(20 if self.active else 3, 3, 16, 16))


class PathLabel(QLabel):
    """Keep long paths from changing the size of the scan card."""
    def __init__(self, text='', **kwargs):
        super().__init__('', **kwargs)
        self.full_text = text
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(22)
        self.setText(text)

    def setText(self, text):
        self.full_text = text
        self.setToolTip(text)
        super().setText(self.fontMetrics().elidedText(text, Qt.TextElideMode.ElideMiddle, max(0, self.width())))

    def resizeEvent(self, event):
        self.setText(self.full_text)
        super().resizeEvent(event)


def configure_app(app):
    from PySide6.QtGui import QFontDatabase
    app.setStyle('Fusion')
    for name in ['segoeui.ttf', 'segoeuib.ttf', 'seguisb.ttf']:
        QFontDatabase.addApplicationFont('C:/Windows/Fonts/' + name)
    app.setStyleSheet(STYLE)

PATHS = {
 'lab': '<path d="M9 2h6M10 2v7L4 19q-1 3 2 3h12q3 0 2-3L14 9V2M7 15h10"/>',
 'shield': '<path d="M12 2 21 6v6c0 6-9 10-9 10S3 18 3 12V6Z"/><path d="m8 12 3 3 5-6"/>',
 'home': '<path d="m3 11 9-8 9 8M5 10v11h5v-7h4v7h5V10"/>',
 'scan': '<circle cx="10" cy="10" r="7"/><path d="m15 15 7 7"/>',
 'box': '<rect x="3" y="7" width="18" height="14" rx="2"/><path d="M2 3h20v4H2zM10 12h4"/>',
 'report': '<path d="M5 2h10l4 4v16H5zM14 2v6h5M8 12h8M8 16h8"/>',
 'settings': '<path d="m9 3 1-2h4l1 2 3 2 3 1v4l-2 2v3l1 3-3 3-3-1h-3l-2 2-4-2v-3l-2-3-2-1V9l3-1 2-3z"/><circle cx="12" cy="12" r="3"/>',
 'bars': '<path d="M4 21V13M9 21V7M14 21V2M19 21V10"/>',
 'folder': '<path d="M2 6h8l2 3h10v12H2zM2 6V3h8l2 3h9v3"/>',
 'play': '<path d="m8 3 13 9L8 21Z"/>',
 'network': '<circle cx="12" cy="12" r="10"/><ellipse cx="12" cy="12" rx="4" ry="10"/><path d="M2 12h20M4 6h16M4 18h16"/>',
 'lock': '<rect x="5" y="10" width="14" height="12" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4M12 15v3"/>',
}

def pixmap(name, color='#ed7b23', size=24, filled=False):
    body = PATHS.get(name, PATHS['shield'])
    if filled and name == 'shield':
        body = '<path fill="'+color+'" stroke="'+color+'" d="M12 2 21 6v6c0 6-9 10-9 10S3 18 3 12V6Z"/><path stroke="white" d="m8 12 3 3 5-6"/>'
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    result = QPixmap(size*2, size*2)
    result.fill(Qt.GlobalColor.transparent)
    painter = QPainter(result)
    QSvgRenderer(QByteArray(svg.encode())).render(painter)
    painter.end()
    result.setDevicePixelRatio(2)
    return result

def icon(name, color='#ed7b23'):
    return QIcon(pixmap(name, color))

def art(name, size=24, color='#ed7b23', filled=False):
    label = QLabel()
    label.setPixmap(pixmap(name, color, size, filled))
    label.setFixedSize(size, size)
    label.setStyleSheet('background:transparent;border:0;')
    return label

STYLE = '''
QWidget {font-family:'Segoe UI';font-size:13px;color:#241a12;background:#fff6e8;}
QMainWindow {background:#fff6e8;}
QLabel {background:transparent;border:0;}
QFrame#sidebar {background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #342315,stop:1 #22180f);border-right:1px solid #493322;}
QFrame#sidebar QLabel {color:#fff2df;}
QFrame#sidebar QPushButton {background:transparent;color:#fff2df;text-align:left;border:0;padding:10px 12px;font-size:12px;border-radius:6px;}
QFrame#sidebar QPushButton:hover {background:#473020;}
QFrame#sidebar QPushButton:checked {background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #f69539,stop:1 #ed7c23);color:#21170e;}
QLabel#brand {font-size:19px;font-weight:700;}
QLabel#title {font-size:26px;font-weight:700;}
QLabel#statusTitle {font-size:23px;font-weight:700;}
QLabel#muted {color:#6f665d;font-size:12px;}
QLabel#small {color:#6f665d;font-size:11px;}
QLabel#value {font-size:17px;font-weight:600;}
QFrame#card {border:1px solid #e7dac8;border-radius:8px;background:#fff8ed;}
QFrame#badge {border:0;border-radius:7px;background:#fbedda;}
QPushButton {background:#fff1df;border:1px solid #edbc90;padding:9px 18px;border-radius:5px;}
QPushButton:hover {background:#ffe4c7;}
QPushButton#primary {background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #ef8a32,stop:1 #ed7921);border:1px solid #e97c26;color:white;font-weight:600;}
QPushButton:disabled {background:#f0e7da;color:#a2978b;border-color:#e5d9c8;}
QPushButton#primary:disabled {background:#f0e7da;color:#a2978b;border-color:#e5d9c8;}
QPushButton#tab {background:transparent;border:0;border-bottom:2px solid transparent;border-radius:0;padding:10px 20px;}
QPushButton#tab:checked {color:#df6815;border-bottom:2px solid #f17c25;font-weight:600;}
QProgressBar {border:0;border-radius:7px;background:#f0e5d5;height:14px;color:#6b5946;text-align:center;}
QProgressBar::chunk {background:#ed812b;border-radius:7px;}
QTableWidget {background:#fff8ed;alternate-background-color:#fcf2e3;border:1px solid #e6d9c7;border-radius:6px;gridline-color:#eee2d1;font-size:12px;selection-background-color:#ffe2be;selection-color:#251b11;}
QHeaderView::section {background:#f5ead9;border:0;border-bottom:1px solid #e6d9c7;padding:8px;font-size:11px;}
QTabWidget::pane {border:1px solid #e7dac8;border-radius:6px;background:#fff8ed;}
QTabBar::tab {background:transparent;padding:10px 16px;border-bottom:2px solid transparent;font-size:12px;}
QTabBar::tab:selected {color:#df6815;border-bottom:2px solid #f17c25;}
QPlainTextEdit,QSpinBox,QComboBox,QLineEdit,QTimeEdit {background:#fff8ed;border:1px solid #e5cfb6;border-radius:5px;padding:7px;}
QComboBox {color:#291e15;min-height:22px;padding:5px 30px 5px 10px;}
QComboBox::drop-down {width:25px;border:0;border-left:1px solid #e5cfb6;background:#f9ecd9;border-top-right-radius:5px;border-bottom-right-radius:5px;}
QComboBox QAbstractItemView {background:#fff8ed;color:#291e15;selection-background-color:#f18a32;selection-color:#21180f;border:1px solid #ddc5a7;outline:0;padding:4px;}
QComboBox QAbstractItemView::item {min-height:30px;padding:4px 10px;color:#291e15;}
QScrollArea {border:0;background:#fff6e8;}
QScrollBar:vertical {width:8px;background:#fff6e8;margin:0;}
QScrollBar::handle:vertical {background:#dac7af;border-radius:4px;min-height:30px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {height:0;}
QFrame#separator {background:#ebdfce;max-height:1px;border:0;}
QToolTip {background:#2e2117;color:#fff5e6;border:1px solid #6c4b2e;padding:6px;}
'''
STYLE += 'QComboBox::down-arrow {image:url("' + (RESOURCE_ROOT/'assets/chevron.svg').as_posix() + '");width:10px;height:6px;}'

class DesignMixin:
    def page(self, title, subtitle):
        page = QWidget()
        page.setMaximumWidth(930)
        page.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 23, 24, 22)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        header_widget = QWidget()
        header_widget.setFixedHeight(54)
        header = QVBoxLayout(header_widget)
        header.setContentsMargins(0,0,0,0)
        header.setSpacing(3)
        header.addWidget(QLabel(title, objectName='title'))
        label = QLabel(subtitle, objectName='muted')
        label.setWordWrap(True)
        header.addWidget(label)
        layout.addWidget(header_widget)
        layout.addSpacing(6)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(page)
        self.stack.addWidget(scroll)
        return layout

    def dashboard(self):
        layout = self.page('Dashboard', 'Your system security at a glance')
        frame = QFrame(objectName='card')
        frame.setMaximumHeight(145)
        row = QHBoxLayout(frame)
        row.setContentsMargins(18, 18, 18, 18)
        row.setSpacing(18)
        halo = QFrame(objectName='badge')
        halo.setFixedSize(96, 96)
        hl = QVBoxLayout(halo)
        hl.addWidget(art('shield', 78, filled=True), alignment=Qt.AlignmentFlag.AlignCenter)
        row.addWidget(halo)
        copy = QVBoxLayout()
        copy.setSpacing(6)
        copy.addStretch()
        self.dashboard_title = QLabel('Ready to scan', objectName='statusTitle')
        copy.addWidget(self.dashboard_title)
        text = QLabel('On-demand scanning is available.\nRun a scan to check your files.', objectName='muted')
        text.setWordWrap(True)
        self.dashboard_description = text
        copy.addWidget(text)
        copy.addStretch()
        row.addLayout(copy, 1)
        badge = QFrame(objectName='badge')
        bl = QVBoxLayout(badge)
        badge.setFixedHeight(78)
        bl.setSpacing(8)
        bl.addWidget(QLabel('Real-time protection', objectName='small'))
        off = QHBoxLayout()
        self.dashboard_badge_label = QLabel('OFF', objectName='small')
        off.addWidget(self.dashboard_badge_label)
        self.dashboard_switch = self.toggle()
        off.addWidget(self.dashboard_switch)
        bl.addLayout(off)
        row.addWidget(badge)
        layout.addWidget(frame)
        metrics = QHBoxLayout()
        metrics.setSpacing(12)
        self.metric_values = []
        self.metric_notes = []
        for symbol, title in [('scan','Last Scan'),('report','Files Scanned'),('shield','Threats Found'),('bars','System Status')]:
            box = QFrame(objectName='card')
            box.setMinimumHeight(135)
            box.setMaximumHeight(145)
            box.setMinimumWidth(0)
            col = QVBoxLayout(box)
            col.setContentsMargins(16,16,12,16)
            col.addWidget(art(symbol, 25))
            col.addSpacing(5)
            col.addWidget(QLabel(title))
            value = QLabel('—', objectName='value')
            note = QLabel('', objectName='small')
            value.setWordWrap(True)
            note.setWordWrap(True)
            col.addWidget(value)
            col.addWidget(note)
            self.metric_values.append(value)
            self.metric_notes.append(note)
            metrics.addWidget(box, 1)
        layout.addLayout(metrics)
        actions = QHBoxLayout()
        quick = self.action(actions, 'Quick Scan', self.quick_scan, True)
        quick.setIcon(icon('play', '#ffffff'))
        custom = self.action(actions, 'Custom Scan', self.choose_folder)
        custom.setIcon(icon('folder', '#a95519'))
        layout.addLayout(actions)
        quick.setMinimumHeight(42)
        custom.setMinimumHeight(42)
        self.latest = QLabel(objectName='small')
        self.latest.setWordWrap(True)
        layout.addWidget(self.latest)
        layout.addStretch()

    def toggle(self):
        return InactiveSwitch()

    def scan_page(self):
        layout = self.page('Scan', 'Scan your files and folders for malware.')
        tabs = QHBoxLayout()
        tabs.setSpacing(0)
        self.scan_tabs = []
        for i, name in enumerate(['Quick Scan','Full Scan','Custom Scan']):
            b = QPushButton(name, objectName='tab')
            b.setCheckable(True)
            b.setChecked(i == 0)
            b.clicked.connect(lambda checked=False, index=i: self.select_scan_tab(index))
            tabs.addWidget(b)
            self.scan_tabs.append(b)
        tabs.addStretch()
        layout.addLayout(tabs)
        card = self.card(layout)
        card.setSpacing(10)
        head = QHBoxLayout()
        head.addWidget(art('scan', 58))
        head.addSpacing(14)
        text = QVBoxLayout()
        text.setSpacing(4)
        text.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self.scan_status = QLabel('Ready to scan', objectName='value')
        self.path_label = PathLabel('Check Downloads and temporary files.', objectName='small')
        text.addWidget(self.scan_status)
        text.addWidget(self.path_label)
        head.addLayout(text, 1)
        card.addLayout(head)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setValue(0)
        self.progress.setFixedHeight(14)
        card.addWidget(self.progress)
        stats = QHBoxLayout()
        self.live_stats = []
        for name in ['Files scanned', 'Threats found', 'Time elapsed']:
            col = QVBoxLayout()
            col.addWidget(QLabel(name, objectName='small'))
            val = QLabel('00:00:00' if name == 'Time elapsed' else '0', objectName='value')
            col.addWidget(val)
            self.live_stats.append(val)
            stats.addLayout(col, 1)
        self.live_stats[1].setStyleSheet('color:#d4422c;')
        self.cancel = self.action(stats, 'Cancel', self.cancel_scan)
        self.cancel.setEnabled(False)
        card.addLayout(stats)
        self.count = QLabel('Files are inspected without changing them.', objectName='small')
        card.addWidget(self.count)
        controls = QHBoxLayout()
        self.scan_start = self.action(controls, 'Start Quick Scan', self.run_selected_scan, True)
        self.select_files_button = self.action(controls, 'Select Files…', self.choose_files)
        layout.addLayout(controls)
        self.results = self.table(['File', 'Detection / error'])
        self.results.setFixedHeight(132)
        layout.addWidget(self.results, 1)
        layout.addStretch()
        self.selected_scan = 0

    def select_scan_tab(self, index):
        self.selected_scan = index
        for i, button in enumerate(self.scan_tabs):
            button.setChecked(i == index)
        self.scan_start.setText(['Start Quick Scan','Choose Drive…','Choose Folder…'][index])
        if self.worker is None:
            self.path_label.setText(['Check Downloads and temporary files.','Choose a drive or its root folder to scan.','Choose any folder or select individual files.'][index])

    def run_selected_scan(self):
        if self.selected_scan == 0:
            self.quick_scan()
        else:
            self.choose_folder()

    def future_page(self, title, subtitle, body):
        if title == 'Quarantine':
            layout = self.page(title, 'Manage files that have been detected and isolated.')
            table = self.table(['Name','Threat Type','Date Quarantined','Action'])
            table.setMinimumHeight(230)
            table.setMaximumHeight(300)
            layout.addWidget(table)
            bottom = QHBoxLayout()
            bottom.addStretch()
            b = self.action(bottom, 'Delete Selected', lambda: None)
            b.setEnabled(False)
            layout.addLayout(bottom)
            label = QLabel('No files quarantined. Isolation and restore controls are planned for Phase 5.', objectName='muted')
            label.setWordWrap(True)
            layout.addWidget(label)
        else:
            layout = self.page(title, 'Monitor your system for suspicious activity in real time.')
            card = self.card(layout)
            card.setSpacing(10)
            row = QHBoxLayout()
            row.addWidget(art('shield', 46, '#a88c68', True))
            copy = QVBoxLayout()
            copy.setSpacing(4)
            copy.addWidget(QLabel('Real-time protection is inactive', objectName='value'))
            copy.addWidget(QLabel('Monitoring will be available in a later phase.', objectName='small'))
            row.addLayout(copy, 1)
            row.addWidget(QLabel('OFF', objectName='small'))
            row.addWidget(self.toggle())
            card.addLayout(row)
            for symbol, name, description in [('report','File System Monitoring','Monitors file changes and new files.'),('settings','Process Monitoring','Monitors running processes for suspicious behavior.'),('network','Network Monitoring','Checks for suspicious network connections.'),('lock','Ransomware Protection','Detects unusual file modifications and ransomware behavior.')]:
                self.setting_row(card, symbol, name, description)
        layout.addStretch()

    def setting_row(self, layout, symbol, title, description):
        separator = QFrame(objectName='separator')
        separator.setFixedHeight(1)
        layout.addWidget(separator)
        row = QHBoxLayout()
        row.setContentsMargins(0, 5, 0, 5)
        row.addWidget(art(symbol, 25))
        row.addSpacing(13)
        copy = QVBoxLayout()
        copy.setSpacing(3)
        copy.addWidget(QLabel(title))
        label = QLabel(description, objectName='small')
        label.setWordWrap(True)
        copy.addWidget(label)
        row.addLayout(copy, 1)
        row.addWidget(QLabel('OFF', objectName='small'))
        row.addWidget(self.toggle())
        layout.addLayout(row)

    def reports_page(self):
        layout = self.page('Reports', 'View your scan history, detected threats, and system activity.')
        row = QHBoxLayout()
        self.report_tabs = []
        for i, title in enumerate(['Scan History','Threats','Protection Events']):
            b = QPushButton(title, objectName='tab')
            b.setCheckable(True)
            b.setChecked(i == 0)
            b.clicked.connect(lambda checked=False, index=i: self.change_report(index))
            row.addWidget(b)
            self.report_tabs.append(b)
        row.addStretch()
        b = self.action(row, 'Export Report', self.export)
        b.setIcon(icon('report'))
        layout.addLayout(row)
        self.history_table = self.table(['Date','Scan Type','Files Scanned','Threats Found','Result'])
        self.history_table.setMinimumHeight(220)
        self.history_table.setMaximumHeight(360)
        layout.addWidget(self.history_table, 1)
        self.history_table.cellDoubleClicked.connect(self.open_history)
        layout.addWidget(QLabel('Double-click a scan to view its full report.', objectName='small'))
        layout.addStretch()
        self.report_mode = 0

    def open_history(self, row, column):
        if self.report_mode == 0:
            self.show_report(row, column)

    def change_report(self, index):
        self.report_mode = index
        for i, b in enumerate(self.report_tabs):
            b.setChecked(i == index)
        self.refresh()

    def settings_page(self):
        layout = self.page('Settings', 'Configure SentinelAV to suit your needs.')
        tabs = QTabWidget()
        tabs.setFixedHeight(330)
        tabs.setUsesScrollButtons(True)
        general = QWidget()
        gl = QVBoxLayout(general)
        gl.setContentsMargins(18,14,18,14)
        gl.addWidget(QLabel('Startup and daily scan controls are under Scheduling.',objectName='small'))
        for symbol, title, description in [('shield','Automatically check for updates','Signature updates are not connected yet.'),('lock','Use cloud-based threat intelligence','Cloud analysis is not available. Scans run locally.')]:
            self.setting_row(gl, symbol, title, description)
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel('Theme'))
        theme_row.addStretch()
        theme = QComboBox()
        theme.setView(QListView())
        theme.setMinimumWidth(115)
        theme.setFixedHeight(35)
        theme.addItem('Light')
        theme_row.addWidget(theme)
        gl.addLayout(theme_row)
        gl.addStretch()
        tabs.addTab(general, 'General')
        scanning = QWidget()
        sl = QVBoxLayout(scanning)
        sl.setContentsMargins(18,18,18,18)
        sl.addWidget(QLabel('Maximum file size (MB)'))
        self.limit = QSpinBox()
        self.limit.setRange(1,1024)
        self.limit.setValue(self.store.get('max_mb',100))
        sl.addWidget(self.limit)
        self.limit.setMaximumWidth(160)
        sl.addWidget(QLabel('Larger files are skipped and reported.', objectName='small'))
        feed_label=QLabel(objectName='small')
        feed_label.setWordWrap(True)
        try:
            feed_path=RESOURCE_ROOT/'signature-data'/'active.json'
            if feed_path.exists():
                if feed_path.stat().st_size>16384: raise ValueError('Manifest exceeds size limit')
                feed=json.loads(feed_path.read_text(encoding='utf-8'))
                feed_label.setText(f"Full hash feed: {feed['unique_sha256']:,} SHA-256 records\nImported: {feed['imported_utc'][:19]} UTC · Local lookups; no automatic updates.")
            else:
                feed_label.setText('Local JSON hash signatures. No full SQLite feed is installed.')
        except (OSError,ValueError,KeyError,TypeError):
            feed_label.setText('Hash feed metadata unavailable. Scan initialization will verify the database.')
        sl.addWidget(feed_label)
        sl.addStretch()
        tabs.addTab(scanning, 'Scanning')
        for title, text in [('Protection','Choose watched folders and monitoring sources on Real-Time Protection. Optional background mode continues after window close within the current Windows session.'),('Notifications','Detections appear in the live alert list, status bar, and Windows tray notifications when available. Windows notification settings may suppress popups.')]:
            page = QWidget()
            pl = QVBoxLayout(page)
            label = QLabel(text, objectName='muted')
            label.setWordWrap(True)
            pl.addWidget(label)
            pl.addStretch()
            tabs.addTab(page,title)
        excluded = QWidget()
        el = QVBoxLayout(excluded)
        el.setContentsMargins(18,18,18,18)
        el.addWidget(QLabel('Excluded absolute paths — one file or folder per line'))
        self.exclusions = QPlainTextEdit('\n'.join(self.store.get('exclusions',[])))
        el.addWidget(self.exclusions)
        tabs.addTab(excluded,'Exclusions')
        layout.addWidget(tabs,1)
        bottom = QHBoxLayout()
        bottom.addStretch()
        self.action(bottom,'Save Settings',self.save_settings,True)
        layout.addLayout(bottom)
        layout.addStretch()

    def refresh(self):
        history = self.store.history()
        values = ['Never' if not history else history[0]['started'][5:16],
                  f"{sum(s['scanned'] for s in history):,}",
                  str(sum(len(s['detections']) for s in history)), 'On-demand']
        notes = ['No scans yet' if not history else history[0]['status'], 'Across all scans', 'Recorded detections', 'Monitoring off']
        for label, value, note, description in zip(self.metric_values,values,self.metric_notes,notes):
            label.setText(value)
            note.setText(description)
        self.latest.setText('Scan results cover inspected files only. Real-time protection is not active.')
        if self.report_mode == 0:
            headings = ['Date','Scan Type','Files Scanned','Threats Found','Result']
            rows = [(s['started'],s.get('kind',''),s['scanned'],len(s['detections']),s['status']) for s in history]
        elif self.report_mode == 1:
            headings = ['Date','File','Detection','SHA-256','Action']
            rows = [(s['started'],d['path'],'; '.join(d['reasons']),d['sha256'],'Reported') for s in history for d in s['detections']]
        else:
            headings = ['Date','Event','Details','Source','Status']
            rows = []
        self.history_table.setHorizontalHeaderLabels(headings)
        self.fill(self.history_table,rows)

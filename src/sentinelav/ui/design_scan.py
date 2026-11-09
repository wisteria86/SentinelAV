# Purpose: Build scan tabs and dispatch the selected scan mode.
# Works with: ui.design_components
# Used by: ui.design

"""Reference-inspired desktop components; all icons are resolution-independent SVGs."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QPushButton, QHBoxLayout, QVBoxLayout, QProgressBar
from .design_components import PathLabel, art


class ScanPageMixin:
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
        elif self.selected_scan == 1:
            self.full_scan()
        else:
            self.choose_folder()

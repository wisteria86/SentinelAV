# Purpose: Display scan-history reports and change the selected report.
# Works with: ui.design_components
# Used by: ui.design

"""Reference-inspired desktop components; all icons are resolution-independent SVGs."""
from PySide6.QtWidgets import QLabel, QPushButton, QHBoxLayout
from .design_components import icon


class ReportsPageMixin:
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

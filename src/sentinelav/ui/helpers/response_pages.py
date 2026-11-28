# Purpose: Build quarantine views and select detections or recovery records.
# Works with: response.response, ui.application
# Used by: ui.core.response_ui

"""Explicit response actions; no automatic quarantine or process termination."""

from pathlib import Path
from PySide6.QtWidgets import (
    QLabel,
    QTabWidget,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QListWidget,
    QTableWidget,
    QPushButton,
    QMenu,
)
from sentinelav.response.response import ResponseService


class ResponsePagesMixin:
    """Builds the Quarantine page and the Trusted Files settings tab."""

    def quarantine_page(self):
        """Build the Quarantine page with its Detected Files and Isolated Files tabs and their action
        buttons.
        """
        layout = self.page(
            'Quarantine', 'Review flagged files and manage encrypted, isolated files.'
        )
        self.response_status = QLabel(
            'Select a file to act on it. Only high-confidence detections in watched folders are quarantined automatically.',
            objectName='small',
        )
        self.response_status.setWordWrap(True)
        layout.addWidget(self.response_status)
        tabs = QTabWidget()
        pending = QWidget()
        pl = QVBoxLayout(pending)
        self.pending_table = self.table(['File', 'Verdict', 'Score', 'Why', 'SHA-256'])
        self.pending_table.cellDoubleClicked.connect(
            lambda row, column: self.show_finding(self.pending_detections[row])
        )
        self.pending_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.pending_table.setMinimumHeight(140)
        self.fit_columns(self.pending_table, 0, 3)
        pl.addWidget(self.pending_table)
        row = QHBoxLayout()
        self.quarantine_button = self.action(
            row, 'Quarantine Selected', self.quarantine_selected, True
        )
        self.action(row, 'Remove Permanently', self.remove_selected)
        self.action(row, 'Trust Exact File', self.trust_selected)
        pl.addLayout(row)
        row = QHBoxLayout()
        self.action(row, 'Exclude File Path', self.exclude_selected)
        process_button = QPushButton('Process Actions…')
        process_menu = QMenu(process_button)
        process_menu.addAction('Terminate Matching Process…', self.terminate_selected)
        process_menu.addAction('Review Process Tree…', self.review_process_tree)
        process_button.setMenu(process_menu)
        row.addWidget(process_button)
        pl.addLayout(row)
        tabs.addTab(pending, 'Detected Files')
        isolated = QWidget()
        il = QVBoxLayout(isolated)
        self.quarantine_table = self.table(['Name', 'Threat', 'Date', 'State'])
        self.quarantine_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        il.addWidget(self.quarantine_table)
        actions = QHBoxLayout()
        self.action(actions, 'Restore…', lambda: self.restore_selected(False))
        self.action(actions, 'Restore and Trust…', lambda: self.restore_selected(True))
        self.action(actions, 'Permanently Delete', self.delete_selected)
        il.addLayout(actions)
        self.action(il, 'Recover Interrupted Action', self.recover_selected)
        tabs.addTab(isolated, 'Isolated Files')
        tabs.setFixedHeight(330)
        layout.addWidget(tabs)
        label = QLabel(
            'Quarantine is encrypted for your Windows account. Restore never overwrites a file.\nAll actions appear under Reports → Protection Events.',
            objectName='small',
        )
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addStretch()

    def settings_page(self):
        """Add the Trusted Files tab listing trusted hashes."""
        super().settings_page()
        tabs = self.stack.widget(5).findChild(QTabWidget)
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel(
            'Trusting an exact SHA-256 stops file detections for that content. It does not suppress behavior warnings. Remove trust to scan that content normally again.',
            objectName='small',
        )
        label.setWordWrap(True)
        layout.addWidget(label)
        self.trusted_list = QListWidget()
        self.trusted_list.addItems(self.store.get('trusted_hashes', []))
        layout.addWidget(self.trusted_list)
        self.action(layout, 'Remove Selected Trust', self.remove_trust)
        tabs.addTab(page, 'Trusted Files')

    def refresh(self):
        """Rebuild the list of detected files still needing action (not quarantined, not trusted, still
        present) and the quarantine table.
        """
        super().refresh()
        if not hasattr(self, 'pending_table'):
            return
        trusted = set(self.store.get('trusted_hashes', []))
        records = self.store.quarantine()
        isolated = {
            (r['original'], r['sha256'])
            for r in records
            if r['state'] in ('Preparing', 'Quarantined', 'Delete pending', 'Restore pending')
        }
        items = {}
        for scan in reversed(self.store.history()):
            for detection in scan['detections'] + scan.get('suspicious', []):
                items[(detection['path'], detection['sha256'])] = detection
        for event in reversed(self.store.events(5000)):
            if event['kind'] in ('Threat detected', 'Suspicious file') and event.get('sha256'):
                items[(event['path'], event['sha256'])] = {
                    key: value
                    for key, value in event.items()
                    if key not in ('time', 'kind', 'details', 'source', 'level')
                }
        self.pending_detections = [
            d
            for key, d in items.items()
            if key not in isolated and d['sha256'] not in trusted and Path(d['path']).is_file()
        ]
        self.pending_detections.sort(key=lambda d: -d.get('score', 100))
        self.fill(
            self.pending_table,
            [
                (
                    d['path'],
                    d.get('verdict', 'Malicious'),
                    d.get('score', ''),
                    '; '.join(d['reasons']),
                    d['sha256'],
                )
                for d in self.pending_detections
            ],
        )
        self.quarantine_records = records
        self.fill(
            self.quarantine_table,
            [
                (Path(r['original']).name, '; '.join(r['reasons']), r['date'], r['state'])
                for r in records
            ],
        )

    def selected_detection(self):
        """Return the selected detected file, or None with a hint."""
        row = self.pending_table.currentRow()
        if row < 0:
            self.response_status.setText('Select a detected file first.')
            return None
        return self.pending_detections[row]

    def selected_quarantine(self):
        """Return the selected quarantine record if it can still be acted on, or None with a hint."""
        row = self.quarantine_table.currentRow()
        if row < 0:
            self.response_status.setText('Select an isolated file first.')
            return None
        record = self.quarantine_records[row]
        if record['state'] not in ('Preparing', 'Quarantined', 'Restore pending', 'Delete pending'):
            self.response_status.setText('This item has already been restored or deleted.')
            return None
        return record

    def confirm(self, title, text):
        """Ask a Yes/No question (No is the default) and return True for Yes."""
        return (
            QMessageBox.question(
                self,
                title,
                text,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            == QMessageBox.StandardButton.Yes
        )

    def audit_response(self, kind, details):
        """Record a response action in the activity log."""
        from sentinelav.ui.application import ROOT

        ResponseService(self.store, ROOT).audit(kind, details)

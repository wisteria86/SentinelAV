# Purpose: Render dashboard controls and refresh their displayed status.
# Works with: ui.design_components
# Used by: ui.design

"""Reference-inspired desktop components; all icons are resolution-independent SVGs."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QFrame, QHBoxLayout, QVBoxLayout
from .design_components import icon, art


class DashboardMixin:
    """Builds the Dashboard page and keeps its numbers and the reports table up to date."""

    def dashboard(self):
        """Build the Dashboard: status card, four metric cards, and the Quick/Custom scan buttons."""
        layout = self.page('Dashboard', 'Your system security at a glance')
        frame = QFrame(objectName='card')
        frame.setMaximumHeight(150)
        row = QHBoxLayout(frame)
        row.setContentsMargins(22, 20, 22, 20)
        row.setSpacing(20)
        halo = QFrame(objectName='badge')
        halo.setFixedSize(96, 96)
        halo.setStyleSheet('QFrame#badge {border-radius:48px;}')
        hl = QVBoxLayout(halo)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(art('shield', 62, filled=True), alignment=Qt.AlignmentFlag.AlignCenter)
        row.addWidget(halo)
        copy = QVBoxLayout()
        copy.setSpacing(6)
        copy.addStretch()
        self.dashboard_title = QLabel('Ready to scan', objectName='statusTitle')
        copy.addWidget(self.dashboard_title)
        text = QLabel(
            'On-demand scanning is available.\nRun a scan to check your files.', objectName='muted'
        )
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
        for symbol, title in [
            ('scan', 'Last Scan'),
            ('report', 'Files Scanned'),
            ('shield', 'Threats Found'),
            ('bars', 'System Status'),
        ]:
            box = QFrame(objectName='card')
            box.setMinimumHeight(150)
            box.setMaximumHeight(160)
            box.setMinimumWidth(0)
            col = QVBoxLayout(box)
            col.setContentsMargins(18, 18, 14, 16)
            col.setSpacing(2)
            chip = QFrame(objectName='chip')
            chip.setFixedSize(38, 38)
            chip_layout = QVBoxLayout(chip)
            chip_layout.setContentsMargins(0, 0, 0, 0)
            chip_layout.addWidget(art(symbol, 20), alignment=Qt.AlignmentFlag.AlignCenter)
            col.addWidget(chip)
            col.addSpacing(6)
            col.addWidget(QLabel(title, objectName='muted'))
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

    def refresh(self):
        """Update the dashboard metrics and refill the Reports table for the selected report tab."""
        history = self.store.history()
        values = [
            'Never' if not history else history[0]['started'][5:16],
            f"{sum(s['scanned'] for s in history):,}",
            str(sum(len(s['detections']) for s in history)),
            'On-demand',
        ]
        notes = [
            'No scans yet' if not history else history[0]['status'],
            'Across all scans',
            'Recorded detections',
            'Monitoring off',
        ]
        for label, value, note, description in zip(
            self.metric_values, values, self.metric_notes, notes
        ):
            label.setText(value)
            note.setText(description)
        self.latest.setText(
            'Scan results cover inspected files only. Real-time protection is not active.'
        )
        if self.report_mode == 0:
            headings = ['Date', 'Scan Type', 'Files Scanned', 'Malicious / Suspicious', 'Result']
            rows = [
                (
                    s['started'],
                    s.get('kind', ''),
                    s['scanned'],
                    f"{len(s['detections'])} / {len(s.get('suspicious',[]))}",
                    s['status'],
                )
                for s in history
            ]
        elif self.report_mode == 1:
            headings = ['Date', 'File', 'Detection', 'SHA-256', 'Action']
            rows = [
                (
                    s['started'],
                    d['path'],
                    '; '.join(d['reasons']),
                    d['sha256'],
                    d.get('verdict', 'Malicious') + ' ' + str(d.get('score', '')),
                )
                for s in history
                for d in s['detections'] + s.get('suspicious', [])
            ]
        else:
            headings = ['Date', 'Event', 'Details', 'Source', 'Status']
            rows = []
        self.history_table.setHorizontalHeaderLabels(headings)
        self.fill(self.history_table, rows)

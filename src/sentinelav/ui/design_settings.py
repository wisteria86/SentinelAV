# Purpose: Build the base application preferences page.
# Works with: paths
# Used by: ui.design

"""Reference-inspired desktop components; all icons are resolution-independent SVGs."""
from sentinelav.paths import RESOURCE_ROOT
import json
from PySide6.QtWidgets import QWidget, QLabel, QHBoxLayout, QVBoxLayout, QTabWidget, QSpinBox, QPlainTextEdit, QComboBox, QListView


class SettingsPageMixin:
    def settings_page(self):
        layout = self.page('Settings', 'Configure SentinelAV to suit your needs.')
        tabs = QTabWidget()
        tabs.setFixedHeight(330)
        tabs.setUsesScrollButtons(True)
        general = QWidget()
        gl = QVBoxLayout(general)
        gl.setContentsMargins(18,14,18,14)
        for title, description in [('Scheduling','Windows sign-in startup and daily scans'),
                                   ('Definitions','Import, verify, and roll back detection updates'),
                                   ('Defense','Inspection layers and automatic quarantine policy')]:
            row=QHBoxLayout()
            label=QLabel(description,objectName='small'); label.setWordWrap(True)
            row.addWidget(label,1)
            self.action(row,'Open '+title,lambda checked=False,name=title:self.open_settings_tab(name))
            gl.addLayout(row)
        local=QLabel('Files are inspected locally. Signed feed downloads are configured under Defense → Analysis Data.',objectName='small')
        local.setWordWrap(True); gl.addWidget(local)
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
            from sentinelav.detection.definition_paths import signature_data_dir
            feed_path=signature_data_dir(RESOURCE_ROOT)/'active.json'
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

    def open_settings_tab(self, name):
        tabs=self.stack.widget(5).findChild(QTabWidget)
        for index in range(tabs.count()):
            if tabs.tabText(index)==name:
                tabs.setCurrentIndex(index)
                return

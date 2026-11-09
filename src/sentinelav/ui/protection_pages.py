# Purpose: Build protection settings, watched folders, and canary controls.
# Works with: monitoring.behavior
# Used by: ui.protection

"""Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread."""
import ipaddress
from pathlib import Path
from PySide6.QtWidgets import QLabel, QHBoxLayout, QPlainTextEdit, QCheckBox, QFileDialog, QMessageBox, QHeaderView, QWidget, QVBoxLayout, QTabWidget, QListWidget


class ProtectionPagesMixin:
    def protection_page(self):
        layout = self.page('Real-Time Protection', 'Monitor selected sources in this window or through the optional background engine.')
        self.protection_title = QLabel('Monitoring is off', objectName='value')
        layout.addWidget(self.protection_title)
        self.protection_stats = QLabel('Choose folders and monitoring sources, then start protection.', objectName='small')
        self.protection_stats.setWordWrap(True)
        layout.addWidget(self.protection_stats)
        row = QHBoxLayout()
        row.addWidget(QLabel('Watched folders — one absolute path per line'))
        row.addStretch()
        self.add_watch = self.action(row, 'Add Folder…', self.add_watch_folder)
        layout.addLayout(row)
        self.watch_folders = QPlainTextEdit('\n'.join(self.store.get('watch_folders', [])))
        self.watch_folders.setFixedHeight(56)
        self.watch_folders.setPlaceholderText(str(Path.home()/'Downloads'))
        layout.addWidget(self.watch_folders)
        sources = QHBoxLayout()
        self.process_option = QCheckBox('Track new processes')
        self.process_option.setChecked(self.store.get('watch_processes', True))
        self.sysmon_option = QCheckBox('Read existing Sysmon events')
        self.sysmon_option.setChecked(self.store.get('watch_sysmon', False))
        sources.addWidget(self.process_option)
        sources.addWidget(self.sysmon_option)
        sources.addStretch()
        layout.addLayout(sources)
        advanced = QHBoxLayout()
        self.behavior_option = QCheckBox('Behavior and ransomware warnings')
        self.behavior_option.setChecked(self.store.get('watch_behavior',True))
        self.network_option = QCheckBox('Network telemetry')
        self.network_option.setChecked(self.store.get('watch_network',False))
        advanced.addWidget(self.behavior_option)
        advanced.addWidget(self.network_option)
        advanced.addStretch()
        layout.addLayout(advanced)
        self.background_option = QCheckBox('Keep monitoring when this window closes (current Windows session)')
        self.background_option.setChecked(self.store.get('background_engine',False))
        self.background_option.setToolTip('Optional independent process under your account. Not a Windows service; stops at sign-out or reboot.')
        layout.addWidget(self.background_option)
        actions = QHBoxLayout()
        self.start_protection = self.action(actions, 'Start Protection', self.begin_protection, True)
        self.stop_protection_button = self.action(actions, 'Stop Protection', self.stop_protection)
        self.stop_protection_button.setEnabled(False)
        layout.addLayout(actions)
        self.alert_banner = QLabel('No live alerts this session.', objectName='small')
        self.alert_banner.setWordWrap(True)
        layout.addWidget(self.alert_banner)
        self.live_events = self.table(['Time','Event','Details','Source'])
        self.live_events.setFixedHeight(125)
        for column in (0,1,3):
            self.live_events.horizontalHeader().setSectionResizeMode(column,QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.live_events)
        self.live_events.cellDoubleClicked.connect(self.show_live_event)
        label = QLabel('Configure canaries and IP indicators in Settings → Advanced. Restart after settings changes.\nWarnings indicate suspicion, not confirmed malware. Review signature detections on the Quarantine page.', objectName='small')
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addStretch()

    def settings_page(self):
        super().settings_page()
        tabs = self.stack.widget(5).findChild(QTabWidget)
        advanced = QWidget()
        layout = QVBoxLayout(advanced)
        layout.setContentsMargins(14,12,14,12)
        label = QLabel('Canaries warn when changed or missing in watched folders. They are harmless files you create explicitly.',objectName='small')
        label.setWordWrap(True)
        layout.addWidget(label)
        self.canary_list = QListWidget()
        self.canary_list.setMaximumHeight(65)
        for entry in self.store.get('canaries',[]):
            self.canary_list.addItem(entry['path'])
        layout.addWidget(self.canary_list)
        row = QHBoxLayout()
        self.action(row,'Create Canary…',self.add_canary)
        self.action(row,'Stop Tracking Selected',self.remove_canary)
        layout.addLayout(row)
        layout.addWidget(QLabel('Network IP/CIDR indicators — one per line (no feed is bundled)',objectName='small'))
        self.network_indicators = QPlainTextEdit('\n'.join(self.store.get('network_indicators',[])))
        self.network_indicators.setMaximumHeight(65)
        self.network_indicators.setPlaceholderText('Example lab indicator: 192.0.2.10/32')
        layout.addWidget(self.network_indicators)
        tabs.addTab(advanced,'Advanced')

    def add_canary(self):
        if self.protection_worker:
            QMessageBox.information(self,'Monitoring active','Stop monitoring before changing canary tracking.')
            return
        folder = QFileDialog.getExistingDirectory(self,'Create harmless canary in folder')
        if not folder:
            return
        from sentinelav.monitoring.behavior import create_canary
        try:
            entries = self.store.get('canaries',[])
            if len(entries)>=64:
                raise ValueError('Limit of 64 tracked canaries reached')
            entry = create_canary(folder)
            self.store.set('canaries',entries+[entry])
            self.canary_list.addItem(entry['path'])
            folders = self.watch_folders.toPlainText().splitlines()
            if folder not in folders:
                folders.append(folder)
                self.watch_folders.setPlainText('\n'.join(folders))
        except (OSError,ValueError) as error:
            QMessageBox.warning(self,'Canary creation failed',str(error))

    def remove_canary(self):
        if self.protection_worker:
            QMessageBox.information(self,'Monitoring active','Stop monitoring before changing canary tracking.')
            return
        row = self.canary_list.currentRow()
        if row>=0:
            entries = self.store.get('canaries',[])
            del entries[row]
            self.store.set('canaries',entries)
            self.canary_list.takeItem(row)

    def save_settings(self):
        networks = [v.strip() for v in self.network_indicators.toPlainText().splitlines() if v.strip()]
        try:
            for value in networks:
                ipaddress.ip_network(value,strict=False)
        except ValueError as error:
            QMessageBox.warning(self,'Invalid IP/CIDR indicator',str(error))
            return
        paths = [p.strip() for p in self.exclusions.toPlainText().splitlines() if p.strip()]
        if any(not Path(p).is_absolute() for p in paths):
            QMessageBox.warning(self,'Invalid exclusion','Use absolute paths for exclusions.')
            return
        self.store.set('network_indicators',networks)
        super().save_settings()

    def open_history(self,row,column):
        if self.report_mode == 2:
            self.show_event_details(self.store.events()[row])
        else:
            super().open_history(row,column)

    def add_watch_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Watch folder')
        if path:
            paths = self.watch_folders.toPlainText().splitlines()
            if path not in paths:
                paths.append(path)
            self.watch_folders.setPlainText('\n'.join(p for p in paths if p.strip()))

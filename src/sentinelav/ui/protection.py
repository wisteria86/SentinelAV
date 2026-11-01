"""Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread."""
import json
import os
import time
import ipaddress
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QLabel, QHBoxLayout, QPlainTextEdit, QCheckBox,
    QFileDialog, QMessageBox, QSystemTrayIcon, QHeaderView, QWidget, QVBoxLayout,
    QTabWidget, QListWidget)
from sentinelav.monitoring.monitoring import Monitor
from sentinelav.ui.design import icon


class ProtectionWorker(QThread):
    event = Signal(dict)
    status = Signal(dict)
    failed = Signal(str)

    def __init__(self, config):
        super().__init__()
        self.monitor = Monitor(config, self.event.emit, self.status.emit)

    def run(self):
        try:
            self.monitor.run()
        except Exception as error:
            self.failed.emit(str(error))

    def stop(self):
        self.monitor.stop.set()


class ProtectionMixin:
    def future_page(self, title, subtitle, body):
        if title != 'Real-Time Protection':
            return super().future_page(title, subtitle, body)
        layout = self.page(title, 'Monitor selected sources in this window or through the optional background engine.')
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

    def show_live_event(self,row,column):
        self.show_event_details(self.session_events[row])

    def show_event_details(self,event):
        box = QMessageBox(self)
        box.setWindowTitle(event['kind'])
        box.setText(event['details'])
        box.setDetailedText(json.dumps(event,indent=2))
        box.exec()

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

    def begin_protection(self):
        if self.protection_worker is not None:
            return
        folders = [p.strip() for p in self.watch_folders.toPlainText().splitlines() if p.strip()]
        if any(not Path(p).is_absolute() or not Path(p).is_dir() for p in folders):
            QMessageBox.warning(self, 'Invalid watch folder', 'Use existing absolute folder paths.')
            return
        if not folders and not self.process_option.isChecked() and not self.sysmon_option.isChecked() and not self.network_option.isChecked():
            QMessageBox.warning(self, 'No sources selected', 'Add a folder or enable a monitoring source.')
            return
        from sentinelav.ui.application import ROOT
        config = dict(folders=folders, processes=self.process_option.isChecked(),
                      sysmon=self.sysmon_option.isChecked(), signatures=ROOT/'signatures.json',
                      rules=ROOT/'rules', max_mb=self.store.get('max_mb',100),
                      exclusions=self.store.get('exclusions',[]) + [str(self.store.path.parent)],
                      behavior=self.behavior_option.isChecked(), network=self.network_option.isChecked(),
                      canaries=self.store.get('canaries',[]),network_indicators=self.store.get('network_indicators',[]),
                      trusted_hashes=self.store.get('trusted_hashes',[]))
        config.update(inspection_options=self.store.get('inspection_options',{}),event_processes=self.store.get('event_processes',True),
                      auto_response=self.store.get('auto_response',{}),data_dir=str(self.store.path.parent))
        for key, value in [('watch_folders', folders),('watch_processes',config['processes']),('watch_sysmon',config['sysmon']),('watch_behavior',config['behavior']),('watch_network',config['network'])]:
            self.store.set(key,value)
        self.store.set('background_engine',self.background_option.isChecked())
        self.monitor_state = 'Starting'
        self.protection_failure = ''
        if self.background_option.isChecked():
            from sentinelav.ui.background_ui import BackgroundWorker
            self.protection_worker = BackgroundWorker(self.store.path.parent)
        else:
            self.protection_worker = ProtectionWorker(config)
        self.protection_worker.event.connect(self.receive_event)
        self.protection_worker.status.connect(self.receive_status)
        self.protection_worker.failed.connect(self.protection_error)
        self.protection_worker.finished.connect(self.protection_finished)
        self.set_protection_controls(True)
        self.refresh()
        self.protection_worker.start()

    def reconnect_background(self):
        if self.protection_worker or self.closing or not self.store.get('background_engine',False):
            return
        from sentinelav.ui.background_ui import BackgroundWorker
        self.protection_failure = ''
        self.protection_worker = BackgroundWorker(self.store.path.parent,attach_only=True)
        self.protection_worker.event.connect(self.receive_event)
        self.protection_worker.status.connect(self.receive_status)
        self.protection_worker.failed.connect(self.protection_error)
        self.protection_worker.finished.connect(self.protection_finished)
        self.set_protection_controls(True)
        self.protection_worker.start()

    def set_protection_controls(self, active):
        for control in [self.watch_folders,self.add_watch,self.process_option,self.sysmon_option,self.start_protection,self.behavior_option,self.network_option,self.background_option]:
            control.setEnabled(not active)
        self.stop_protection_button.setEnabled(active)

    def stop_protection(self):
        if self.protection_worker:
            self.monitor_state = 'Stopping'
            self.protection_title.setText('Stopping monitoring…')
            self.stop_protection_button.setEnabled(False)
            self.protection_worker.stop()
            self.refresh()

    def protection_error(self, error):
        self.protection_failure = error
        self.receive_event(dict(time=time.strftime('%Y-%m-%d %H:%M:%S'),
                                kind='Monitoring failed', details=error, source='Protection',level='Warning'))
        self.protection_stats.setText(error)

    def protection_finished(self):
        remote = hasattr(self.protection_worker,'detach')
        self.protection_worker.deleteLater()
        self.protection_worker = None
        self.monitor_state = ('Unknown' if remote else 'Failed') if getattr(self,'protection_failure','') else 'Off'
        self.set_protection_controls(False)
        if self.monitor_state=='Unknown':
            self.background_option.setEnabled(False)
        self.protection_title.setText('Protection status unknown — reconnect to verify' if self.monitor_state=='Unknown' else 'Monitoring failed' if self.monitor_state=='Failed' else 'Monitoring is off')
        self.refresh()

    def receive_status(self, state):
        if self.monitor_state != 'Stopping':
            self.monitor_state = 'Active'
            self.protection_title.setText('Background monitoring is active' if state.get('background') else 'Monitoring is active')
        self.protection_stats.setText(
            f"{state['folders']} watched folders · {state['checked']:,} files inspected · "
            f"{state['processes']} processes visible · {state['denied']} executable paths unavailable\n"
            f"{state['queued']} queued · Sysmon: {'connected' if state['sysmon'] else 'off / unavailable'} · "
            f"Network: {state.get('connections',0)} connections" + (' (off)' if not state.get('network') else ''))
        if 'signature_count' in state:
            self.protection_stats.setText(self.protection_stats.text()+f" · {state['signature_count']:,} hash signatures")
        if 'yara_research_rules' in state:
            self.protection_stats.setText(self.protection_stats.text()+f" · {state['yara_research_rules']} research YARA rules")
        if 'process_event_source' in state:
            suffix=(f"{state.get('uninspected_process_events',0)} observed starts unverified · {state.get('process_event_drops',0)} dropped"
                    if state['process_event_source']=='WMI subscribed' else 'Short-lived process coverage is unknown')
            self.protection_stats.setText(self.protection_stats.text()+f"\nProcess starts: {state['process_event_source']} · "+suffix)
        if state.get('engine_error') or state.get('dropped'):
            self.protection_stats.setText(self.protection_stats.text() + '\nDegraded: ' + (state.get('engine_error') or f"{state['dropped']} telemetry updates dropped"))
        self.refresh()

    def receive_event(self, event):
        event=dict(event)
        persisted=event.pop('_background_persisted',False)
        try:
            if not persisted:
                self.store.save_event(event)
        except Exception as error:
            self.protection_stats.setText(f'Event persistence failed: {error}')
        self.session_events.insert(0,event)
        del self.session_events[200:]
        self.fill(self.live_events, [(e['time'][11:],e['kind'],e['details'],e['source']) for e in self.session_events])
        for row, entry in enumerate(self.session_events):
            if entry['level'] in ('Alert','Warning'):
                for col in range(4):
                    self.live_events.item(row,col).setForeground(QColor('#b64020'))
        if event['kind']=='Behavioral risk' and event['level']=='Warning':
            self.alert_banner.setText('WARNING: ' + event['details'])
            self.alert_banner.setStyleSheet('color:#98520d;font-weight:600;')
            self.statusBar().showMessage('SentinelAV warning: ' + event['details'],15000)
        if event['level'] == 'Alert':
            self.alert_banner.setText(('RISK ALERT: ' if 'score' in event else 'DETECTED: ') + event.get('path','') + ' — ' + event['details'])
            self.alert_banner.setStyleSheet('color:#b8351b;font-weight:600;')
            self.statusBar().showMessage('SentinelAV detection: ' + event['details'], 15000)
            if self.tray:
                self.tray.showMessage('SentinelAV — review required', event.get('path','') + '\n' + event['details'], QSystemTrayIcon.MessageIcon.Warning, 10000)
        self.refresh()

    def refresh(self):
        super().refresh()
        state = getattr(self,'monitor_state','Off')
        active = state == 'Active'
        self.metric_values[3].setText('Monitoring' if active else state if state in ('Starting','Stopping') else 'On-demand')
        self.metric_notes[3].setText('Selected sources' if active else 'Monitoring ' + state.lower())
        self.dashboard_title.setText('Monitoring active' if active else 'Ready to scan')
        self.dashboard_description.setText('Watching selected sources.\nOn-demand scans are also available.' if active else 'On-demand scanning is available.\nRun a scan to check your files.')
        self.dashboard_badge_label.setText('ON' if active else state.upper())
        if state=='Unknown':
            self.dashboard_title.setText('Protection status unknown')
            self.dashboard_description.setText('Reconnect to the background engine\nto verify monitoring status.')
            self.metric_values[3].setText('Unknown')
        self.dashboard_switch.setToolTip('Monitoring ' + state.lower())
        self.dashboard_switch.active = active
        self.dashboard_switch.update()
        background = active and getattr(self,'background_option',None) and self.background_option.isChecked()
        self.latest.setText(('Background engine watches selected sources until stopped or Windows sign-out.' if background else 'Monitoring covers selected sources while the app is open. Response actions require review.') if active else 'Background engine disconnected; monitoring state is unknown.' if state=='Unknown' else 'Scan results cover inspected files only. Real-time monitoring is off.')
        self.metric_values[2].setText(str(sum(len(s['detections']) for s in self.store.history()) + sum(e['level']=='Alert' for e in self.store.events(5000))))
        if self.report_mode == 2:
            self.fill(self.history_table, [(e['time'],e['kind'],e['details'],e['source'],e['level']) for e in self.store.events()])
        elif self.report_mode == 1:
            rows = [(s['started'],d['path'],'; '.join(d['reasons']),d['sha256'],'Reported') for s in self.store.history() for d in s['detections']]
            rows += [(e['time'],e.get('path',''),e['details'],e.get('sha256',''),'Reported live') for e in self.store.events(5000) if e['level']=='Alert']
            self.fill(self.history_table,rows)

    def export(self):
        path, _ = QFileDialog.getSaveFileName(self,'Export report','sentinelav-report.json','JSON (*.json)')
        if path:
            try:
                Path(path).write_text(json.dumps(dict(scans=self.store.history(),protection_events=self.store.events(5000)),indent=2),encoding='utf-8')
            except OSError as error:
                QMessageBox.warning(self,'Export failed',str(error))

    def closeEvent(self, event):
        if self.worker is not None or self.protection_worker is not None:
            if not self.closing:
                self.closing = True
                self.cancel_scan()
                if self.protection_worker and hasattr(self.protection_worker,'detach'):
                    self.protection_worker.detach()
                else:
                    self.stop_protection()
                self.close_timer.start(100)
            event.ignore()
            return
        self.close_timer.stop()
        if self.tray:
            self.tray.hide()
        super().closeEvent(event)

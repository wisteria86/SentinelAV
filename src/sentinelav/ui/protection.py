# Purpose: Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread.
# Works with: monitoring.monitoring, ui.application, ui.background_ui, ui.design, ui.protection_events
# Used by: ui.application

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


from .protection_workers import ProtectionWorker
from .protection_pages import ProtectionPagesMixin
from .protection_events import ProtectionEventsMixin

class ProtectionMixin(ProtectionPagesMixin, ProtectionEventsMixin):


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
                      auto_response=self.store.get('auto_response',{}),data_dir=str(self.store.path.parent),artifact_updates=self.store.get('artifact_updates',{}),
                      watch_app_changes=self.store.get('watch_app_changes',False),tracked_settings=self.store.get('tracked_settings',[]))
        if self.store.get('kernel_collector',''): config['kernel_collector']=self.store.get('kernel_collector','')
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

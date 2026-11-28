# Purpose: Present live events, monitoring status, and protection summaries.
# Works with: sibling modules in ui
# Used by: ui.core.protection

"""Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread."""

import json
from pathlib import Path
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFileDialog, QMessageBox, QSystemTrayIcon
from sentinelav.data.reporting import is_detection


class ProtectionEventsMixin:
    """Shows live protection events and status in the window."""

    def show_live_event(self, row, column):
        """Show the details of a double-clicked live event."""
        self.show_event_details(self.session_events[row])

    def show_event_details(self, event):
        """Show one event's summary and full JSON in a dialog."""
        box = QMessageBox(self)
        box.setWindowTitle(event['kind'])
        box.setText(event['details'])
        box.setDetailedText(json.dumps(event, indent=2))
        box.exec()

    def receive_status(self, state):
        """Update the protection page with a status summary from the monitor, marking it 'needs
        attention' if anything is degraded.
        """
        health_error = (
            state.get('inspection_error')
            or state.get('engine_error')
            or state.get('telemetry_error')
        )
        if not health_error and state.get('dropped'):
            health_error = f"{state['dropped']} telemetry updates dropped"
        if self.monitor_state != 'Stopping':
            self.monitor_state = 'Degraded' if health_error else 'Active'
            self.protection_title.setText(
                'Monitoring needs attention'
                if self.monitor_state == 'Degraded'
                else (
                    'Background monitoring is active'
                    if state.get('background')
                    else 'Monitoring is active'
                )
            )
        self.protection_stats.setText(
            f"{state['folders']} watched folders · {state['checked']:,} files inspected · "
            f"{state['processes']} processes visible · {state['denied']} executable paths unavailable\n"
            f"{state['queued']} queued · Sysmon: {'connected' if state['sysmon'] else 'off / unavailable'} · "
            f"Network: {state.get('connections',0)} connections"
            + (' (off)' if not state.get('network') else '')
        )
        if 'signature_count' in state:
            self.protection_stats.setText(
                self.protection_stats.text() + f" · {state['signature_count']:,} hash signatures"
            )
        if 'yara_research_rules' in state:
            self.protection_stats.setText(
                self.protection_stats.text()
                + f" · {state['yara_research_rules']} research YARA rules"
            )
        if 'process_event_source' in state:
            suffix = (
                f"{state.get('uninspected_process_events',0)} observed starts unverified · {state.get('process_event_drops',0)} dropped"
                if state['process_event_source'] == 'WMI subscribed'
                else 'Short-lived process coverage is unknown'
            )
            self.protection_stats.setText(
                self.protection_stats.text()
                + f"\nProcess starts: {state['process_event_source']} · "
                + suffix
            )
        if 'sequence_telemetry' in state:
            self.protection_stats.setText(
                self.protection_stats.text()
                + '\nBehavior sequences: '
                + state['sequence_telemetry']
            )
        if 'kernel_file_telemetry' in state:
            self.protection_stats.setText(
                self.protection_stats.text()
                + '\nAttributed writes: '
                + state['kernel_file_telemetry']
            )
        if health_error:
            self.protection_stats.setText(
                self.protection_stats.text() + '\nDegraded: ' + health_error
            )
        self.refresh()

    def receive_event(self, event):
        """Save a new event, add it to the live list, and raise a banner, status-bar message or tray
        notification for warnings and alerts.
        """
        event = dict(event)
        persisted = event.pop('_background_persisted', False)
        try:
            if not persisted:
                self.store.save_event(event)
        except Exception as error:
            self.protection_stats.setText(f'Event persistence failed: {error}')
        self.session_events.insert(0, event)
        del self.session_events[200:]
        self.fill(
            self.live_events,
            [(e['time'][11:], e['kind'], e['details'], e['source']) for e in self.session_events],
        )
        for row, entry in enumerate(self.session_events):
            if entry['level'] in ('Alert', 'Warning'):
                for col in range(4):
                    self.live_events.item(row, col).setForeground(QColor('#b64020'))
        if event['kind'] in ('Behavioral risk', 'Suspicious file') and event['level'] == 'Warning':
            self.alert_banner.setText('WARNING: ' + event['details'])
            self.alert_banner.setStyleSheet('color:#98520d;font-weight:600;')
            self.statusBar().showMessage('SentinelAV warning: ' + event['details'], 15000)
        if event['level'] == 'Alert':
            self.alert_banner.setText(
                ('DETECTED: ' if event['kind'] == 'Threat detected' else 'RISK ALERT: ')
                + event.get('path', '')
                + ' — '
                + event['details']
            )
            self.alert_banner.setStyleSheet('color:#b8351b;font-weight:600;')
            self.statusBar().showMessage('SentinelAV detection: ' + event['details'], 15000)
            if self.tray:
                self.tray.showMessage(
                    'SentinelAV — review required',
                    event.get('path', '') + '\n' + event['details'],
                    QSystemTrayIcon.MessageIcon.Warning,
                    10000,
                )
        self.refresh()

    def refresh(self):
        """Update the dashboard to reflect the monitoring state, and refill the Reports table with live
        events and detections.
        """
        super().refresh()
        state = getattr(self, 'monitor_state', 'Off')
        active = state == 'Active'
        self.metric_values[3].setText(
            'Monitoring' if active else state if state in ('Starting', 'Stopping') else 'On-demand'
        )
        self.metric_notes[3].setText(
            'Selected sources' if active else 'Monitoring ' + state.lower()
        )
        self.dashboard_title.setText('Monitoring active' if active else 'Ready to scan')
        self.dashboard_description.setText(
            'Watching selected sources.\nOn-demand scans are also available.'
            if active
            else 'On-demand scanning is available.\nRun a scan to check your files.'
        )
        self.dashboard_badge_label.setText('ON' if active else state.upper())
        if state == 'Unknown':
            self.dashboard_title.setText('Protection status unknown')
            self.dashboard_description.setText(
                'Reconnect to the background engine\nto verify monitoring status.'
            )
            self.metric_values[3].setText('Unknown')
        if state == 'Degraded':
            self.dashboard_title.setText('Monitoring needs attention')
            self.dashboard_description.setText(
                'Inspection or telemetry coverage is incomplete.\nReview protection warnings and affected files.'
            )
            self.metric_values[3].setText('Degraded')
        self.dashboard_switch.setToolTip('Monitoring ' + state.lower())
        self.dashboard_switch.active = active
        self.dashboard_switch.update()
        background = (
            active
            and getattr(self, 'background_option', None)
            and self.background_option.isChecked()
        )
        self.latest.setText(
            (
                'Background engine watches selected sources until stopped or Windows sign-out.'
                if background
                else 'Monitoring covers selected sources while the app is open. Response actions require review.'
            )
            if active
            else (
                'Background engine disconnected; monitoring state is unknown.'
                if state == 'Unknown'
                else 'Scan results cover inspected files only. Real-time monitoring is off.'
            )
        )
        if state == 'Degraded':
            self.latest.setText(
                'Monitoring continues with coverage omissions. Review protection warnings.'
            )
        self.metric_values[2].setText(
            str(
                sum(len(s['detections']) for s in self.store.history())
                + sum(is_detection(e) for e in self.store.events(5000))
            )
        )
        if self.report_mode == 2:
            self.fill(
                self.history_table,
                [
                    (e['time'], e['kind'], e['details'], e['source'], e['level'])
                    for e in self.store.events()
                ],
            )
        elif self.report_mode == 1:
            rows = [
                (
                    s['started'],
                    d['path'],
                    '; '.join(d['reasons']),
                    d['sha256'],
                    d.get('verdict', 'Malicious') + ' ' + str(d.get('score', '')),
                )
                for s in self.store.history()
                for d in s['detections'] + s.get('suspicious', [])
            ]
            rows += [
                (e['time'], e.get('path', ''), e['details'], e.get('sha256', ''), 'Reported live')
                for e in self.store.events(5000)
                if is_detection(e)
            ]
            self.fill(self.history_table, rows)

    def export(self):
        """Save scan history and protection events as a JSON file."""
        path, _ = QFileDialog.getSaveFileName(
            self, 'Export report', 'sentinelav-report.json', 'JSON (*.json)'
        )
        if path:
            try:
                Path(path).write_text(
                    json.dumps(
                        dict(scans=self.store.history(), protection_events=self.store.events(5000)),
                        indent=2,
                    ),
                    encoding='utf-8',
                )
            except OSError as error:
                QMessageBox.warning(self, 'Export failed', str(error))

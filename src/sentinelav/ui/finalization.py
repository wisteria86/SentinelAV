# Purpose: Daily scheduling, opt-in startup, and human-readable exports.
# Works with: data.reporting, platform.runtime
# Used by: ui.application

"""Daily scheduling, opt-in startup, and human-readable exports."""

from pathlib import Path
from PySide6.QtCore import QTimer, QTime, QThread, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QCheckBox,
    QTimeEdit,
    QComboBox,
    QLineEdit,
    QFileDialog,
    QTabWidget,
    QMessageBox,
)
from sentinelav.platform.runtime import (
    VERSION,
    next_daily,
    due,
    set_startup,
    startup_enabled,
    register_schedule,
)
from sentinelav.data.reporting import snapshot, render_report


class PreferencesWorker(QThread):
    """Background thread that applies the Windows startup and scheduled-task settings (these system
    calls can be slow).
    """

    completed = Signal(dict, list)

    def __init__(self, schedule, data_dir, startup):
        """Remember the schedule, data folder and whether to start with Windows."""
        super().__init__()
        self.schedule, self.data_dir, self.startup = schedule, data_dir, startup

    def run(self):
        """Apply both settings and emit completed(schedule, list of problems)."""
        errors = []
        try:
            set_startup(self.startup)
        except OSError as error:
            errors.append('Windows startup was not changed: ' + str(error))
        try:
            register_schedule(self.schedule, self.data_dir)
            self.schedule['windows_task'] = self.schedule['enabled']
        except Exception as error:
            errors.append('Windows task was not updated; app timer only: ' + str(error))
        self.completed.emit(self.schedule, errors)


class FinalizationMixin:
    """Scheduling, startup, report export and close handling for the window."""

    def settings_page(self):
        """Add the Scheduling tab: start with Windows, resume protection, and daily scan time, type and
        folder.
        """
        super().settings_page()
        tabs = self.stack.widget(5).findChild(QTabWidget)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 12, 14, 12)
        self.startup_option = QCheckBox('Launch SentinelAV when I sign in to Windows')
        self.startup_option.setChecked(startup_enabled())
        layout.addWidget(self.startup_option)
        self.resume_option = QCheckBox('Start saved protection sources when the app launches')
        self.resume_option.setChecked(self.store.get('resume_protection', False))
        layout.addWidget(self.resume_option)
        self.schedule_option = QCheckBox('Enable a daily scheduled scan (Asia/Karachi time)')
        schedule = self.store.get('schedule', {})
        self.schedule_option.setChecked(schedule.get('enabled', False))
        layout.addWidget(self.schedule_option)
        row = QHBoxLayout()
        self.schedule_time = QTimeEdit(QTime(schedule.get('hour', 18), schedule.get('minute', 0)))
        self.schedule_time.setDisplayFormat('HH:mm')
        row.addWidget(self.schedule_time)
        self.schedule_kind = QComboBox()
        self.schedule_kind.addItems(['Quick', 'Full', 'Folder'])
        self.schedule_kind.setCurrentText(schedule.get('kind', 'Quick'))
        row.addWidget(self.schedule_kind)
        row.addStretch()
        layout.addLayout(row)
        row = QHBoxLayout()
        self.schedule_folder = QLineEdit(schedule.get('folder', ''))
        self.schedule_folder.setPlaceholderText('Folder path for a Folder schedule')
        row.addWidget(self.schedule_folder)
        self.action(row, 'Browse…', self.choose_schedule_folder)
        layout.addLayout(row)
        self.apply_schedule_button = self.action(
            layout, 'Apply Startup and Schedule', self.apply_schedule, True
        )
        self.schedule_note = QLabel(objectName='small')
        self.schedule_note.setWordWrap(True)
        layout.addWidget(self.schedule_note)
        layout.addStretch()
        tabs.addTab(page, 'Scheduling')
        self.update_schedule_note()

    def choose_schedule_folder(self):
        """Let the user pick the folder for a Folder schedule."""
        folder = QFileDialog.getExistingDirectory(self, 'Scheduled scan folder')
        if folder:
            self.schedule_folder.setText(folder)

    def update_schedule_note(self):
        """Show when the next scheduled scan will run and how it is triggered."""
        schedule = self.store.get('schedule', {})
        text = 'Daily scans are disabled.'
        if schedule.get('enabled'):
            text = (
                'Next scan: '
                + schedule['next_run']
                + ' · '
                + ('Windows task + app timer' if schedule.get('windows_task') else 'app timer only')
            )
        self.schedule_note.setText(
            text
            + ' Closed-app tasks require this user to be logged in. Missed runs catch up once; busy scans are deferred.'
        )

    def apply_schedule(self):
        """Validate the schedule inputs and apply them in a PreferencesWorker."""
        if self.response_worker or self.preferences_worker:
            QMessageBox.information(
                self, 'Response active', 'Wait for the response operation to finish.'
            )
            return
        folder = self.schedule_folder.text().strip()
        if (
            self.schedule_option.isChecked()
            and self.schedule_kind.currentText() == 'Folder'
            and (not Path(folder).is_absolute() or not Path(folder).is_dir())
        ):
            QMessageBox.warning(
                self, 'Invalid schedule folder', 'Choose an existing absolute folder path.'
            )
            return
        hour, minute = self.schedule_time.time().hour(), self.schedule_time.time().minute()
        schedule = dict(
            enabled=self.schedule_option.isChecked(),
            hour=hour,
            minute=minute,
            kind=self.schedule_kind.currentText(),
            folder=folder,
            next_run=next_daily(hour, minute).isoformat(),
            windows_task=False,
        )
        self.pending_resume = self.resume_option.isChecked()
        self.apply_schedule_button.setEnabled(False)
        self.schedule_note.setText('Applying Windows preferences…')
        self.preferences_worker = PreferencesWorker(
            schedule, self.store.path.parent, self.startup_option.isChecked()
        )
        self.preferences_worker.completed.connect(self.preferences_completed)
        self.preferences_worker.finished.connect(self.preferences_finished)
        self.preferences_worker.start()

    def preferences_completed(self, schedule, errors):
        """Save the applied schedule, log the change and tell the user about any limitations."""
        self.store.set('schedule', schedule)
        self.store.set('resume_protection', self.pending_resume)
        self.audit_response('Startup/schedule settings changed', str(schedule))
        self.update_schedule_note()
        if errors:
            QMessageBox.warning(self, 'Settings applied with limitations', '\n'.join(errors))
        else:
            QMessageBox.information(
                self, 'Schedule saved', 'Startup and scheduling preferences applied.'
            )

    def preferences_finished(self):
        """Tidy up after the preferences worker and re-enable the Apply button."""
        self.preferences_worker.deleteLater()
        self.preferences_worker = None
        self.apply_schedule_button.setEnabled(True)

    def check_schedule(self):
        """Start the scheduled scan if it is due and nothing else is running (checked every 30
        seconds).
        """
        if self.closing or self.worker or self.response_worker:
            return
        schedule = self.store.get('schedule', {})
        if not due(schedule):
            return
        if schedule['kind'] == 'Folder':
            roots = [schedule['folder']]
        else:
            import os

            roots = [
                p
                for p in [
                    Path.home() / 'Downloads',
                    Path(os.getenv('TEMP', str(Path.home() / 'AppData/Local/Temp'))),
                ]
                if p.is_dir()
            ]
        self.start_scan(roots, 'Scheduled ' + schedule['kind'])
        if self.worker:
            schedule['next_run'] = next_daily(schedule['hour'], schedule['minute']).isoformat()
            self.store.set('schedule', schedule)
            self.audit_response('Scheduled scan started', schedule['kind'])
            self.update_schedule_note()

    def export(self):
        """Ask where to save a report and write it as HTML, JSON or CSV."""
        path, selected = QFileDialog.getSaveFileName(
            self,
            'Export security report',
            'sentinelav-report.html',
            'HTML report (*.html);;JSON evidence (*.json);;Scan history CSV (*.csv)',
        )
        if not path:
            return
        kind = Path(path).suffix.lower().lstrip('.')
        if kind not in ('html', 'json', 'csv'):
            kind = 'json' if 'JSON' in selected else 'csv' if 'CSV' in selected else 'html'
            path += '.' + kind
        try:
            Path(path).write_text(
                render_report(snapshot(self.store), kind),
                encoding='utf-8-sig' if kind == 'csv' else 'utf-8',
            )
        except OSError as error:
            QMessageBox.warning(self, 'Export failed', str(error))

    def refresh(self):
        """Add scan coverage and quarantine counts to the dashboard summary line."""
        super().refresh()
        if hasattr(self, 'latest'):
            last = self.store.history()
            coverage = (
                'No scan completed yet.'
                if not last
                else f"Last scan coverage: {last[0]['skipped']} oversized files, {len(last[0]['errors'])} errors."
            )
            active = sum(r['state'] == 'Quarantined' for r in self.store.quarantine())
            self.latest.setText(
                self.latest.text() + f'\n{coverage} {active} files quarantined. v{VERSION}'
            )

    def closeEvent(self, event):
        """Wait for the preferences worker to finish before closing."""
        if self.preferences_worker:
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        super().closeEvent(event)

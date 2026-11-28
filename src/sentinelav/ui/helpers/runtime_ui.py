# Purpose: Explicit guest-job UI; host receives metadata only and never launches samples.
# Works with: paths, updates.artifacts, workspace
# Used by: ui.helpers.lab_pages

"""Explicit guest-job UI; host receives metadata only and never launches samples."""

import json
import os
from pathlib import Path
import re
import subprocess
import uuid
from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QHBoxLayout,
    QPushButton,
    QMessageBox,
    QFileDialog,
)
from sentinelav.paths import PROJECT_ROOT


class RuntimeWorker(QThread):
    """Background thread that runs one lab controller script (prepare kit, start guest, or run/reset a
    guest job) and reads its output.
    """

    stage = Signal(str)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, request, state_dir):
        """Remember the request and where to write the temporary request file."""
        super().__init__()
        self.request = request
        self.state_dir = Path(state_dir)

    def run(self):
        """Write the request, run the matching PowerShell controller, relay '[stage]' lines as
        progress, and emit the final JSON result.
        """
        request_path = None
        try:
            operation = self.request.get('operation', 'runtime')
            script_names = {
                'runtime': 'Invoke-RuntimeJob.ps1',
                'prepare': 'Prepare-TestEnvironment.ps1',
                'start': 'Start-TestEnvironment.ps1',
            }
            if operation not in script_names:
                raise ValueError('Unknown lab controller operation')
            script = PROJECT_ROOT / 'scripts/lab' / script_names[operation]
            if not script.is_file():
                raise ValueError(
                    'The source-workspace runtime controller is unavailable in this build'
                )
            self.state_dir.mkdir(parents=True, exist_ok=True)
            request_path = self.state_dir / ('job-' + uuid.uuid4().hex + '.json')
            with request_path.open('x', encoding='utf-8') as stream:
                json.dump(self.request, stream)
            command = [
                str(
                    Path(os.environ.get('SystemRoot', 'C:/Windows'))
                    / 'System32/WindowsPowerShell/v1.0/powershell.exe'
                ),
                '-NoProfile',
                '-File',
                str(script),
            ]
            if operation == 'prepare':
                command += ['-PackageRoot', self.request['package_root']]
            elif operation == 'runtime':
                command += (
                    ['-ResetOnly']
                    if self.request.get('reset_only')
                    else ['-JobManifest', str(request_path)]
                )
            environment = dict(os.environ)
            environment['PSModulePath'] = str(
                Path(os.environ.get('SystemRoot', 'C:/Windows'))
                / 'System32/WindowsPowerShell/v1.0/Modules'
            )
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            )
            result = None
            tail = []
            for raw in iter(lambda: process.stdout.readline(65537), b''):
                if len(raw) > 65536:
                    tail.append('Oversized controller output discarded; waiting for owned cleanup.')
                    continue
                line = raw.decode('utf-8', errors='replace').strip()
                if line.startswith('[stage]'):
                    self.stage.emit(line[7:].strip())
                elif line.startswith('{'):
                    try:
                        result = json.loads(line)
                    except ValueError:
                        tail.append(line[:500])
                else:
                    tail.append(line[:500])
                tail = tail[-20:]
            code = process.wait()
            process.stdout.close()
            if operation in ('prepare', 'start') and code == 0:
                from sentinelav.updates.artifacts import bounded_json
                from sentinelav.workspace import Workspace

                state = bounded_json(Workspace().area('lab') / 'windows-sandbox/latest.json', 16384)
                result = dict(
                    schema=1,
                    status=(
                        'Offline input kit prepared'
                        if operation == 'prepare'
                        else 'Registered guest launch requested; runtime checks remain required'
                    ),
                    kit_id=state['kit_id'],
                    execution_attempted=False,
                    guest_disposal_verified=False,
                    operation=operation,
                )
            if code or not isinstance(result, dict) or result.get('schema') != 1:
                raise RuntimeError('Runtime controller failed: ' + '\n'.join(tail))
            self.completed.emit(result)
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            if request_path is not None:
                try:
                    request_path.unlink(missing_ok=True)
                except OSError:
                    pass


def add_runtime_tab(window, tabs):
    """Add the 'Offline Guest Job' tab to the lab page and wire up its buttons.

    It also attaches prepare_guest_kit() and start_registered_guest() to the window so the Overview
    tab's buttons can use them.
    """
    window.runtime_worker = None
    window.runtime_last_result = None
    page = QWidget()
    layout = QVBoxLayout(page)
    label = QLabel(
        'Run one specimen already imported into the registered offline guest.\nNo malware file is selected or executed on this PC. The used guest is discarded afterward.'
    )
    label.setWordWrap(True)
    layout.addWidget(label)
    layout.addWidget(QLabel('Guest corpus SHA-256'))
    window.runtime_sha = QLineEdit()
    window.runtime_sha.setMaxLength(64)
    layout.addWidget(window.runtime_sha)
    row = QHBoxLayout()
    row.addWidget(QLabel('Observation seconds'))
    window.runtime_seconds = QSpinBox()
    window.runtime_seconds.setRange(1, 120)
    window.runtime_seconds.setValue(30)
    row.addWidget(window.runtime_seconds)
    row.addStretch()
    layout.addLayout(row)
    window.runtime_note = QLabel(
        'Requires a current lab kit and an explicitly imported guest specimen. No job has run.'
    )
    window.runtime_note.setWordWrap(True)
    layout.addWidget(window.runtime_note)
    row = QHBoxLayout()
    window.runtime_start = QPushButton('Run in Offline Guest…')
    row.addWidget(window.runtime_start)
    window.runtime_reset = QPushButton('Reset Registered Guest…')
    row.addWidget(window.runtime_reset)
    controller = PROJECT_ROOT / 'scripts/lab/Invoke-RuntimeJob.ps1'
    if not controller.is_file():
        window.runtime_start.setEnabled(False)
        window.runtime_reset.setEnabled(False)
        window.runtime_note.setText(
            'Offline guest control requires the source-workspace lab controller. This build does not include it.'
        )
    details = QPushButton('View Last Job')
    row.addWidget(details)
    layout.addLayout(row)

    def show_details():
        """Show the full summary of the last guest job."""
        if not window.runtime_last_result:
            return
        box = QMessageBox(window)
        box.setWindowTitle('Guest runtime summary')
        box.setText(window.runtime_note.text())
        box.setDetailedText(json.dumps(window.runtime_last_result, indent=2))
        box.exec()

    details.clicked.connect(show_details)

    def start():
        """Validate the specimen hash, confirm with the user, and run the job in the disposable guest."""
        if (
            window.runtime_worker
            or window.lab_worker
            or window.worker
            or window.response_worker
            or window.protection_worker
        ):
            window.runtime_note.setText(
                'Finish active scans, monitoring, response or lab work first.'
            )
            return
        if (
            window.runtime_last_result
            and window.runtime_last_result.get('execution_attempted')
            and not window.runtime_last_result.get('guest_disposal_verified')
        ):
            window.runtime_note.setText('Reset the registered guest before another runtime job.')
            return
        sha = window.runtime_sha.text().strip().lower()
        if not re.fullmatch('[a-f0-9]{64}', sha):
            window.runtime_note.setText(
                'Enter the exact SHA-256 of an existing guest corpus specimen.'
            )
            return
        answer = QMessageBox.question(
            window,
            'Run in disposable guest?',
            'Execute this selected specimen only inside the registered offline Windows Sandbox?\n\n'
            + sha
            + '\n\nThe used guest and its contents will be discarded. Only a bounded summary is retained on the host.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        request = dict(
            schema=1,
            authorization='RUN_ONLY_IN_DISPOSABLE_OFFLINE_GUEST',
            sha256=sha,
            seconds=window.runtime_seconds.value(),
        )
        launch(request)

    def launch(request):
        """Start a RuntimeWorker for a request and connect its progress and result to the page."""
        window.runtime_worker = RuntimeWorker(
            request, window.store.path.parent / 'runtime-requests'
        )
        window.runtime_start.setEnabled(False)
        window.runtime_reset.setEnabled(False)
        window.runtime_worker.stage.connect(window.runtime_note.setText)

        def completed(result):
            """Show and audit the finished job's summary."""
            window.runtime_last_result = result
            window.runtime_note.setText(
                result['status']
                + ' · guest disposal: '
                + ('verified' if result.get('guest_disposal_verified') else 'not verified')
            )
            window.audit_response('Guest runtime job', json.dumps(result)[:4000])

        window.runtime_worker.completed.connect(completed)
        window.runtime_worker.failed.connect(
            lambda error: window.runtime_note.setText(
                'Job incomplete: ' + error + ' — check registered guest state before retrying.'
            )
        )

        def finished():
            """Tidy up after the worker and re-enable the buttons."""
            window.runtime_worker.deleteLater()
            window.runtime_worker = None
            window.runtime_start.setEnabled(True)
            window.runtime_reset.setEnabled(True)

        window.runtime_worker.finished.connect(finished)
        window.runtime_worker.start()

    window.runtime_start.clicked.connect(start)

    def reset():
        """After confirmation, discard the registered guest and verify a fresh one."""
        if window.runtime_worker or window.lab_worker:
            return
        if (
            QMessageBox.question(
                window,
                'Discard registered guest?',
                'Discard only the registered test guest and verify a fresh replacement? Its current contents will be lost.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            == QMessageBox.StandardButton.Yes
        ):
            launch(dict(reset_only=True))

    window.runtime_reset.clicked.connect(reset)

    def prepare():
        """Let the user pick a built package folder and prepare the offline guest kit from it."""
        if window.runtime_worker or window.lab_worker:
            return
        folder = QFileDialog.getExistingDirectory(
            window, 'Choose the built SentinelAV package folder'
        )
        if not folder:
            return
        if not (Path(folder) / 'SentinelAV.exe').is_file():
            window.runtime_note.setText('Select a built package containing SentinelAV.exe.')
            return
        tabs.setCurrentWidget(page)
        launch(dict(operation='prepare', package_root=folder))

    def start_guest():
        """After confirmation, start the prepared offline guest."""
        if window.runtime_worker or window.lab_worker:
            return
        if (
            QMessageBox.question(
                window,
                'Start registered offline guest?',
                'Start the prepared read-only, offline Windows Sandbox kit? Its bootstrap performs guest readiness checks.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            == QMessageBox.StandardButton.Yes
        ):
            tabs.setCurrentWidget(page)
            launch(dict(operation='start'))

    window.prepare_guest_kit = prepare
    window.start_registered_guest = start_guest
    layout.addStretch()
    tabs.addTab(page, 'Offline Guest Job')

# Purpose: Background inventory, encrypted change history, and reviewed cleanup controls.
# Works with: data.change_journal, data.storage, detection.inspection, monitoring.app_changes, paths
# Used by: ui.application

"""Background inventory, encrypted change history, and reviewed cleanup controls."""

import json
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtWidgets import (
    QLabel,
    QHBoxLayout,
    QMessageBox,
    QCheckBox,
    QPlainTextEdit,
    QFileDialog,
    QAbstractItemView,
    QComboBox,
)
from sentinelav.data.change_journal import ChangeJournal
from sentinelav.monitoring.app_changes import WindowsInventory, ChangeTracker
from sentinelav.response.remediation import Remediator, WindowsRemediationBackend
from sentinelav.response.response import ResponseService
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.paths import RESOURCE_ROOT


class AppChangeWorker(QThread):
    """Background thread for the App Changes page: refreshes the inventory, plans clean-ups or
    restores, and executes approved plans.

    With source='service' it works on the protected service's machine-wide history and goes through
    the elevated broker (UAC) instead.
    """

    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, folder, settings, options, action='refresh', value=None, source='local'):
        """Remember the data folder, tracked setting files, scan options, the action and its value, and
        which history to use.
        """
        super().__init__()
        self.folder, self.settings, self.options, self.action, self.value = (
            folder,
            settings,
            options,
            action,
            value,
        )
        self.source = source

    def run(self):
        """Carry out the requested action and emit completed(result) or failed(message)."""
        journal = None
        store = None
        scanner = None
        try:
            if self.source == 'service':
                from sentinelav.platform.service_changes import load_view
                from sentinelav.platform.remediation_broker import (
                    launch,
                    BrokerJournal,
                    protected_root,
                )
                from sentinelav.platform.windows_identity import current_sid

                result = None
                if self.action == 'cleanup':
                    result = launch(dict(schema=1, operation='prepare', change_ids=self.value))
                elif self.action == 'execute':
                    result = launch(dict(schema=1, operation='execute', plan_id=self.value))
                elif self.action != 'refresh':
                    raise ValueError(
                        'Machine history supports reviewed cleanup; restoration requires protected original-state validation'
                    )
                view = load_view()
                root = protected_root(current_sid())
                view['receipts'] = (
                    BrokerJournal(root, current_sid()).operations() if root.exists() else []
                )
                if view.get('stale'):
                    view['errors'].append(
                        'Service history is stale; reviewed machine cleanup needs a fresh service observation'
                    )
                if result:
                    view['result'] = result
                self.completed.emit(view)
                return
            from sentinelav.data.storage import Store

            journal = ChangeJournal(self.folder / 'app-changes')
            inventory = WindowsInventory(self.settings)
            if self.action == 'refresh':
                result = ChangeTracker(journal, inventory).poll()
                self.completed.emit(
                    dict(
                        rows=journal.changes(),
                        receipts=journal.operations(),
                        errors=result['errors'],
                    )
                )
                return
            store = Store(self.folder / 'sentinelav.db')
            scanner = IsolatedScanner(
                RESOURCE_ROOT / 'signatures.json',
                RESOURCE_ROOT / 'rules',
                options=self.options,
                persistent=True,
            )

            def verify(path):
                """Re-scan one file and return its detections."""
                return scanner.scan([path], lambda: False, lambda *a: None)['detections']

            def verify_buffer(content):
                """Scan content that is about to be restored, refusing if the scan was incomplete."""
                result = scanner.scan_buffer(content)
                if not result['complete']:
                    raise ValueError('Recovery content inspection incomplete')
                return result['detected']

            engine = Remediator(
                journal,
                WindowsRemediationBackend(inventory),
                verify,
                ResponseService(store, RESOURCE_ROOT),
                verify_buffer,
            )
            engine.reconcile()
            if self.action in ('cleanup', 'restore'):
                result = engine.plan(
                    self.value if isinstance(self.value, list) else [self.value], self.action
                )
            elif self.action == 'execute':
                result = engine.execute(self.value, approved=True)
            else:
                raise ValueError('Unsupported App Changes operation')
            self.completed.emit(
                dict(
                    result=result, rows=journal.changes(), receipts=journal.operations(), errors=[]
                )
            )
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            if scanner:
                scanner.close()
            if journal:
                journal.close()
            if store:
                store.db.close()


class AppChangesMixin:
    """Builds and drives the App Changes page."""

    def app_changes_page(self):
        """Build the App Changes page: history source picker, tracking switch, change table, details
        box and action buttons.
        """
        layout = self.page(
            'App Changes',
            'Review startup, task, service and selected settings changes. Attribution is shown only when established.',
        )
        self.change_worker = None
        self.change_rows = []
        self.change_plan = None
        self.change_receipts = []
        self.change_status = QLabel(
            'Refresh to capture the initial inventory. Existing entries are not assumed malicious.',
            objectName='muted',
        )
        self.change_status.setWordWrap(True)
        layout.addWidget(self.change_status)
        self.change_source = QComboBox()
        self.change_source.addItem('My account — changes and recovery', 'local')
        self.change_source.addItem('Protected service — machine changes', 'service')
        self.change_source.currentIndexChanged.connect(self.change_source_changed)
        layout.addWidget(self.change_source)
        self.track_changes = QCheckBox('Track changes continuously while protection is running')
        self.track_changes.setChecked(self.store.get('watch_app_changes', False))
        self.track_changes.toggled.connect(lambda value: self.store.set('watch_app_changes', value))
        layout.addWidget(self.track_changes)
        self.change_table = self.table(['Observed', 'Resource', 'Attribution', 'Baseline'])
        self.change_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.change_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.change_table.cellClicked.connect(self.show_change)
        layout.addWidget(self.change_table, 1)
        self.change_details = QPlainTextEdit()
        self.change_details.setReadOnly(True)
        self.change_details.setMaximumHeight(110)
        layout.addWidget(self.change_details)
        row = QHBoxLayout()
        self.change_refresh = self.action(
            row, 'Refresh inventory', lambda: self.change_action('refresh')
        )
        self.action(row, 'Review cleanup', lambda: self.selected_change_action('cleanup'))
        self.action(row, 'Restore selected change', lambda: self.selected_change_action('restore'))
        self.action(row, 'Track setting file…', self.add_tracked_setting)
        layout.addLayout(row)
        receipt_row = QHBoxLayout()
        self.action(receipt_row, 'Show latest cleanup receipt', self.show_change_receipt)
        self.action(receipt_row, 'Export summary…', self.export_change_summary)
        layout.addLayout(receipt_row)
        self.change_execute = self.action(
            layout, 'Apply reviewed plan', self.execute_change_plan, True
        )
        self.change_execute.setEnabled(False)

    def change_source_changed(self):
        """Clear the page when the user switches between their own history and the protected service's."""
        if self.change_worker:
            return
        local = self.change_source.currentData() == 'local'
        self.track_changes.setEnabled(local)
        self.change_rows = []
        self.change_receipts = []
        self.change_plan = None
        self.change_table.setRowCount(0)
        self.change_execute.setEnabled(False)
        self.change_details.clear()
        self.change_status.setText(
            'Refresh to read '
            + (
                'your account history.'
                if local
                else 'the protected service history. Machine repair prompts for UAC twice: prepare, then apply the reviewed plan.'
            )
        )

    def add_tracked_setting(self):
        """Let the user pick an application setting file to track, then refresh."""
        if self.change_source.currentData() != 'local':
            self.change_status.setText('Select My account to track personal setting files.')
            return
        path, _ = QFileDialog.getOpenFileName(
            self,
            'Select application setting file',
            '',
            'Settings (*.ini *.json *.xml *.cfg *.conf *.yaml *.yml)',
        )
        if path:
            selected = self.store.get('tracked_settings', [])
            if path not in selected:
                self.store.set('tracked_settings', selected + [path])
            self.change_action('refresh')

    def show_change(self, row, column=0):
        """Show the details of the clicked change, hiding stored file contents."""
        if not 0 <= row < len(self.change_rows):
            return
        record = self.change_rows[row]

        # Content is available locally to the owner, never exported by default.
        def view(state):
            """Replace a stored file snapshot with a placeholder for display."""
            if not state:
                return state
            return {
                k: ('[encrypted file snapshot]' if k == 'content' else v) for k, v in state.items()
            }

        self.change_details.setPlainText(
            json.dumps(
                dict(
                    resource=record['resource'],
                    attribution=record['attribution'],
                    before=view(record['before']),
                    after=view(record['after']),
                    baseline_trusted=record['baseline_trusted'],
                ),
                indent=2,
            )
        )

    def selected_change_action(self, action):
        """Run an action (cleanup or restore) on every selected change."""
        rows = sorted({item.row() for item in self.change_table.selectedIndexes()})
        if not rows:
            return
        self.change_action(action, [self.change_rows[row]['id'] for row in rows])

    def show_change_receipt(self):
        """Show the most recent clean-up receipt."""
        receipts = [row for row in self.change_receipts if row.get('kind') == 'RemediationReceipt']
        self.change_details.setPlainText(
            json.dumps(receipts[0], indent=2) if receipts else 'No cleanup receipt recorded yet.'
        )

    def export_change_summary(self):
        """Save a redacted summary of changes and receipts to a new JSON file."""
        path, _ = QFileDialog.getSaveFileName(
            self, 'Export App Changes summary', 'SentinelAV-app-changes.json', 'JSON (*.json)'
        )
        if not path:
            return
        try:
            from sentinelav.response.change_reports import summary

            # A new destination prevents an export from silently replacing a
            # configuration file selected by mistake.
            with Path(path).open('x', encoding='utf-8') as stream:
                json.dump(summary(self.change_rows, self.change_receipts), stream, indent=2)
            self.change_status.setText(
                'Summary exported. Sensitive recorded settings and commands were omitted.'
            )
        except Exception as error:
            self.change_status.setText('Export unavailable: ' + str(error))

    def change_action(self, action, value=None):
        """Start an AppChangeWorker for the given action (ignored if one is already running)."""
        if self.change_worker:
            return
        self.change_execute.setEnabled(False)
        self.change_plan = None
        self.change_source.setEnabled(False)
        self.change_status.setText(
            'Reading Windows inventory…'
            if action == 'refresh'
            else 'Verifying identities, evidence and current settings…'
        )
        self.change_worker = AppChangeWorker(
            self.store.path.parent,
            self.store.get('tracked_settings', []),
            self.store.get('inspection_options', {}),
            action,
            value,
            self.change_source.currentData(),
        )
        self.change_worker.completed.connect(self.change_completed)
        self.change_worker.failed.connect(
            lambda message: self.change_status.setText('Action unavailable: ' + message)
        )
        self.change_worker.finished.connect(self.change_finished)
        self.change_worker.start()

    def change_completed(self, result):
        """Fill the table with the returned changes and show any plan, receipt or collection gaps."""
        import time

        self.change_rows = result['rows']
        self.change_receipts = result.get('receipts', [])
        self.fill(
            self.change_table,
            [
                (
                    time.strftime('%m-%d %H:%M:%S', time.localtime(r['observed_at'])),
                    r['resource'].get(
                        'path', r['resource'].get('name', r['resource'].get('key', ''))
                    ),
                    r['attribution'],
                    'Pre-existing' if r['preexisting'] else 'Recorded',
                )
                for r in self.change_rows
            ],
        )
        errors = result['errors']
        self.change_status.setText(
            f"{len(self.change_rows)} recorded observations; {len(errors)} collection gaps. Continuous tracking changes apply when protection restarts."
        )
        self.change_details.setPlainText('\n'.join(errors))
        value = result.get('result')
        if value:
            self.change_details.setPlainText(json.dumps(value, indent=2))
            if value['state'] == 'Planned':
                self.change_plan = value
                self.change_execute.setEnabled(True)
            else:
                self.change_status.setText(value['state'])

    def change_finished(self):
        """Tidy up after the worker finishes and re-enable the source picker."""
        self.change_worker.deleteLater()
        self.change_worker = None
        self.change_source.setEnabled(True)

    def execute_change_plan(self):
        """Ask the user to confirm, then execute the reviewed plan."""
        if not self.change_plan or self.change_worker:
            return
        answer = QMessageBox.question(
            self,
            'Apply reviewed change plan',
            'Apply the displayed plan? Recorded previous settings are not automatically trustworthy. '
            'Restoring startup entries or tasks can enable an application to run again. Conflicting resources will be skipped.',
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.change_action('execute', self.change_plan['id'])

    def closeEvent(self, event):
        """Wait for a running App Changes action to finish before closing."""
        if getattr(self, 'change_worker', None):
            event.ignore()
            QTimer.singleShot(200, self.close)
            return
        super().closeEvent(event)

# Purpose: Definition maintenance in the existing Settings UI; file work stays off Qt UI.
# Works with: ui.application, updates.definition_updates, updates.hash_archive
# Used by: ui.application

"""Definition maintenance in the existing Settings UI; file work stays off Qt UI."""

from pathlib import Path
import json
import threading
from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QFileDialog
from sentinelav.updates.definition_updates import (
    load_active,
    freshness,
    import_recent,
    apply_signed,
    apply_changes,
    read_json,
    rollback,
    MAX_PAYLOAD,
)
from sentinelav.updates.hash_archive import import_archive


class DefinitionWorker(QThread):
    """Background thread for definition updates: CSV and archive imports, signed packages, corrections,
    rollback and ClamAV signature downloads.
    """

    completed = Signal(dict)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, root, kind, path=None):
        """Remember the resources folder, the kind of update and its input file."""
        super().__init__()
        self.root, self.kind, self.path = Path(root), kind, path
        self.cancelled = threading.Event()

    def run(self):
        """Run the requested update and emit completed(metadata) or failed(message)."""
        from sentinelav.detection.definition_paths import signature_data_dir

        folder = signature_data_dir(self.root)
        try:
            if self.kind == 'recent':
                result = import_recent(folder, self.path)
            elif self.kind == 'signed':
                result = apply_signed(folder, self.path, self.root / 'trusted-update-keys.json')
            elif self.kind == 'corrections':
                result = apply_changes(
                    folder,
                    read_json(self.path, MAX_PAYLOAD),
                    'Manual explicit corrections; not publisher-authenticated',
                )
            elif self.kind == 'rollback':
                result = rollback(folder)
            elif self.kind == 'clamav':
                from sentinelav.detection.clamav_engine import (
                    ClamdService,
                    definitions_summary,
                    update_definitions,
                )

                self.progress.emit('Downloading ClamAV signatures from the official mirror…')
                update_definitions()
                service = ClamdService()
                if service.endpoint():
                    service.reload()
                result = dict(clamav=definitions_summary())
            elif self.kind == 'full':

                def report(count):
                    """Relay import progress, stopping early if the window asked to cancel."""
                    if self.cancelled.is_set():
                        raise InterruptedError('Import cancelled before activation')
                    self.progress.emit(f'Validated {count:,} CSV rows…')

                result = import_archive(self.path, folder, True, report)
            else:
                raise ValueError('Unsupported definition operation')
            self.completed.emit(result)
        except Exception as error:
            self.failed.emit(str(error))


def layer_status():
    """One line per extra signature layer, so missing ones are visible here rather than on every scan."""
    from sentinelav.detection.clamav_engine import definitions_summary, read_endpoint
    from sentinelav.detection.definition_paths import binaries, definitions_dir

    clam = definitions_summary()
    parts = [
        'ClamAV: '
        + (
            'not installed'
            if not binaries()
            else (
                'signatures missing'
                if clam['status'] != 'Present'
                else ('running' if read_endpoint() else 'installed, service not running')
                + ' · '
                + ', '.join(f"{f['name']} {f['modified'][:10]}" for f in clam['files'])
            )
        )
    ]
    pack = definitions_dir('yara-forge') / 'pack.json'
    parts.append(
        'YARA-Forge rules: '
        + (
            json.loads(pack.read_text(encoding='utf-8')).get('release', 'installed')
            if pack.is_file()
            else 'not installed'
        )
    )
    md5 = definitions_dir('md5-feed') / 'active.json'
    parts.append(
        'MD5 lists: '
        + (
            f"{json.loads(md5.read_text(encoding='utf-8'))['unique_md5']:,} hashes"
            if md5.is_file()
            else 'not installed'
        )
    )
    parts.append(
        'Certificate blocklist: '
        + (
            'installed'
            if (definitions_dir('cert-blocklist') / 'cscb.csv').is_file()
            else 'not installed'
        )
    )
    return ' · '.join(parts)


class UpdatesMixin:
    """Adds the Definitions settings tab and runs definition updates."""

    def settings_page(self):
        """Add the Definitions tab with its status line and update buttons."""
        super().settings_page()
        tabs = self.stack.widget(5).findChild(QTabWidget)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 12, 16, 12)
        self.definition_health = QLabel(objectName='small')
        self.definition_health.setWordWrap(True)
        layout.addWidget(self.definition_health)
        self.definition_buttons = []
        for specs in [
            [('Import recent CSV…', 'recent'), ('Import full CSV ZIP…', 'full')],
            [
                ('Apply signed package…', 'signed'),
                ('Apply reviewed corrections…', 'corrections'),
                ('Roll Back Last Update', 'rollback'),
            ],
            [('Update ClamAV Signatures', 'clamav')],
        ]:
            row = QHBoxLayout()
            for title, kind in specs:
                self.definition_buttons.append(
                    self.action(
                        row, title, lambda checked=False, k=kind: self.begin_definition_update(k)
                    )
                )
            layout.addLayout(row)
        self.definition_result = QLabel(
            'Updates are manual. No publisher key or remote update server is configured by default.',
            objectName='small',
        )
        self.definition_result.setWordWrap(True)
        layout.addWidget(self.definition_result)
        note = QLabel(
            'Recent imports never remove hashes just because they are absent. Explicit corrections can revoke hashes.\nChanges apply to new scans; restart monitoring to load the new snapshot.',
            objectName='small',
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch()
        tabs.addTab(page, 'Definitions')
        self.refresh_definition_health()

    def refresh_definition_health(self):
        """Show the hash-database size, age and source, plus the status of every extra signature layer."""
        from sentinelav.ui.application import ROOT

        try:
            from sentinelav.detection.definition_paths import signature_data_dir

            metadata = load_active(signature_data_dir(ROOT))
            state, hours = freshness(metadata)
            age = f'{hours:g} hours' if hours is not None else 'unknown'
            self.definition_health.setText(
                f"{metadata['unique_sha256']:,} full-feed hashes · {state} · import age: {age}\n"
                f"Source: {metadata.get('source','Unknown')} · {metadata.get('update_method','Manual full export import')}\n"
                'Signed publisher: '
                + (
                    'configured'
                    if read_json(ROOT / 'trusted-update-keys.json').get('keys')
                    else 'not configured'
                )
                + '\n'
                + layer_status()
            )
        except Exception as error:
            self.definition_health.setText('Definition status unavailable: ' + str(error))

    def begin_definition_update(self, kind):
        """Ask for the update file if needed and run the update in a DefinitionWorker."""
        if (
            self.definition_worker
            or self.worker
            or self.response_worker
            or self.lab_worker
            or self.preferences_worker
        ):
            self.definition_result.setText(
                'Finish the current scan, response, lab, or settings operation first.'
            )
            return
        path = None
        if kind not in ('rollback', 'clamav'):
            filters = {
                'recent': 'CSV files (*.csv)',
                'full': 'ZIP archives (*.zip)',
                'signed': 'Signed update packages (*.zip)',
                'corrections': 'Reviewed corrections (*.json)',
            }
            path, _ = QFileDialog.getOpenFileName(
                self, 'Select definition update', filter=filters[kind]
            )
            if not path:
                return
        from sentinelav.ui.application import ROOT

        self.definition_worker = DefinitionWorker(ROOT, kind, path)
        self.definition_worker.completed.connect(self.definition_update_done)
        self.definition_worker.failed.connect(
            lambda error: self.definition_result.setText(
                'Update failed; active definitions were preserved. ' + error
            )
        )
        self.definition_worker.progress.connect(self.definition_result.setText)
        self.definition_worker.finished.connect(self.definition_update_finished)
        for button in self.definition_buttons:
            button.setEnabled(False)
        self.definition_result.setText('Validating and preparing definition snapshot…')
        self.definition_worker.start()

    def definition_update_done(self, metadata):
        """Refresh the status and report what was activated."""
        self.refresh_definition_health()
        if 'clamav' in metadata:
            files = ', '.join(item['name'] for item in metadata['clamav']['files'])
            self.definition_result.setText(
                f'ClamAV signatures updated ({files}). New scans use them.'
            )
            return
        self.definition_result.setText(
            f"Activated {metadata['unique_sha256']:,} full-feed hashes. New scans use this version; restart monitoring to reload. Prior snapshot retained for rollback."
        )
        try:
            import time

            self.store.save_event(
                dict(
                    time=time.strftime('%Y-%m-%d %H:%M:%S'),
                    kind='Definitions updated',
                    details=metadata.get('update_method', 'Manual full CSV import')
                    + ' · '
                    + metadata['database'],
                    source='Definitions',
                    level='Info',
                )
            )
        except Exception:
            self.definition_result.setText(
                self.definition_result.text() + ' Local audit recording failed.'
            )

    def definition_update_finished(self):
        """Tidy up after the update worker and re-enable the buttons."""
        self.definition_worker.deleteLater()
        self.definition_worker = None
        for button in self.definition_buttons:
            button.setEnabled(True)

    def ready_for_response(self):
        """Block response actions during a definition update."""
        if self.definition_worker:
            self.response_status.setText('Wait for the definition update to finish.')
            return False
        return super().ready_for_response()

    def start_scan(self, roots, kind):
        """Block scans during a definition update."""
        if self.definition_worker:
            self.statusBar().showMessage('Wait for the definition update to finish.', 5000)
            return
        super().start_scan(roots, kind)

    def begin_protection(self):
        """Block starting protection during a definition update."""
        if self.definition_worker:
            self.statusBar().showMessage('Wait for the definition update to finish.', 5000)
            return
        super().begin_protection()

    def start_lab(self):
        """Block lab runs during a definition update."""
        if self.definition_worker:
            self.lab_note.setText('Wait for the definition update to finish.')
            return
        super().start_lab()

    def check_schedule(self):
        """Skip scheduled scans during a definition update."""
        if not self.definition_worker:
            super().check_schedule()

    def closeEvent(self, event):
        """Cancel a running import and close once it has stopped."""
        if self.definition_worker:
            self.definition_worker.cancelled.set()
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        super().closeEvent(event)

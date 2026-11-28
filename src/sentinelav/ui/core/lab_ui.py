# Purpose: Safe simulations plus a separately confirmed, offline guest-only runtime path.
# Works with: lab.lab, ui.application, ui.design, ui.helpers.lab_pages, ui.helpers.lab_ui_workers
# Used by: ui.application

"""Safe simulations plus a separately confirmed, offline guest-only runtime path."""

import json
import threading
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QTimer, Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTabWidget,
    QTableWidgetItem,
    QFileDialog,
    QMessageBox,
    QPushButton,
    QHeaderView,
)
from sentinelav.lab.lab import PROFILES, SimulationRunner, capabilities
from sentinelav.ui.design import icon


from ..helpers.lab_ui_workers import LabWorker, CapabilityWorker
from ..helpers.lab_pages import LabPagesMixin


class LabMixin(LabPagesMixin):
    """Runs the safe lab simulations and shows their results."""

    def start_lab(self):
        """Start the selected safe simulation profiles in a background worker (only when nothing else
        is running).
        """
        if getattr(self, 'runtime_worker', None):
            self.lab_note.setText('Wait for the guest runtime job and disposal to finish.')
            return
        if self.lab_worker or self.worker or self.response_worker or self.preferences_worker:
            self.lab_note.setText(
                'Finish the current scan or response/settings operation before starting a lab run.'
            )
            return
        profiles = [
            self.lab_queue.item(row, 0).data(Qt.ItemDataRole.UserRole)
            for row in range(self.lab_queue.rowCount())
            if self.lab_queue.item(row, 0).checkState() == Qt.CheckState.Checked
        ]
        if not profiles:
            self.lab_tabs.setCurrentIndex(1)
            self.lab_note.setText('Select at least one harmless test in Test Queue.')
            return
        from sentinelav.ui.application import ROOT

        self.lab_activity = []
        self.lab_activity_table.setRowCount(0)
        self.lab_state.setText('Running safe simulations')
        self.lab_note.setText(
            'Generated fixtures only. No VM, sample execution, or real network traffic.'
        )
        self.lab_start.setEnabled(False)
        self.lab_queue.setEnabled(False)
        self.lab_stop.setEnabled(True)
        self.lab_tabs.setCurrentIndex(2)
        self.lab_worker = LabWorker(ROOT, self.store.path.parent / 'lab-workspaces', profiles)
        self.lab_worker.activity.connect(self.lab_activity_event)
        self.lab_worker.completed.connect(self.lab_completed)
        self.lab_worker.failed.connect(self.lab_failed)
        self.lab_worker.finished.connect(self.lab_finished)
        self.lab_worker.start()

    def stop_lab(self):
        """Ask the running simulation to stop and clean up its temporary files."""
        if self.lab_worker:
            self.lab_worker.runner.stop.set()
            self.lab_stop.setEnabled(False)
            self.lab_state.setText('Stopping and cleaning temporary fixtures…')

    def lab_activity_event(self, event):
        """Add one live activity line to the Live Activity table (keeping the last 200)."""
        self.lab_activity.append(event)
        self.lab_activity = self.lab_activity[-200:]
        self.fill(
            self.lab_activity_table,
            [(e['time'], e['kind'], e['details']) for e in self.lab_activity],
        )

    def lab_completed(self, run):
        """Save the finished run, log it, and show whether fixture cleanup succeeded (failed cleanup
        blocks further runs).
        """
        self.store.save_lab_run(run)
        self.audit_response(
            'Safe lab simulation completed',
            f"{run['id']}: {run['status']}; fixture cleanup: {run['workspace_reset']}",
        )
        self.lab_state.setText('Simulation: ' + run['status'])
        self.lab_cleanup_ok = run['workspace_reset']
        self.lab_note.setText(
            (
                'Fixture cleanup verified. '
                if run['workspace_reset']
                else 'Fixture cleanup failed; further runs are blocked. '
            )
            + run.get(
                'error',
                'Results are simulation evidence, not a malware-detection or containment certification.',
            )
        )
        self.refresh_lab_results()
        self.lab_tabs.setCurrentIndex(3)

    def lab_failed(self, error):
        """Show why the simulation could not start."""
        self.lab_state.setText('Simulation could not start')
        self.lab_note.setText(error)

    def lab_finished(self):
        """Tidy up after the lab worker and restore the controls."""
        self.lab_worker.deleteLater()
        self.lab_worker = None
        self.lab_stop.setEnabled(False)
        self.lab_queue.setEnabled(True)
        self.lab_start.setEnabled(self.lab_cleanup_ok)

    def refresh_lab_results(self):
        """Reload the saved lab runs into the Results table."""
        self.lab_runs = self.store.lab_runs()
        self.fill(
            self.lab_results_table,
            [
                (
                    r['date'],
                    len(r['profiles']),
                    r['status'],
                    'Verified' if r['workspace_reset'] else 'Failed',
                )
                for r in self.lab_runs
            ],
        )

    def selected_lab_run(self, row=None):
        """Return the selected (or given) saved run, or None with a hint if nothing is selected."""
        row = self.lab_results_table.currentRow() if row is None or isinstance(row, bool) else row
        if row < 0 or row >= len(self.lab_runs):
            self.lab_note.setText('Select a saved simulation result first.')
            return None
        return self.lab_runs[row]

    def show_lab_result(self, row=None, column=None):
        """Show the full evidence of a saved run in a dialog."""
        run = self.selected_lab_run(row)
        if run:
            box = QMessageBox(self)
            box.setWindowTitle('Safe simulation evidence')
            box.setText(run['status'] + ' · local simulation, no VM execution')
            box.setDetailedText(json.dumps(run, indent=2)[:512000])
            box.exec()

    def export_lab_result(self):
        """Save the selected run's evidence as a JSON file."""
        run = self.selected_lab_run()
        if not run:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            'Export safe simulation evidence',
            'sentinelav-lab-' + run['id'] + '.json',
            'JSON (*.json)',
        )
        if path:
            try:
                Path(path).write_text(json.dumps(run, indent=2), encoding='utf-8')
            except OSError as error:
                self.lab_note.setText('Export failed: ' + str(error))

    def ready_for_response(self):
        """Block response actions while a lab job is running."""
        if self.lab_worker or getattr(self, 'runtime_worker', None):
            self.response_status.setText('Finish or stop the safe simulation first.')
            return False
        return super().ready_for_response()

    def start_scan(self, roots, kind):
        """Block scans while a lab job is running."""
        if self.lab_worker or getattr(self, 'runtime_worker', None):
            self.navigate(6)
            self.lab_note.setText('Finish or stop the current lab simulation before scanning.')
            return
        super().start_scan(roots, kind)

    def check_schedule(self):
        """Skip scheduled scans while a lab job is running."""
        if not self.lab_worker and not getattr(self, 'runtime_worker', None):
            super().check_schedule()

    def closeEvent(self, event):
        """Wait for lab jobs (including guest disposal) to finish before closing."""
        if getattr(self, 'runtime_worker', None):
            self.runtime_note.setText(
                'Waiting for the owned runtime controller to finish guest disposal before closing…'
            )
            event.ignore()
            QTimer.singleShot(250, self.close)
            return
        if self.lab_worker or self.capability_worker:
            self.stop_lab()
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        super().closeEvent(event)

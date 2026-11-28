# Purpose: Honest layer status, bounded manual inspection, and opt-in response policy.
# Works with: detection.inspection, detection.preexecution, platform.windows_service, ui.application,
#   ui.helpers.defense_pages
# Used by: ui.application

"""Honest layer status, bounded manual inspection, and opt-in response policy."""

import json
import os
from pathlib import Path
import re
import psutil
from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTabWidget,
    QCheckBox,
    QPlainTextEdit,
    QFileDialog,
    QInputDialog,
    QMessageBox,
    QHeaderView,
    QLineEdit,
    QScrollArea,
)
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.detection.preexecution import verdict
from sentinelav.platform.windows_service import read_health


from ..helpers.defense_ui_workers import InspectionWorker
from ..helpers.defense_pages import DefensePagesMixin
from ..helpers.defense_settings import DefenseSettingsMixin


class DefenseMixin(DefensePagesMixin, DefenseSettingsMixin):
    """Everything on the Defense tab: page layout, settings, and the manual memory and pre-execution
    inspections.
    """

    def begin_bounded_inspection(self, kind):
        """Start a manual inspection: kind 'memory' asks for a process id, 'file' asks for a file to
        check before running it.
        """
        if self.inspection_worker or self.worker or self.response_worker or self.definition_worker:
            self.inspection_note.setText(
                'Wait for the active scan/update/response operation first.'
            )
            return
        if kind == 'memory':
            pid, okay = QInputDialog.getInt(
                self,
                'Read-only process inspection',
                'PID owned by your Windows account:',
                os.getpid(),
                5,
                2**31 - 1,
            )
            if not okay:
                return
            try:
                target = (pid, psutil.Process(pid).create_time())
            except psutil.Error as error:
                self.inspection_note.setText(str(error))
                return
        else:
            target, _ = QFileDialog.getOpenFileName(self, 'Inspect file without executing it')
            if not target:
                return
        from sentinelav.ui.application import ROOT

        self.last_inspection = None
        self.inspection_worker = InspectionWorker(
            ROOT, kind, target, self.store.get('inspection_options', {})
        )
        self.inspection_worker.completed.connect(self.bounded_inspection_done)
        self.inspection_worker.failed.connect(
            lambda error: self.inspection_note.setText('Inspection failed / incomplete: ' + error)
        )
        self.inspection_worker.finished.connect(self.bounded_inspection_finished)
        self.memory_button.setEnabled(False)
        self.prelaunch_button.setEnabled(False)
        self.inspection_note.setText('Read-only inspection running in a limited worker…')
        self.inspection_worker.start()

    def bounded_inspection_done(self, result):
        """Show the inspection result, save it to history and the activity log."""
        self.last_inspection = result
        if 'verdict' in result:
            message = (
                result['verdict']['decision']
                + ' — '
                + result['verdict']['reason']
                + '. No file was launched.'
            )
        elif result.get('status') == 'Cancelled':
            message = 'Inspection cancelled; coverage is incomplete.'
        else:
            message = f"Read {result.get('bytes',0):,} bytes across {result.get('regions',0)} executable regions; {len(result.get('findings_requiring_review',[]))} findings; {len(result.get('omissions',[]))} omissions. Review details."
        self.inspection_note.setText(message)
        try:
            import time

            if 'scan' in result:
                report = dict(
                    result['scan'],
                    kind='Manual pre-execution check',
                    guard_decision=result['verdict'],
                )
                if (
                    result['verdict']['decision'] == 'Indeterminate'
                    and report['status'] == 'Complete'
                ):
                    report['status'] = 'Complete with omissions'
                    report['errors'] = list(report['errors']) + [result['verdict']['reason']]
                self.store.save_scan(report)
            self.store.save_event(
                dict(
                    time=time.strftime('%Y-%m-%d %H:%M:%S'),
                    kind='Manual inspection completed',
                    details=message,
                    source='Manual inspection',
                    level='Info',
                    pid=result.get('pid'),
                )
            )
            self.refresh()
        except Exception:
            self.inspection_note.setText(message + ' Audit recording failed.')

    def bounded_inspection_finished(self):
        """Tidy up after an inspection and re-enable its buttons."""
        self.inspection_worker.deleteLater()
        self.inspection_worker = None
        self.memory_button.setEnabled(True)
        self.prelaunch_button.setEnabled(True)

    def show_inspection_details(self):
        """Show the full JSON result of the last inspection."""
        if self.last_inspection:
            box = QMessageBox(self)
            box.setWindowTitle('Bounded inspection result')
            box.setText(self.inspection_note.text())
            box.setDetailedText(json.dumps(self.last_inspection, indent=2))
            box.exec()

    def receive_status(self, state):
        """Remember the latest protection status so the Layers table can describe it."""
        self.last_protection_state = dict(state)
        super().receive_status(state)

    def ready_for_response(self):
        """Block response actions while a manual inspection is running."""
        if self.inspection_worker:
            self.response_status.setText('Wait for the manual inspection to finish.')
            return False
        return super().ready_for_response()

    def protection_finished(self):
        """Forget the protection status when monitoring stops and refresh the Layers table."""
        self.last_protection_state = {}
        super().protection_finished()
        self.refresh_defense_layers()

    def navigate(self, index):
        """Refresh the Layers table whenever the Settings page is opened."""
        super().navigate(index)
        if index == 5 and hasattr(self, 'layer_table'):
            self.refresh_defense_layers()

    def closeEvent(self, event):
        """Interrupt a running inspection and close once it has stopped."""
        if self.inspection_worker:
            self.inspection_worker.requestInterruption()
            event.ignore()
            QTimer.singleShot(100, self.close)
            return
        super().closeEvent(event)

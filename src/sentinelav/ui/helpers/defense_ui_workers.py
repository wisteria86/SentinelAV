# Purpose: Honest layer status, bounded manual inspection, and opt-in response policy.
# Works with: detection.inspection, detection.preexecution
# Used by: ui.core.defense_ui

"""Honest layer status, bounded manual inspection, and opt-in response policy."""

from PySide6.QtCore import QThread, Signal
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.detection.preexecution import verdict


class InspectionWorker(QThread):
    """Background thread for a manual memory inspection or pre-execution file check."""

    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, root, kind, target, options):
        """kind is 'memory' (target is (pid, start time)) or 'file' (target is a path)."""
        super().__init__()
        self.root = root
        self.kind = kind
        self.target = target
        self.options = options

    def run(self):
        """Run the inspection in an isolated scanner and emit completed(result) or failed(message)."""
        scanner = None
        try:
            scanner = IsolatedScanner(
                self.root / 'signatures.json', self.root / 'rules', options=self.options
            )
            if self.kind == 'memory':
                pid, creation = self.target
                result = scanner.scan_memory(pid, creation, self.isInterruptionRequested)
            else:
                report = scanner.scan([self.target], self.isInterruptionRequested, lambda *a: None)
                result = dict(
                    scope='Manual pre-execution inspection; no file was launched',
                    verdict=verdict(self.target, report),
                    scan=report,
                )
            self.completed.emit(result)
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            if scanner:
                scanner.close()

# Purpose: Run isolated scanning off the GUI thread and emit Qt signals.
# Works with: detection.inspection, paths
# Used by: ui.application, ui.scan_actions

from sentinelav.paths import RESOURCE_ROOT
import time
from PySide6.QtCore import QThread, Signal
from sentinelav.detection.inspection import IsolatedScanner as Scanner

ROOT = RESOURCE_ROOT


class ScanWorker(QThread):
    """Background thread that runs one scan so the window stays responsive.

    It emits progress(path, scanned, threats) at most ten times a second, then completed(result) or
    failed(message).
    """

    progress = Signal(str, int, int)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(
        self, roots, max_mb, exclusions, trusted_hashes=(), options=None, resource_root=None
    ):
        """Remember what to scan and with which settings."""
        super().__init__()
        self.roots = roots
        self.max_mb = max_mb
        self.exclusions = exclusions
        self.trusted_hashes = trusted_hashes
        self.options = options
        self.resource_root = resource_root or ROOT

    def run(self):
        """Run the scan on this thread, stopping early if interruption is requested."""
        try:
            engine = Scanner(
                self.resource_root / 'signatures.json',
                self.resource_root / 'rules',
                self.max_mb,
                self.exclusions,
                self.trusted_hashes,
                self.options,
            )
            last = [0.0]

            def report(path, scanned, threats):
                """Forward progress to the window, throttled to every 0.1 seconds."""
                if time.monotonic() - last[0] > 0.1:
                    self.progress.emit(path, scanned, threats)
                    last[0] = time.monotonic()

            self.completed.emit(engine.scan(self.roots, self.isInterruptionRequested, report))
        except Exception as error:
            self.failed.emit(str(error))

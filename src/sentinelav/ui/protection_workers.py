# Purpose: Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread.
# Works with: monitoring.monitoring
# Used by: ui.protection

"""Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread."""

from PySide6.QtCore import QThread, Signal
from sentinelav.monitoring.monitoring import Monitor


class ProtectionWorker(QThread):
    """Background thread that runs the Monitor inside the window's process."""

    event = Signal(dict)
    status = Signal(dict)
    failed = Signal(str)

    def __init__(self, config):
        """Create the Monitor, wired to emit events and status as Qt signals."""
        super().__init__()
        self.monitor = Monitor(config, self.event.emit, self.status.emit)

    def run(self):
        """Run the monitor until it stops, emitting failed(message) if it crashes."""
        try:
            self.monitor.run()
        except Exception as error:
            self.failed.emit(str(error))

    def stop(self):
        """Ask the monitor to stop."""
        self.monitor.stop.set()

# Purpose: Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread.
# Works with: monitoring.monitoring
# Used by: ui.protection

"""Phase 3 UI and Qt adapter. SQLite is only touched on the GUI thread."""
from PySide6.QtCore import QThread, Signal
from sentinelav.monitoring.monitoring import Monitor


class ProtectionWorker(QThread):
    event = Signal(dict)
    status = Signal(dict)
    failed = Signal(str)

    def __init__(self, config):
        super().__init__()
        self.monitor = Monitor(config, self.event.emit, self.status.emit)

    def run(self):
        try:
            self.monitor.run()
        except Exception as error:
            self.failed.emit(str(error))

    def stop(self):
        self.monitor.stop.set()

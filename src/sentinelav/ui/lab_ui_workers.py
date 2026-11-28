# Purpose: Safe simulations plus a separately confirmed, offline guest-only runtime path.
# Works with: lab.lab
# Used by: ui.lab_pages, ui.lab_ui

"""Safe simulations plus a separately confirmed, offline guest-only runtime path."""

from PySide6.QtCore import QThread, Signal
from sentinelav.lab.lab import SimulationRunner, capabilities


class LabWorker(QThread):
    """Background thread that runs the safe simulation profiles."""

    activity = Signal(dict)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, root, workspace, profiles):
        """Prepare a SimulationRunner whose activity events are forwarded to the window."""
        super().__init__()
        self.runner = SimulationRunner(root, workspace, self.activity.emit)
        self.profiles = profiles

    def run(self):
        """Run the profiles and emit completed(run) or failed(message)."""
        try:
            self.completed.emit(self.runner.run(self.profiles))
        except Exception as error:
            self.failed.emit(str(error))


class CapabilityWorker(QThread):
    """Background thread that checks which virtualisation tools are available."""

    completed = Signal(dict)

    def run(self):
        """Run the check and emit the result."""
        self.completed.emit(capabilities())

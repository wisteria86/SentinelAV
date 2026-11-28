# Purpose: Qt adapter for the optional independent, current-user engine.
# Works with: monitoring.background
# Used by: ui.protection, tests.unit.test_background

"""Qt adapter for the optional independent, current-user engine."""

import threading
import time
from PySide6.QtCore import QThread, Signal
from sentinelav.monitoring.background import launch, request


class BackgroundWorker(QThread):
    """Background thread that connects the window to the separate background engine and relays its
    events and status.
    """

    event = Signal(dict)
    status = Signal(dict)
    failed = Signal(str)

    def __init__(self, data, attach_only=False):
        """attach_only=True only connects to an engine that is already running instead of starting one."""
        super().__init__()
        self.data = data
        self.attach_only = attach_only
        self.disconnect = threading.Event()
        self.stop_engine = threading.Event()

    def stop(self):
        """Ask the engine to stop monitoring (the loop then shuts it down)."""
        self.stop_engine.set()

    def detach(self):
        """Stop relaying without stopping the engine (protection keeps running in the background)."""
        self.disconnect.set()

    def run(self):
        """Poll the engine for new events and status until detached or the engine stops.

        After an explicit stop, the engine process is also shut down, so the next start loads fresh
        code and detection data.
        """
        try:
            if self.attach_only:
                try:
                    initial = request(self.data, 'status')
                except ConnectionError:
                    return
                if initial['state'] == 'Failed':
                    self.failed.emit(initial['error'] or 'Background monitoring failed')
                    return
                if initial['state'] not in ('Starting', 'Active', 'Stopping'):
                    return
            else:
                initial = self.connect_and_start()
                if initial is None:
                    return
            epoch = initial['epoch']
            cursor = initial['cursor']
            stopping = False
            while not self.disconnect.is_set():
                if self.stop_engine.is_set() and not stopping:
                    request(self.data, 'stop')
                    stopping = True
                reply = request(self.data, 'poll', epoch=epoch, cursor=cursor)
                epoch = reply['epoch']
                cursor = reply['cursor']
                if reply['gap']:
                    self.failed.emit(
                        'Live event delivery fell behind. Review persisted protection events in Reports.'
                    )
                for entry in reply['events']:
                    self.event.emit(dict(entry['event'], _background_persisted=True))
                if reply['state'] == 'Active' and reply['stats']:
                    self.status.emit(
                        dict(
                            reply['stats'],
                            background=True,
                            engine_error=reply['error'],
                            dropped=reply['dropped'],
                        )
                    )
                if reply['state'] in ('Failed', 'Off'):
                    if reply['error']:
                        self.failed.emit(reply['error'])
                    if stopping:
                        # Release the helper after explicit Stop so the next
                        # start loads updated engine code and detection data.
                        request(self.data, 'shutdown')
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            try:
                                request(self.data, 'status')
                            except ConnectionError:
                                break
                            except RuntimeError:
                                pass  # Server acknowledged shutdown but is draining.
                            self.disconnect.wait(0.1)
                        else:
                            raise RuntimeError('Stopped engine did not finish shutdown')
                    return
                self.disconnect.wait(0.4)
        except Exception as error:
            self.failed.emit('Engine disconnected; protection status is unknown. ' + str(error))

    def connect_and_start(self):
        """Make sure the engine is running (launching it if needed, waiting up to 10 seconds) and ask
        it to start monitoring.
        """
        try:
            request(self.data, 'status')
        except ConnectionError:
            launch(self.data)
            deadline = time.monotonic() + 10
            while True:
                if self.disconnect.is_set():
                    return
                try:
                    request(self.data, 'status')
                    break
                except ConnectionError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            'Background engine did not start. Use a non-administrator Windows session.'
                        )
                    self.disconnect.wait(0.2)
        if not self.disconnect.is_set():
            return request(self.data, 'start')

# Purpose: Give the harmless ETW fixture a dedicated, stable writer process.
# Works with: lab.qualification.guest_telemetry, lab.qualification.telemetry

import os
import subprocess
import time
import uuid


class ProbeWriter:
    """Controls a helper process that writes one known file on demand, so ETW collection can be checked
    against a write we know happened.
    """
    def __init__(self, root, collector):
        """Start the collector in probe-writer mode and wait until it says it is ready."""
        self.path = root / ('SentinelAVLabProbe-' + uuid.uuid4().hex + '.txt')
        self.ready = self.path.with_suffix('.ready')
        self.start = self.path.with_suffix('.start')
        self.stop = self.path.with_suffix('.stop')
        env = dict(os.environ, SENTINELAV_PROBE_FILE=str(self.path))
        self.process = subprocess.Popen([str(collector), '--lab-probe-writer'],
                                        env=env, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            self.wait_for(self.ready)
        except BaseException:
            self.close()
            raise

    def wait_for(self, path):
        """Wait up to 10 seconds for a signal file to appear, failing if the helper exits."""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('Dedicated ETW probe writer exited')
            if path.exists():
                return
            time.sleep(.05)
        raise TimeoutError('Dedicated ETW probe writer did not reach ' + path.suffix)

    def write(self):
        """Ask the helper to write the probe file and wait until it exists."""
        self.start.touch(exist_ok=False)
        self.wait_for(self.path)

    def close(self):
        """Stop the helper and delete all its signal files."""
        try:
            if self.process.poll() is None:
                self.stop.touch(exist_ok=True)
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            for path in (self.path, self.ready, self.start, self.stop):
                path.unlink(missing_ok=True)

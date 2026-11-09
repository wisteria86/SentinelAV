# Purpose: Give the harmless ETW fixture a dedicated, stable writer process.
# Works with: lab.qualification.guest_telemetry, lab.qualification.telemetry

import os
import subprocess
import time
import uuid


class ProbeWriter:
    def __init__(self, root, collector):
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
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('Dedicated ETW probe writer exited')
            if path.exists():
                return
            time.sleep(.05)
        raise TimeoutError('Dedicated ETW probe writer did not reach ' + path.suffix)

    def write(self):
        self.start.touch(exist_ok=False)
        self.wait_for(self.path)

    def close(self):
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

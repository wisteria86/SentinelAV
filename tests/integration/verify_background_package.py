# Purpose: Validate the frozen engine with harmless fixtures and no installation.
# Works with: data.storage, monitoring.background
# Used by: unittest discovery

"""Validate the frozen engine with harmless fixtures and no installation."""

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path
from PySide6.QtCore import QCoreApplication
from PySide6.QtNetwork import QLocalSocket
from sentinelav.monitoring.background import request, endpoint
from sentinelav.data.storage import Store

parser = argparse.ArgumentParser()
parser.add_argument('executable', type=Path)
args = parser.parse_args()
app = QCoreApplication([])


def wait(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except ConnectionError:
            pass
        time.sleep(0.05)
    raise AssertionError('Packaged background engine timed out')


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    data = root / 'state'
    watched = root / 'watched'
    watched.mkdir()
    store = Store(data / 'sentinelav.db')
    store.set('watch_folders', [str(watched)])
    for key in ('processes', 'sysmon', 'behavior', 'network'):
        store.set('watch_' + key, False)
    process = subprocess.Popen(
        [str(args.executable.resolve()), '--engine-host', '--data-dir', str(data)],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        wait(lambda: request(data, 'status')['state'] == 'Off')
        # A malformed request reaches the actual server, bypassing client-side validation.
        sock = QLocalSocket()
        sock.connectToServer(endpoint(data))
        assert sock.waitForConnected(1500)
        sock.write(b'{"version":1,"command":"execute","path":"unused"}\n')
        sock.flush()
        assert sock.waitForReadyRead(3000)
        assert not json.loads(bytes(sock.readAll()))['ok']
        sock.abort()
        request(data, 'start')
        wait(lambda: request(data, 'status')['state'] == 'Active')
        request(data, 'start')  # Idempotent; must not start a second monitor.
        marker = watched / 'harmless-packaged-marker.txt'
        marker.write_text('SENTINELAV_DEMO_THREAT_7C23A')
        wait(lambda: any(e['level'] == 'Alert' for e in store.events()))
        assert len([e for e in store.events() if e['level'] == 'Alert']) == 1
        assert marker.exists()
        request(data, 'stop')
        wait(lambda: request(data, 'status')['state'] == 'Off')
        request(data, 'shutdown')
        assert process.wait(timeout=15) == 0
    finally:
        if process.poll() is None:
            try:
                request(data, 'shutdown')
            except (ConnectionError, RuntimeError):
                pass
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.terminate()  # Only the helper process created by this test.
                process.wait(timeout=5)
        store.db.close()
print(
    'PASS: packaged background engine, server-side RPC rejection, fixture detection, idempotent start, stop/shutdown'
)

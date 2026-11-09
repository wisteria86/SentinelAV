# Purpose: Per-user background engine. Local JSON IPC; never an elevated service.
# Works with: data.storage, monitoring.agent_protocol, monitoring.monitoring, paths
# Used by: entrypoint, lab.qualification.guest_lifecycle, lab.qualification.guest_support,
#   lab.qualification.guest_telemetry

"""Per-user background engine. Local JSON IPC; never an elevated service.

The pipe ACL is restricted to the current user by Qt. This does not defend
against malicious code already running as that user. No remote commands,
arbitrary code execution, or automatic response actions are exposed.
"""
from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid
from collections import deque

from PySide6.QtCore import QCoreApplication, QLockFile, QObject, QTimer
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from sentinelav.monitoring.monitoring import Monitor
from sentinelav.data.storage import Store

MAX_MESSAGE = 128 * 1024
COMMANDS = {'status', 'start', 'stop', 'poll', 'shutdown'}


from .agent_protocol import endpoint, decode, request, configuration, launch


class EngineHost(QObject):
    def __init__(self, data, root, monitor_factory=Monitor):
        super().__init__()
        self.data, self.root = Path(data), Path(root)
        self.store = Store(self.data/'sentinelav.db')
        self.factory = monitor_factory
        self.monitor = self.thread = None
        self.state, self.error, self.stats = 'Off', '', {}
        self.epoch, self.sequence = uuid.uuid4().hex, 0
        self.events = deque(maxlen=2000 if self.store.get('evaluation_attestation',False) is True else 200)
        self.inbox = queue.Queue(maxsize=2048)
        self.dropped = 0
        self.quitting = False
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        self.server.setMaxPendingConnections(8)
        if not self.server.listen(endpoint(data)):
            self.store.db.close()
            raise RuntimeError('Cannot own engine endpoint: ' + self.server.errorString())
        self.server.newConnection.connect(self.accept)
        self.clients = set()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(100)

    def publish(self, kind, value):
        try:
            self.inbox.put_nowait((kind, value))
        except queue.Full:
            self.dropped += 1

    def start(self):
        if self.thread and self.thread.is_alive():
            if self.state == 'Stopping':
                raise ValueError('Wait for monitoring to stop')
            return
        config = configuration(self.store, self.root)
        self.monitor = self.factory(config, lambda e: self.publish('event', e), lambda s: self.publish('status', s))
        self.state, self.error = 'Starting', ''
        def run():
            try:
                self.monitor.run()
            except Exception as error:
                self.publish('error', str(error))
        self.thread = threading.Thread(target=run, name='SentinelAV-monitor')
        self.thread.start()

    def stop(self):
        if self.thread and self.thread.is_alive():
            self.state = 'Stopping'
            self.monitor.stop.set()

    def tick(self):
        for _ in range(200):
            try:
                kind, value = self.inbox.get_nowait()
            except queue.Empty:
                break
            if kind == 'status':
                self.stats = value
                if self.state != 'Stopping':
                    self.state = 'Active'
            elif kind == 'error':
                self.error = value
                self.state = 'Failed'
            else:
                try:
                    self.store.save_event(value)
                except Exception as error:
                    self.error = 'Event persistence failed: ' + str(error)
                self.sequence += 1
                self.events.append((self.sequence, value))
        if self.thread and not self.thread.is_alive() and self.inbox.empty():
            self.thread = self.monitor = None
            self.state = 'Failed' if self.error else 'Off'
        if self.quitting and self.thread is None:
            self.server.close()
            for client in list(self.clients):
                client.abort()
            self.store.db.close()
            self.timer.stop()
            QCoreApplication.instance().quit()

    def handle(self, message):
        command = message['command']
        if self.quitting:
            raise ValueError('Engine is shutting down')
        if command == 'start':
            self.start()
        elif command == 'stop':
            self.stop()
        elif command == 'shutdown':
            self.stop()
            self.quitting = True
        cursor = message.get('cursor', self.sequence)
        epoch_changed = message.get('epoch', '') != self.epoch
        if epoch_changed:
            cursor = 0
        events = [(n, e) for n, e in self.events if n > cursor] if command == 'poll' else []
        # Bound each response independently of telemetry size. Cursor advances
        # only through records actually returned; clients can drain later pages.
        selected = []
        for n, event in events:
            candidate = selected + [dict(sequence=n, event=event)]
            if len(json.dumps(candidate).encode()) > MAX_MESSAGE // 2:
                break
            selected = candidate
        return dict(version=1, ok=True, state=self.state, error=self.error, stats=self.stats,
                    epoch=self.epoch, cursor=selected[-1]['sequence'] if selected else self.sequence,
                    events=selected, gap=bool(command == 'poll' and self.events and cursor < self.events[0][0]-1),
                    dropped=self.dropped, background=True, elevated_service=False)

    def accept(self):
        while self.server.hasPendingConnections():
            sock = self.server.nextPendingConnection()
            if len(self.clients) >= 8:
                sock.abort()
                sock.deleteLater()
                continue
            self.clients.add(sock)
            sock.setReadBufferSize(MAX_MESSAGE + 1)
            timer = QTimer(sock)
            timer.setSingleShot(True)
            timer.timeout.connect(sock.abort)
            timer.start(3000)
            buffer = bytearray()
            def read(sock=sock, buffer=buffer):
                buffer.extend(bytes(sock.readAll()))
                if len(buffer) > MAX_MESSAGE:
                    sock.abort()
                    return
                if b'\n' not in buffer:
                    return
                try:
                    raw, trailing = bytes(buffer).split(b'\n', 1)
                    if trailing:
                        raise ValueError('One request per connection')
                    reply = self.handle(decode(raw))
                except Exception as error:
                    reply = dict(version=1, ok=False, error=str(error)[:1000])
                sock.write(json.dumps(reply).encode() + b'\n')
                sock.disconnectFromServer()
            def cleanup(sock=sock):
                self.clients.discard(sock)
                sock.deleteLater()
            sock.readyRead.connect(read)
            sock.disconnected.connect(cleanup)
            if sock.bytesAvailable():
                read()


def main(data):
    # Do not turn per-user, user-writable code/config into an elevated broker.
    if os.name != 'nt':
        raise RuntimeError('Background engine currently supports Windows only')
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('Run the per-user background engine without administrator elevation')
    data = Path(data).absolute()
    for part in [data, *data.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError('Engine data path cannot contain links')
    data.mkdir(parents=True, exist_ok=True)
    app = QCoreApplication(sys.argv[:1])
    lock = QLockFile(str(data/'sentinelav.detection.engine.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        return 0
    try:
        host = EngineHost(data, RESOURCE_ROOT)
        return app.exec()
    except Exception as error:
        (data/'engine-startup-error.json').write_text(json.dumps(dict(error=type(error).__name__,reason=str(error)[:2000])),encoding='utf-8')
        return 1
    finally:
        lock.unlock()

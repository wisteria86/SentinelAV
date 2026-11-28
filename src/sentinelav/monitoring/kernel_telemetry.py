# Purpose: Optional protected ETW collector. Permission failure never implies coverage.
# Works with: platform.integrity
# Used by: lab.qualification.telemetry, monitoring.monitor_loop

"""Optional protected ETW collector. Permission failure never implies coverage."""

import json
import ctypes
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time
import psutil
from sentinelav.platform.integrity import verify_windows_acl


class KernelFileEvents:
    """Receives file-write events from the kernel (ETW) through a small native collector program.

    The collector must live under Program Files with locked-down permissions, so ordinary users
    cannot swap it out. Every event names the writing process; we verify that process by id and
    exact start time before trusting it.
    """

    def __init__(self, executable, probe_pid=None):
        """Check the collector's location and permissions, map device names to drive letters, and start
        the collector with a reader thread.
        """
        path = Path(executable).resolve()
        program_files = Path(os.environ.get('ProgramFiles', 'C:/Program Files')).resolve()
        if not path.is_relative_to(program_files):
            raise ValueError('ETW collector must be deployed under protected Program Files')
        verify_windows_acl(path)
        for parent in path.parents:
            if parent == program_files:
                break
            verify_windows_acl(parent)
        self.queue = queue.Queue(maxsize=1024)
        self.ready = False
        self.error = ''
        self.dropped = 0
        self.native_dropped = 0
        self.etw_lost = 0
        self.last_heartbeat = 0
        self.unresolved_paths = 0
        self.unresolved_identities = 0
        self.outside_probe_scope = 0
        self.probe_pid = probe_pid
        self.session = None
        self.devices = {}
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            buffer = ctypes.create_unicode_buffer(32768)
            if kernel.QueryDosDeviceW(letter + ':', buffer, len(buffer)):
                self.devices[buffer.value.casefold()] = letter + ':'
        command = [str(path)]
        if probe_pid is not None:
            command.extend(('--probe-pid', str(probe_pid)))
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.thread = threading.Thread(target=self.read, name='kernel-file-events', daemon=True)
        self.thread.start()

    def read(self):
        """Background thread: read JSON lines from the collector, track its health counters and queue
        file-write events.
        """
        try:
            while True:
                raw = self.process.stdout.readline(65537)
                if not raw:
                    break
                if len(raw) > 65536 or not raw.endswith(b'\n'):
                    raise ValueError('ETW collector framing exceeded')
                event = json.loads(raw)
                if event.get('kind') == 'ready':
                    name = event.get('session', '')
                    if not re.fullmatch(r'SentinelAV-FileIO-[a-f0-9]{32}', name):
                        raise ValueError('Invalid collector session identity')
                    if event.get('probe_pid') != self.probe_pid:
                        raise ValueError('Unexpected ETW collector scope')
                    self.session = name
                    self.ready = True
                    continue
                if event.get('kind') == 'unavailable':
                    raise RuntimeError(event.get('reason', 'ETW unavailable'))
                if event.get('kind') in ('health', 'stopped'):
                    self.native_dropped = max(self.native_dropped, int(event.get('dropped', 0)))
                    self.etw_lost = max(self.etw_lost, int(event.get('etw_lost', 0)))
                    self.unresolved_paths = max(
                        self.unresolved_paths, int(event.get('unresolved_paths', 0))
                    )
                    self.unresolved_identities = max(
                        self.unresolved_identities, int(event.get('unresolved_identities', 0))
                    )
                    self.outside_probe_scope = max(
                        self.outside_probe_scope, int(event.get('outside_probe_scope', 0))
                    )
                    self.last_heartbeat = time.time()
                    if event.get('kind') == 'stopped':
                        self.ready = False
                    continue
                if event.get('kind') != 'file_write':
                    continue
                try:
                    self.queue.put_nowait(event)
                except queue.Full:
                    self.dropped += 1
        except Exception as error:
            self.error = str(error)[:300]
        finally:
            self.ready = False
            if not self.error:
                self.error = 'Collector exited; kernel file coverage unavailable'

    def poll(self):
        """Return up to 128 queued file-write events whose process identity and path could be verified
        (others are counted as dropped).
        """
        events = []
        for _ in range(128):
            try:
                event = self.queue.get_nowait()
            except queue.Empty:
                break
            try:
                identity = event['identity']
                process = psutil.Process(int(identity['pid']))
                creation = process.create_time()
                if abs(creation - float(identity['creation'])) > 0.05 or creation > float(
                    event['timestamp']
                ):
                    raise ValueError('PID identity changed')
                if abs(time.time() - float(event['timestamp'])) > 30:
                    raise ValueError('Stale telemetry event')
                path = event['path']
                if isinstance(path, str):
                    for device, drive in self.devices.items():
                        if path.casefold().startswith(device + '\\'):
                            path = drive + path[len(device) :]
                            break
                if not isinstance(path, str) or not Path(path).is_absolute():
                    raise ValueError('Unresolved ETW path')
                info = process.as_dict(attrs=['pid', 'create_time', 'exe', 'name'])
                events.append(
                    dict(
                        path=path,
                        bytes=int(event['bytes']),
                        process=info,
                        identity=identity,
                        timestamp=float(event['timestamp']),
                    )
                )
            except (ValueError, TypeError, KeyError, psutil.Error):
                self.dropped += 1
        return events

    def close(self):
        # Task cancellation ends this owned collector only. Its session uses a
        # unique name; no unrelated ETW session or security service is stopped.
        """Ask the collector to stop, forcing its ETW session closed if it does not exit in time."""
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b'stop\n')
                self.process.stdin.flush()
            except OSError:
                pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if self.session:
                logman = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/logman.exe'
                subprocess.run(
                    [str(logman), 'stop', self.session, '-ets'],
                    capture_output=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            self.process.terminate()
            self.process.wait(timeout=5)
        self.thread.join(timeout=2)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stdin:
            self.process.stdin.close()

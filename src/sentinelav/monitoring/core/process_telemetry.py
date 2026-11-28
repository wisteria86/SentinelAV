# Purpose: Temporary WMI event subscription plus PID-reuse-aware process ancestry.
# Works with: paths
# Used by: monitoring.core.monitor_loop, monitoring.monitoring, tests.unit.test_defense_layers

"""Temporary WMI event subscription plus PID-reuse-aware process ancestry."""

from sentinelav.paths import RESOURCE_ROOT
from collections import OrderedDict
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time


class ProcessGraph:
    """Remembers recently seen processes so we can work out a process's parent chain safely.

    Windows reuses process ids, so a parent is only accepted if it started before its child;
    otherwise the id now belongs to a different program.
    """

    def __init__(self):
        """Start with no known processes."""
        self.identities = OrderedDict()
        self.current = {}

    def observe(self, info):
        """Remember one process (keeping at most 4096)."""
        if not info.get('create_time'):
            return
        key = (info['pid'], info['create_time'])
        self.identities[key] = dict(
            pid=info['pid'],
            create_time=info['create_time'],
            ppid=info.get('ppid'),
            name=info.get('name') or '',
            exe=info.get('exe') or '',
        )
        self.identities.move_to_end(key)
        self.current[info['pid']] = key
        while len(self.identities) > 4096:
            old, _ = self.identities.popitem(last=False)
            if self.current.get(old[0]) == old:
                self.current.pop(old[0], None)

    def ancestors(self, info):
        """Return the verified parent chain of a process (up to 8 levels), nearest parent first."""
        result = []
        seen = {info['pid']}
        parent = info.get('ppid')
        child_time = info.get('create_time', 0)
        if not isinstance(child_time, (int, float)):
            return result
        while parent and parent not in seen and len(result) < 8:
            key = self.current.get(parent)
            item = self.identities.get(key)
            if not item or item['create_time'] > child_time:
                break
            result.append(dict(item))
            seen.add(parent)
            parent = item.get('ppid')
            child_time = item['create_time']
        return result


class ProcessEvents:
    """Receives process-start events from Windows (WMI) through a helper PowerShell script."""

    def __init__(self):
        """Prepare an empty event queue; start() launches the helper."""
        self.events = queue.Queue(maxsize=256)
        self.process = None
        self.ready = False
        self.error = ''
        self.dropped = 0
        self.started = 0

    def start(self):
        """Launch the helper script and the threads that read its output and errors."""
        if os.name != 'nt':
            raise RuntimeError('Windows process events require Windows')
        executable = (
            Path(os.environ.get('SystemRoot', 'C:/Windows'))
            / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        )
        script = RESOURCE_ROOT / 'scripts/process_events.ps1'
        self.process = subprocess.Popen(
            [str(executable), '-NoProfile', '-NonInteractive', '-File', str(script)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        process = self.process
        self.started = time.monotonic()

        def read():
            """Background thread: read and validate JSON events from the helper and queue them."""
            try:
                while True:
                    raw = process.stdout.readline(4097)
                    if not raw:
                        break
                    if len(raw) > 4096:
                        raise ValueError('Process event exceeded transport limit')
                    event = json.loads(raw.decode('utf-8-sig'))
                    if event.get('kind') == 'ready':
                        self.ready = True
                    elif event.get('kind') == 'dropped':
                        self.dropped += int(event['count'])
                    elif event.get('kind') == 'start':
                        if (
                            type(event.get('pid')) is not int
                            or type(event.get('parent_pid')) is not int
                            or not isinstance(event.get('name'), str)
                            or len(event['name']) > 260
                            or not 1 <= event['pid'] < 2**31
                            or not 0 <= event['parent_pid'] < 2**31
                            or len(str(event.get('timestamp', ''))) > 20
                            or not str(event.get('timestamp', '')).isdigit()
                        ):
                            raise ValueError('Invalid process event')
                        try:
                            self.events.put_nowait(event)
                        except queue.Full:
                            self.dropped += 1
            except Exception as error:
                self.error = str(error)

        def errors():
            """Background thread: keep the first error message from the helper and drain the rest."""
            raw = process.stderr.read(2048)
            if raw:
                self.error = raw.decode('utf-8', errors='replace').strip()
            while process.stderr.read(4096):
                pass

        self.reader = threading.Thread(target=read, daemon=True, name='process-events')
        self.errors = threading.Thread(target=errors, daemon=True, name='process-event-errors')
        self.reader.start()
        self.errors.start()

    def poll(self):
        """Return up to 100 queued process-start events, raising RuntimeError if the helper has died or
        never became ready.
        """
        if self.process is None:
            return []
        if self.process.poll() is not None:
            raise RuntimeError(self.error or 'Process event source exited')
        if not self.ready and time.monotonic() - self.started > 10:
            raise RuntimeError('Process event subscription did not become ready')
        result = []
        for _ in range(100):
            try:
                result.append(self.events.get_nowait())
            except queue.Empty:
                break
        return result

    def close(self):
        """Stop the helper process and close its pipes."""
        if self.process:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
            for stream in (self.process.stdout, self.process.stderr):
                if stream:
                    stream.close()
            self.process = None

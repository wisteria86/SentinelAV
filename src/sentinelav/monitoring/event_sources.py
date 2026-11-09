# Purpose: Collect and stabilize filesystem and Sysmon events before inspection.
# Works with: sibling modules in monitoring
# Used by: monitoring.monitor_loop, monitoring.monitoring

"""Bounded, read-only monitoring. No files are removed and no processes are stopped."""
import json
import os
import subprocess
import threading
import time
import queue
from collections import OrderedDict
from watchdog.events import FileSystemEventHandler


# Browsers write here until a download finishes, then rename to the final name, which triggers the scan.
IN_PROGRESS_SUFFIXES=('.crdownload','.part','.partial','.download','.opdownload','.tmpdownload')


def still_downloading(path):
    return str(path).casefold().endswith(IN_PROGRESS_SUFFIXES)


class PendingFiles:
    def __init__(self, capacity=1024, delay=.7):
        self.capacity, self.delay = capacity, delay
        self.items = OrderedDict()
        self.lock = threading.Lock()
        self.dropped = 0

    def add(self, path, source='Filesystem', wait=0):
        with self.lock:
            key = os.path.normcase(os.path.abspath(path))
            if key not in self.items and len(self.items) >= self.capacity:
                self.dropped += 1
                return
            self.items[key] = (time.monotonic()+wait, source)

    def pop(self):
        with self.lock:
            for path, (stamp, source) in self.items.items():
                if time.monotonic() - stamp >= self.delay:
                    del self.items[path]
                    return path, source
        return None


class Changes(FileSystemEventHandler):
    def __init__(self, queue, activity=None):
        self.queue = queue
        self.activity = activity or (lambda *args:None)

    def on_created(self, event):
        if not event.is_directory:
            if not still_downloading(event.src_path):self.queue.add(event.src_path)
            self.activity('modified',event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            if not still_downloading(event.src_path):self.queue.add(event.src_path)
            self.activity('modified',event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            if not still_downloading(event.dest_path):self.queue.add(event.dest_path)
            self.activity('moved',event.dest_path)

    def on_deleted(self,event):
        if not event.is_directory:
            self.activity('deleted',event.src_path)


class SysmonReader:
    """Read an existing Sysmon channel; never install or change Windows logging."""
    def __init__(self):
        self.cursor = None

    def poll(self):
        if os.name != 'nt':
            raise RuntimeError('Sysmon requires Windows')
        if self.cursor is None:
            query = "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop"
        else:
            query = ("Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                     f"-FilterXPath '*[System[EventRecordID > {int(self.cursor)}]]' "
                     '-Oldest -MaxEvents 100 -ErrorAction Stop')
        script = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; try { @(" + query +
                  " | Select-Object RecordId,Id,@{N='Message';E={$_.Message}},@{N='Xml';E={$_.ToXml()}}) | ConvertTo-Json -Compress "
                  "} catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { '[]' } "
                  "else { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } }")
        completed = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
                                   capture_output=True, encoding='utf-8-sig', errors='replace',
                                   timeout=8, creationflags=subprocess.CREATE_NO_WINDOW)
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip() or 'Sysmon channel is unavailable')
        rows = json.loads(completed.stdout.strip() or '[]')
        if isinstance(rows, dict):
            rows = [rows]
        baseline = self.cursor is None
        if rows:
            self.cursor = max(int(r['RecordId']) for r in rows)
        elif baseline:
            self.cursor = 0
        return [] if baseline else rows

# Purpose: Hold published infection markers (mutexes, files) that make specific malware families stand down.
# Works with: resources/deception/vaccines.json
# Used by: monitoring.deception

"""Hold published infection markers (mutexes, files) that make specific malware families stand down.

Mutexes are held by the monitor for as long as protection runs. Marker files go
in the Windows folder, which needs administrator rights; without them the file
markers are skipped and reported as such. Every marker cites its source.
"""
import json
import os
import stat
from pathlib import Path

from sentinelav.paths import RESOURCE_ROOT

MARKER_TEXT = b'SentinelAV infection marker (vaccine). Safe to delete if you remove SentinelAV.\r\n'


def markers(path=None):
    """Load the list of infection markers (mutexes and files, each with its family and source) from the
    bundled JSON.
    """
    return json.loads(Path(path or RESOURCE_ROOT / 'deception' / 'vaccines.json').read_text(encoding='utf-8'))['markers']


class Vaccines:
    """Holds infection markers that make certain malware believe the PC is already infected, so it
    stops.
    """
    def __init__(self, items=None):
        """Use the given markers, or the bundled list by default."""
        self.items, self.handles, self.held, self.skipped, self.files = items if items is not None else markers(), [], [], [], []

    def start(self):
        """Create every mutex and every missing marker file (files need administrator rights). Returns
        what is now held; problems go to `skipped`.
        """
        if os.name != 'nt':
            return self.held
        import win32event
        for item in self.items:
            if item['type'] == 'mutex':
                try:
                    self.handles.append(win32event.CreateMutex(None, False, item['name']))
                    self.held.append(item['family'] + ': ' + item['name'])
                except Exception as error:
                    self.skipped.append(f"{item['name']}: {error}")
            elif item['type'] == 'file':
                for raw in item['paths']:
                    path = Path(os.path.expandvars(raw))
                    if path.exists():
                        continue  # Already there (ours from an earlier run, or someone else's); never replace it.
                    try:
                        path.write_bytes(MARKER_TEXT)
                        os.chmod(path, stat.S_IREAD)
                        self.files.append(str(path))
                        self.held.append(item['family'] + ': ' + str(path))
                    except OSError as error:
                        self.skipped.append(f'{path}: needs administrator rights ({error.strerror})')
        return self.held

    def stop(self):
        """Release the mutexes. Marker files stay, so the protection lasts while SentinelAV is not running."""
        for handle in self.handles:
            try:
                handle.Close()
            except Exception:
                pass
        self.handles = []

    close = stop


def remove_files(paths):
    """Delete marker files SentinelAV created, only if they still hold its own text."""
    for raw in paths:
        path = Path(raw)
        try:
            if path.read_bytes() == MARKER_TEXT:
                os.chmod(path, stat.S_IWRITE)
                path.unlink()
        except OSError:
            pass

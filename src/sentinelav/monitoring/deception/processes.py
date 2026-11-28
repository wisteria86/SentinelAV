# Purpose: Start and watch decoy processes: injection bait, fake analysis tools, and a holder of fake credentials in memory.
# Works with: monitoring.deception.decoy_process, monitoring.deception.common
# Used by: monitoring.deception

"""Start and watch decoy processes: injection bait, fake analysis tools, and a holder of fake credentials in memory.

Each decoy is SentinelAV itself (or, from source, the Python interpreter) under
another file name, created as a hard link so it costs no disk space. Names are
skipped when the real program is installed or already running. Decoys exit on
their own when the monitor stops.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from sentinelav.monitoring.deception.common import event

# Programs that injectors and remote-desktop credential thieves target, used only where the real one is absent.
BAIT = (('mstsc.exe', []), ('KeePass.exe', ['%ProgramFiles%/KeePass Password Safe 2/KeePass.exe']),
        ('firefox.exe', ['%ProgramFiles%/Mozilla Firefox/firefox.exe']))
# Tools whose presence makes evasive malware assume it is being analyzed and stay dormant.
ANALYSIS = (('vmtoolsd.exe', ['%ProgramFiles%/VMware/VMware Tools/vmtoolsd.exe']), ('VBoxService.exe', ['%SystemRoot%/System32/VBoxService.exe']),
            ('procmon.exe', []), ('x64dbg.exe', []), ('ollydbg.exe', []), ('Wireshark.exe', ['%ProgramFiles%/Wireshark/Wireshark.exe']))
CREATE_NO_WINDOW, LOGON_NETCREDENTIALS_ONLY = 0x08000000, 2
RUNTIME_FILES = ('python3.dll', f'python{sys.version_info[0]}{sys.version_info[1]}.dll', 'vcruntime140.dll', 'vcruntime140_1.dll')


def _link(source, target):
    """Make `target` a hard link to `source` (no extra disk space), or a copy if linking is not
    possible.
    """
    target.unlink(missing_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def running_names():
    """Return the lower-case names of every running process."""
    import psutil
    return {(process.info['name'] or '').casefold() for process in psutil.process_iter(['name'])}


def host_command(name, folder, role, status, parent):
    """The command line for one decoy, creating its named executable first."""
    arguments = ['--decoy-role', role, '--decoy-status', str(status), '--decoy-parent', str(parent)]
    if getattr(sys, 'frozen', False):
        # The packaged app runs its decoy mode before anything else; the link must sit beside it to find its runtime.
        target = Path(sys.executable).with_name(name)
        _link(Path(sys.executable), target)
        return [str(target), *arguments], None
    base = Path(getattr(sys, '_base_executable', sys.executable))
    folder.mkdir(parents=True, exist_ok=True)
    _link(base, folder / name)
    for file in RUNTIME_FILES:
        if (base.parent / file).exists():
            _link(base.parent / file, folder / file)
    source = Path(__file__).resolve().parents[3]
    paths = [str(source)] + [entry for entry in sys.path if entry.endswith('site-packages')]
    env = dict(os.environ, PYTHONHOME=sys.base_prefix, PYTHONPATH=os.pathsep.join(paths))
    return [str(folder / name), '-m', 'sentinelav.monitoring.deception.decoy_process', *arguments], env


def _present(markers):
    """Tell whether any of the given program paths exists (meaning the real program is installed).
    """
    return any(Path(os.path.expandvars(marker)).exists() for marker in markers)


class DecoyProcesses:
    """Starts and watches the decoy processes."""
    def __init__(self, emit, folder, bait=True, analysis=False, credentials=None):
        """Plan which decoys to run (skipping names whose real program is installed). credentials, if
        given, are planted in memory by one extra decoy.
        """
        self.emit, self.folder = emit, Path(folder)
        self.plan = ([(name, 'bait') for name, markers in BAIT if not _present(markers)] if bait else []) + \
                    ([(name, 'analysis') for name, markers in ANALYSIS if not _present(markers)] if analysis else [])
        self.credentials, self.children, self.offset = credentials, [], 0
        self.status = self.folder / 'decoy-status.jsonl'

    def start(self):
        """Start every planned decoy whose real program is not already running, and return the names
        started.
        """
        self.folder.mkdir(parents=True, exist_ok=True)
        self.status.touch()
        self.offset = self.status.stat().st_size
        busy = running_names()
        for name, role in self.plan:
            if name.casefold() in busy:
                continue  # The real program is running; a second copy of its name would only confuse.
            try:
                command, env = host_command(name, self.folder / 'host', role, self.status, os.getpid())
                self.children.append((name, subprocess.Popen(command, env=env, creationflags=CREATE_NO_WINDOW,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)))
            except OSError as error:
                self.emit(event('Decoy process unavailable', f'{name}: {error}', level='Warning'))
        if self.credentials:
            self._start_with_credentials()
        return [name for name, _ in self.children]

    def _start_with_credentials(self):
        """A bait process whose network logon uses fake credentials, so a memory-dumping tool finds them in LSASS."""
        try:
            import win32process
            command, _ = host_command('svchost-backup.exe', self.folder / 'host', 'bait', self.status, os.getpid())
            info = win32process.STARTUPINFO()
            handles = win32process.CreateProcessWithLogonW(self.credentials['user'], self.credentials['domain'], self.credentials['password'],
                LOGON_NETCREDENTIALS_ONLY, None, subprocess.list2cmdline(command), CREATE_NO_WINDOW, None, None, info)
            self.children.append(('svchost-backup.exe', handles))
        except Exception as error:
            self.emit(event('Fake credentials not planted', str(error)[:200], level='Warning'))

    def poll(self):
        """Read new findings from the decoys' status file and raise an alert for each injection found.
        """
        try:
            with self.status.open('r', encoding='utf-8') as stream:
                stream.seek(self.offset)
                lines = stream.readlines()
                self.offset = stream.tell()
        except OSError:
            return []
        events = []
        for line in lines:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            what = 'executable memory appeared' if item['kind'] == 'executable_memory' else 'a thread started outside every loaded module'
            events.append(event('Code injected into a decoy process', f"In decoy {item['role']} process PID {item['pid']}, {what}. "
                'Nothing legitimate injects code into an idle program, so another process on this PC is injecting code.', decoy=item))
            self.emit(events[-1])
        return events

    def stop(self):
        """Stop every decoy process and remove the named links created beside the packaged app."""
        for name, child in self.children:
            try:
                if hasattr(child, 'terminate'):
                    child.terminate()
                else:  # CreateProcessWithLogonW returns raw handles.
                    import win32api
                    win32api.TerminateProcess(child[0], 0)
            except Exception:
                pass
        self.children = []
        if getattr(sys, 'frozen', False):
            for name, _ in self.plan + [('svchost-backup.exe', 'bait')]:
                try:
                    Path(sys.executable).with_name(name).unlink(missing_ok=True)
                except OSError:
                    pass  # Still closing; the next start replaces the link anyway.

    close = stop


def fake_credentials():
    """Make up a fake service account and password to plant in memory as bait."""
    return dict(user='svc_backup', domain='CORP-FILES', password='Decoy-' + secrets.token_urlsafe(12))

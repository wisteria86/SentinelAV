# Purpose: Deploy decoy files and an opt-in network listener, and report anything that touches them.
# Works with: monitoring.core.behavior, monitoring.core.monitor_loop, data.storage
# Used by: monitoring.core.monitor_loop, ui.core.honeypot_ui

"""Deploy decoy files and an opt-in network listener, and report anything that touches them.

Decoys are harmless text files with clearly fake values and a visible marker.
Nothing legitimate should open them, so a read, change, rename or deletion is
strong evidence of data theft or ransomware. They are hidden and excluded from
indexing and from SentinelAV's own scans. Processes are never stopped here.
"""

import hashlib
import os
import secrets
import socket
import threading
import time
from pathlib import Path

MARKER = 'SENTINELAV DECOY FILE. It holds no real data; please leave it in place.'
CREDENTIAL_DECOYS = (
    ('Documents', 'passwords-backup.txt', 'credentials'),
    ('Documents', 'wallet-recovery-phrase.txt', 'crypto_wallet'),
    ('Documents', 'id_rsa.backup', 'ssh_key'),
    ('Documents', 'aws-credentials.bak', 'cloud_credentials'),
    ('Desktop', 'Banking logins.txt', 'credentials'),
)
# Named to sort first, so encryption sweeps reach it early.
TRAP_FOLDER = '!000 Archive'
TRAP_FILES = (
    '000 budget.docx',
    '001 invoice.pdf',
    '002 contracts.xlsx',
    '003 family photo.jpg',
    '004 notes.txt',
    '005 tax return.pdf',
    '006 payroll.xlsx',
    '007 scan.png',
    '008 letter.docx',
    '009 backup.zip',
)
HIDDEN = 0x2
NOT_INDEXED = 0x2000
DEFAULT_PORTS = (23, 2323, 5900)
WORDS = (
    'river',
    'candle',
    'orbit',
    'velvet',
    'harbor',
    'lemon',
    'quartz',
    'meadow',
    'pilot',
    'echo',
    'tundra',
    'saddle',
)


def _content(kind):
    """Build the text of a decoy file of the given kind: the visible marker plus obviously fake values."""
    token = secrets.token_hex(8)
    body = {
        'credentials': f'email: decoy.{token}@example.invalid\npassword: Decoy-{token}\nbank pin: 0000\n',
        'crypto_wallet': 'seed: '
        + ' '.join(secrets.choice(WORDS) for _ in range(12))
        + f'\nwallet id: decoy-{token}\n',
        'ssh_key': f'-----BEGIN DECOY KEY-----\n{secrets.token_hex(48)}\n-----END DECOY KEY-----\n',
        'cloud_credentials': f'[default]\naws_access_key_id = DECOY{token.upper()}\naws_secret_access_key = decoy/{secrets.token_hex(16)}\n',
        'ransomware_trap': f'decoy document {token}\n' + secrets.token_hex(256) + '\n',
    }[kind]
    return (MARKER + '\n' + body).encode('utf-8')


def _hide(path):
    """Mark a file as hidden and excluded from Windows Search indexing."""
    if os.name == 'nt':
        import ctypes

        ctypes.windll.kernel32.SetFileAttributesW(str(path), HIDDEN | NOT_INDEXED)


def _record(path, kind, content):
    """Remember a decoy's path, kind, hash and timestamps, so later changes can be detected."""
    info = path.stat()
    return dict(
        path=str(path),
        kind=kind,
        sha256=hashlib.sha256(content).hexdigest(),
        atime_ns=info.st_atime_ns,
        mtime_ns=info.st_mtime_ns,
        size=info.st_size,
    )


def deploy(home=None, trap=True):
    """Create every decoy that does not exist yet. Existing user files are never overwritten."""
    # SENTINELAV_DECOY_HOME lets tests and evaluations place decoys somewhere other than the real profile.
    home = Path(home or os.environ.get('SENTINELAV_DECOY_HOME') or Path.home())
    entries = []
    targets = [
        (home / folder / name, kind)
        for folder, name, kind in CREDENTIAL_DECOYS
        if (home / folder).is_dir()
    ]
    if trap and (home / 'Documents').is_dir():
        folder = home / 'Documents' / TRAP_FOLDER
        folder.mkdir(exist_ok=True)
        _hide(folder)
        targets += [(folder / name, 'ransomware_trap') for name in TRAP_FILES]
    for path, kind in targets:
        content = _content(kind)
        try:
            with path.open('xb') as stream:
                stream.write(content)
        except FileExistsError:
            continue
        _hide(path)
        entries.append(_record(path, kind, content))
    return entries


def remove(entries):
    """Delete only decoys whose content is still exactly what SentinelAV wrote."""
    kept = []
    for entry in entries:
        path = Path(entry['path'])
        try:
            if hashlib.sha256(path.read_bytes()[:65536]).hexdigest() == entry['sha256']:
                path.unlink()
                continue
        except FileNotFoundError:
            continue
        except OSError:
            pass
        kept.append(entry)
    for folder in {
        Path(entry['path']).parent for entry in entries if entry['kind'] == 'ransomware_trap'
    }:
        try:
            folder.rmdir()
        except OSError:
            pass
    return kept


def holders(path, budget=2.0):
    """Processes that currently have the decoy open, within a time budget."""
    import psutil

    target = os.path.normcase(str(path))
    found = []
    deadline = time.monotonic() + budget
    for process in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
        if time.monotonic() > deadline:
            break
        try:
            if any(os.path.normcase(item.path) == target for item in process.open_files()):
                found.append(
                    dict(
                        pid=process.info['pid'],
                        name=process.info['name'] or '',
                        exe=process.info['exe'] or '',
                        create_time=process.info['create_time'],
                    )
                )
        except (psutil.Error, OSError):
            continue
    return found


class HoneypotWatcher:
    """Polls decoys for reads (last-access time), changes, renames and deletions."""

    def __init__(self, entries, emit, behavior=None, find_holders=holders, clock=time.monotonic):
        """Watch the given decoys. emit receives alerts, behavior (optional) receives per-process
        indicators, and find_holders and clock can be replaced in tests.
        """
        self.entries = [dict(entry) for entry in entries]
        self.emit = emit
        self.behavior = behavior
        self.find_holders = find_holders
        self.clock = clock
        self.reported = {}

    def paths(self):
        """Return the normalised paths of every watched decoy."""
        return {os.path.normcase(entry['path']) for entry in self.entries}

    def _state(self, entry):
        """Check one decoy and return what happened to it ('read', 'modified', 'deleted or renamed',
        ...), or None if it is untouched.
        """
        path = Path(entry['path'])
        try:
            info = path.stat()
        except FileNotFoundError:
            return 'deleted or renamed'
        except OSError:
            return None
        if info.st_mtime_ns != entry['mtime_ns'] or info.st_size != entry['size']:
            try:
                changed = hashlib.sha256(path.read_bytes()[:65536]).hexdigest() != entry['sha256']
            except OSError:
                return 'locked after a change'
            # Reading it here updated the access time; re-baseline so this check is not reported as a read.
            # Read the new access time first: if stat() fails, the entry must stay untouched.
            accessed = path.stat().st_atime_ns
            entry['mtime_ns'] = info.st_mtime_ns
            entry['size'] = info.st_size
            entry['atime_ns'] = accessed
            if changed:
                entry['sha256'] = ''
                return 'modified'
            return None
        if info.st_atime_ns != entry['atime_ns']:
            entry['atime_ns'] = info.st_atime_ns
            return 'read'
        return None

    def poll(self):
        """Check every decoy and raise an alert for each new touch (the same touch is reported at most
        once a minute).

        If the process that has the file open can be found, it is named in the alert and reported to
        the behaviour engine. Three or more trap files changing at once is called out as ransomware-
        like.
        """
        touched = []
        for entry in self.entries:
            state = self._state(entry)
            if state:
                touched.append((entry, state))
        if not touched:
            return []
        traps = [
            item for item in touched if item[0]['kind'] == 'ransomware_trap' and item[1] != 'read'
        ]
        events = []
        for entry, state in touched:
            key = (entry['path'], state)
            now = self.clock()
            if now - self.reported.get(key, -1e9) < 60:
                continue
            self.reported[key] = now
            found = (
                self.find_holders(entry['path'])
                if state in ('read', 'locked after a change')
                else []
            )
            severe = state != 'read' or entry['kind'] != 'ransomware_trap'
            label = (
                'Ransomware trap'
                if entry['kind'] == 'ransomware_trap'
                else 'Decoy ' + entry['kind'].replace('_', ' ')
            )
            who = (
                ', '.join(f"{item['name']} (PID {item['pid']})" for item in found)
                or 'process not identified'
            )
            details = f'{label} {state}: {Path(entry["path"]).name}. Accessed by: {who}.'
            if len(traps) >= 3:
                details += (
                    f' {len(traps)} trap files changed at once, which is how ransomware behaves.'
                )
            event = dict(
                time=time.strftime('%Y-%m-%d %H:%M:%S'),
                kind='Honeypot triggered',
                details=details,
                source='Honeypot',
                level='Alert' if severe else 'Warning',
                path=entry['path'],
                decoy=entry['kind'],
                state=state,
                processes=found,
            )
            events.append(event)
            self.emit(event)
            if self.behavior:
                for item in found:
                    entity = f"process:{item['pid']}:{item['create_time']}"
                    self.behavior.indicator(
                        entity,
                        'decoy_access',
                        70,
                        f'{label} {state} by this process',
                        pid=item['pid'],
                        path=item['exe'],
                    )
        return events


class NetworkHoneypot:
    """Low-interaction listener: logs who connects, sends nothing back, and keeps bounded records."""

    def __init__(self, emit, ports=DEFAULT_PORTS, host='0.0.0.0', limit=256):
        """Prepare listeners for the given ports (they are opened by start())."""
        self.emit = emit
        self.ports = tuple(ports)
        self.host = host
        self.limit = limit
        self.sockets = []
        self.skipped = []
        self.stop_event = threading.Event()
        self.records = []

    def start(self):
        """Open a listener on each port that is free (ports already in use are skipped) and return the
        ports actually opened.
        """
        for port in self.ports:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if os.name == 'nt':
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                server.bind((self.host, port))
                server.listen(16)
                server.settimeout(0.5)
            except OSError:
                server.close()
                self.skipped.append(port)  # In use by something real; never take it over.
                continue
            self.sockets.append(server)
            threading.Thread(
                target=self._serve,
                args=(server, server.getsockname()[1]),
                daemon=True,
                name=f'honeypot-{port}',
            ).start()
        return [server.getsockname()[1] for server in self.sockets]

    def _serve(self, server, port):
        """Accept connections on one port, read the first few bytes, and raise an alert for each
        visitor.
        """
        while not self.stop_event.is_set():
            try:
                connection, (address, peer_port) = server.accept()
            except (socket.timeout, OSError):
                continue
            with connection:
                connection.settimeout(2)
                try:
                    first = connection.recv(128)
                except OSError:
                    first = b''
            local = address.startswith('127.') or address == '::1'
            record = dict(
                time=time.strftime('%Y-%m-%d %H:%M:%S'),
                port=port,
                address=address,
                peer_port=peer_port,
                first_bytes=first[:64].hex(),
            )
            self.records = (self.records + [record])[-self.limit :]
            self.emit(
                dict(
                    record,
                    kind='Network honeypot contacted',
                    source='Honeypot',
                    level='Warning' if local else 'Alert',
                    details=f'{address}:{peer_port} connected to decoy port {port}. '
                    'Nothing legitimate uses this port here, so this is likely a scan or an attempt to spread.',
                )
            )

    def stop(self):
        """Stop all listeners."""
        self.stop_event.set()
        for server in self.sockets:
            server.close()
        self.sockets = []

    close = stop

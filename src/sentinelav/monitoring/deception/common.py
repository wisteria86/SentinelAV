# Purpose: Shared helpers for deception features: decoy file records, owning-process lookup and event shape.
# Works with: monitoring.honeypots
# Used by: monitoring.deception.*

"""Shared helpers for deception features: decoy file records, owning-process lookup and event shape."""
import hashlib
import os
import time
from pathlib import Path

# Loopback address the breadcrumbs and honeytokens point at; nothing else on a normal PC listens there.
DECOY_HOST = '127.0.0.2'
MARKER = 'SENTINELAV DECOY. It holds no real data; please leave it in place.'


def write_decoy(path, content, kind, created):
    """Create one decoy file, never overwriting anything. Records the folders it had to create for later cleanup."""
    path = Path(path)
    missing = [parent for parent in reversed(path.parents) if not parent.exists()]
    path.parent.mkdir(parents=True, exist_ok=True)
    created.extend(str(folder) for folder in missing if str(folder) not in created)
    try:
        with path.open('xb') as stream:
            stream.write(content)
    except FileExistsError:
        return None
    info = path.stat()
    return dict(path=str(path), kind=kind, sha256=hashlib.sha256(content).hexdigest(), atime_ns=info.st_atime_ns,
        mtime_ns=info.st_mtime_ns, size=info.st_size)


def remove_decoys(entries, created):
    """Delete decoys whose content is unchanged, then the folders SentinelAV created, deepest first, if empty."""
    kept = []
    for entry in entries:
        path = Path(entry['path'])
        try:
            if hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256']:
                path.unlink()
                continue
        except FileNotFoundError:
            continue
        except OSError:
            pass
        kept.append(entry)
    for folder in sorted(created, key=len, reverse=True):
        try:
            Path(folder).rmdir()
        except OSError:
            pass
    return kept


def connection_owner(peer_address, peer_port):
    """The local process on the other end of a loopback connection, or None when it cannot be identified."""
    try:
        import psutil
        for item in psutil.net_connections(kind='tcp'):
            if item.laddr and item.laddr.port == peer_port and item.laddr.ip == peer_address and item.pid:
                process = psutil.Process(item.pid)
                return dict(pid=item.pid, name=process.name(), exe=process.exe(), create_time=process.create_time())
    except Exception:
        return None
    return None


def event(kind, details, level='Alert', **extra):
    """Build a deception activity event with the current time."""
    return dict(time=time.strftime('%Y-%m-%d %H:%M:%S'), kind=kind, details=details, source='Deception', level=level, **extra)


def describe(process):
    """Describe a process as 'name (PID n)', or say it could not be identified."""
    return f"{process['name']} (PID {process['pid']})" if process else 'process not identified'


def flag(behavior, process, reason, weight=70):
    """Raise the behavior score of the process involved; processes are never stopped here."""
    if behavior and process:
        entity = f"process:{process['pid']}:{process['create_time']}"
        behavior.indicator(entity, 'decoy_access', weight, reason, pid=process['pid'], path=process['exe'])


def profile_dirs():
    """Return (home, local app data, roaming app data) folders, using the test decoy home when
    SENTINELAV_DECOY_HOME is set.
    """
    home = Path(os.environ.get('SENTINELAV_DECOY_HOME') or Path.home())
    local = Path(os.environ.get('LOCALAPPDATA') or home / 'AppData' / 'Local')
    roaming = Path(os.environ.get('APPDATA') or home / 'AppData' / 'Roaming')
    if os.environ.get('SENTINELAV_DECOY_HOME'):
        local, roaming = home / 'AppData' / 'Local', home / 'AppData' / 'Roaming'
    return home, local, roaming

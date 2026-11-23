# Purpose: Run ClamAV's clamd as a local signature service and stream bytes to it for scanning.
# Works with: detection.engine, detection.definition_paths, detection.threat_score
# Used by: detection.engine, entrypoint, ui.application, lab.qualification.zoo_guest

"""Run ClamAV's clamd as a local signature service and stream bytes to it.

clamd is a separate GPL program started as a child process, bound to 127.0.0.1
on a free port. Scan workers find it through a small endpoint file and send bytes
with INSTREAM, so archive members and decoded content are scanned without being
written to disk. Nothing scanned is ever executed.
"""
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path
from sentinelav.detection.definition_paths import binaries, database_dir

CHUNK = 1024 * 1024
STREAM_LIMIT = 256 * 1024 * 1024
START_TIMEOUT = 300
SCAN_TIMEOUT = 120
ENDPOINT_FILE = 'clamd.endpoint.json'
DATABASE_SUFFIXES = ('.cvd', '.cld', '.cud')
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


class ClamAVUnavailable(RuntimeError):
    pass


def has_definitions(database):
    return database.is_dir() and any(item.suffix in DATABASE_SUFFIXES for item in database.iterdir())


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def _config(database, port):
    # Limits keep one hostile file from exhausting clamd. PUA detection stays off to avoid flagging ordinary tools.
    return '\n'.join([
        f'DatabaseDirectory "{database}"', f'TCPSocket {port}', 'TCPAddr 127.0.0.1', 'Foreground yes',
        'MaxThreads 8', 'StreamMaxLength 256M', 'MaxScanSize 512M', 'MaxFileSize 256M', 'MaxRecursion 12',
        'MaxFiles 4096', 'MaxScanTime 110000', 'ReadTimeout 180', 'CommandReadTimeout 30',
        'HeuristicAlerts yes', 'AlertBrokenExecutables no', 'AlertEncrypted no', 'DetectPUA no',
        'ScanArchive yes', 'ScanPE yes', 'ScanELF yes', 'ScanOLE2 yes', 'ScanPDF yes', 'ScanHTML yes',
        'ScanMail yes', 'Bytecode yes', 'LogTime no', '']).replace('\\', '/')


def _request(endpoint, command, timeout=10):
    with socket.create_connection(tuple(endpoint), timeout=timeout) as connection:
        connection.sendall(b'z' + command + b'\0')
        return _reply(connection)


def _reply(connection):
    data = bytearray()
    while not data.endswith(b'\0'):
        chunk = connection.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 65536:
            raise ClamAVUnavailable('clamd reply too long')
    return bytes(data).rstrip(b'\0').decode('utf-8', 'replace')


def alive(endpoint):
    try:
        return _request(endpoint, b'PING', 3) == 'PONG'
    except OSError:
        return False


def runtime_dir(database=None):
    """Where clamd's config, log and endpoint go: SENTINELAV_CLAMAV_RUNTIME, else beside the signatures.

    The evaluation guest maps signatures read-only, so it points this at a writable folder."""
    if os.environ.get('SENTINELAV_CLAMAV_RUNTIME'):
        path = Path(os.environ['SENTINELAV_CLAMAV_RUNTIME'])
        path.mkdir(parents=True, exist_ok=True)
        return path
    return database or database_dir()


def read_endpoint(database=None):
    """The endpoint written by whichever process started clamd, if it still answers."""
    path = runtime_dir(database) / ENDPOINT_FILE
    try:
        state = json.loads(path.read_text(encoding='utf-8'))
        endpoint = ('127.0.0.1', int(state['port']))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return endpoint if alive(endpoint) else None


def scan_bytes(endpoint, data, timeout=SCAN_TIMEOUT):
    """Return the signature name ClamAV reports, or None when it finds nothing."""
    if len(data) > STREAM_LIMIT:
        raise ClamAVUnavailable('Larger than the ClamAV stream limit')
    view = memoryview(data)
    with socket.create_connection(tuple(endpoint), timeout=timeout) as connection:
        connection.sendall(b'zINSTREAM\0')
        for start in range(0, len(view), CHUNK):
            part = view[start:start + CHUNK]
            connection.sendall(struct.pack('>I', len(part)) + part)
        connection.sendall(struct.pack('>I', 0))
        reply = _reply(connection)
    status = reply.split(': ', 1)[-1]
    if status == 'OK':
        return None
    if status.endswith(' FOUND'):
        return status[:-6].strip()[:120]
    raise ClamAVUnavailable('ClamAV could not scan: ' + status[:160])


class ClamdService:
    """One clamd per database directory, shared by every scan on the machine."""

    def __init__(self, home=None, database=None):
        self.home = home
        self.database = database or database_dir()
        self.runtime = runtime_dir(self.database)
        self.process = None

    def endpoint(self):
        return read_endpoint(self.database)

    def ensure_running(self, timeout=START_TIMEOUT):
        current = self.endpoint()
        if current:
            return current
        tools = binaries(self.home)
        if not tools:
            raise ClamAVUnavailable('ClamAV is not installed')
        if not has_definitions(self.database):
            raise ClamAVUnavailable('ClamAV signatures have not been downloaded')
        port = _free_port()
        config = self.runtime / 'clamd.conf'
        config.write_text(_config(self.database, port), encoding='utf-8')
        log = (self.runtime / 'clamd.log').open('ab')
        self.process = subprocess.Popen([str(tools['clamd']), '--config-file=' + str(config)], cwd=str(tools['home']),
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, creationflags=NO_WINDOW)
        log.close()
        endpoint = ('127.0.0.1', port)
        deadline = time.monotonic() + timeout
        # Loading the full database takes tens of seconds.
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise ClamAVUnavailable(f'clamd exited with code {self.process.returncode}; see clamd.log')
            if alive(endpoint):
                state = self.runtime / ENDPOINT_FILE
                state.write_text(json.dumps(dict(port=port, pid=self.process.pid)), encoding='utf-8')
                return endpoint
            time.sleep(.5)
        self.stop()
        raise ClamAVUnavailable('clamd did not start in time')

    def reload(self):
        endpoint = self.endpoint()
        if endpoint:
            _request(endpoint, b'RELOAD', 10)

    def stop(self):
        if self.process and self.process.poll() is None:
            try:
                _request(('127.0.0.1', self._port()), b'SHUTDOWN', 5)
                self.process.wait(20)
            except (OSError, subprocess.TimeoutExpired, ClamAVUnavailable):
                self.process.kill()
        self.process = None
        (self.runtime / ENDPOINT_FILE).unlink(missing_ok=True)

    def _port(self):
        try:
            return int(json.loads((self.runtime / ENDPOINT_FILE).read_text(encoding='utf-8'))['port'])
        except (OSError, ValueError, KeyError):
            return 0


def update_definitions(home=None, database=None, timeout=1800):
    """Download or refresh signatures from the official ClamAV mirror with freshclam."""
    tools = binaries(home)
    if not tools:
        raise ClamAVUnavailable('ClamAV is not installed')
    database = database or database_dir()
    config = database / 'freshclam.conf'
    config.write_text('\n'.join([f'DatabaseDirectory "{database}"', 'DatabaseMirror database.clamav.net',
        'Foreground yes', 'LogTime no', 'Bytecode yes', '']).replace('\\', '/'), encoding='utf-8')
    completed = subprocess.run([str(tools['freshclam']), '--config-file=' + str(config), '--stdout'],
        cwd=str(tools['home']), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
        creationflags=NO_WINDOW)
    if completed.returncode != 0 or not has_definitions(database):
        raise ClamAVUnavailable('freshclam failed: ' + (completed.stdout + completed.stderr)[-400:])
    return completed.stdout[-2000:]


def definitions_summary(database=None):
    database = database or database_dir()
    if not has_definitions(database):
        return dict(status='Missing', files=[])
    files = sorted(item for item in database.iterdir() if item.suffix in DATABASE_SUFFIXES)
    return dict(status='Present', files=[dict(name=item.name, bytes=item.stat().st_size,
        modified=time.strftime('%Y-%m-%d %H:%M', time.localtime(item.stat().st_mtime))) for item in files])


def ensure_service(enabled=True):
    """Start clamd when it is enabled, installed and has signatures. Returns (service, problem)."""
    if not enabled:
        return None, None
    service = ClamdService()
    try:
        service.ensure_running()
    except (ClamAVUnavailable, OSError) as error:
        return None, str(error)
    return service, None


def environment_ready():
    return os.name == 'nt' and binaries() is not None and has_definitions(database_dir())

# Purpose: Validate local IPC messages and build per-user monitoring configuration.
# Works with: paths
# Used by: monitoring.background

"""Per-user background engine. Local JSON IPC; never an elevated service.

The pipe ACL is restricted to the current user by Qt. This does not defend
against malicious code already running as that user. No remote commands,
arbitrary code execution, or automatic response actions are exposed.
"""
from sentinelav.paths import PROJECT_ROOT
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from PySide6.QtNetwork import QLocalSocket

MAX_MESSAGE = 128 * 1024
COMMANDS = {'status', 'start', 'stop', 'poll', 'shutdown'}


def endpoint(data):
    """Return the local pipe name for the background engine that serves this data folder (one engine
    per folder).
    """
    identity = str(Path(data).resolve()).casefold() if os.name == 'nt' else str(Path(data).resolve())
    return 'SentinelAV-engine-' + hashlib.sha256(identity.encode()).hexdigest()[:32]


def decode(raw):
    """Parse and strictly validate one request sent to the background engine, raising ValueError for
    anything unexpected.
    """
    if len(raw) > MAX_MESSAGE:
        raise ValueError('Request too large')
    value = json.loads(raw)
    if (not isinstance(value, dict) or type(value.get('version')) is not int or value.get('version') != 1
            or not isinstance(value.get('command'), str) or value['command'] not in COMMANDS):
        raise ValueError('Unsupported protocol or command')
    allowed = {'version', 'command'} | ({'cursor', 'epoch'} if value['command'] == 'poll' else set())
    if set(value) - allowed:
        raise ValueError('Unexpected request fields')
    if value['command'] == 'poll':
        cursor = value.get('cursor', 0)
        if type(cursor) is not int or not 0 <= cursor <= 2**53:
            raise ValueError('Invalid cursor')
        if not isinstance(value.get('epoch', ''), str) or len(value.get('epoch', '')) > 64:
            raise ValueError('Invalid epoch')
    return value


def request(data, command, **fields):
    """Send one command to the background engine and return its reply.

    The desktop app uses this to start, stop and poll real-time protection. Raises ConnectionError
    if the engine is not running, and RuntimeError if it refused the request.
    """
    payload = dict(version=1, command=command, **fields)
    encoded = json.dumps(payload).encode() + b'\n'
    decode(encoded)
    sock = QLocalSocket()
    try:
        sock.connectToServer(endpoint(data))
        if not sock.waitForConnected(1500):
            if sock.error() in (QLocalSocket.LocalSocketError.ServerNotFoundError,
                                QLocalSocket.LocalSocketError.ConnectionRefusedError):
                raise ConnectionError('Background engine unavailable: ' + sock.errorString())
            raise RuntimeError('Cannot verify background engine: ' + sock.errorString())
        sock.write(encoded)
        sock.flush()
        deadline = time.monotonic() + 3
        raw = bytearray()
        while b'\n' not in raw:
            if sock.bytesAvailable():
                raw.extend(bytes(sock.read(MAX_MESSAGE + 1 - len(raw))))
            if len(raw) > MAX_MESSAGE:
                raise ValueError('Engine reply exceeded its limit')
            if b'\n' in raw:
                break
            if time.monotonic() >= deadline or not sock.waitForReadyRead(500):
                if time.monotonic() >= deadline or sock.state() == QLocalSocket.LocalSocketState.UnconnectedState:
                    raise ConnectionError('Background engine reply timed out or disconnected')
        result = json.loads(bytes(raw).split(b'\n', 1)[0])
        if not isinstance(result, dict) or result.get('version') != 1:
            raise ValueError('Invalid engine reply')
        if not result.get('ok'):
            raise RuntimeError(result.get('error', 'Engine rejected request'))
        return result
    finally:
        sock.abort()


def configuration(store, root):
    """Build the monitoring configuration from the saved settings: watched folders, size limit,
    exclusions, canaries, enabled sources, response policy and so on. Raises ValueError for invalid
    settings.
    """
    from sentinelav.response.auto_response import policy_for
    folders = store.get('watch_folders', [])
    if not isinstance(folders, list) or len(folders) > 64 or any(
            not isinstance(p, str) or not Path(p).is_absolute() or not Path(p).is_dir() for p in folders):
        raise ValueError('Configure up to 64 existing absolute watch folders')
    cap = store.get('max_mb', 100)
    if type(cap) is not int or not 1 <= cap <= 1024:
        raise ValueError('Invalid scan size limit')
    result = dict(folders=folders, signatures=root/'signatures.json', rules=root/'rules', max_mb=cap,
                  exclusions=store.get('exclusions', []) + [str(store.path.parent)],
                  canaries=store.get('canaries', []), network_indicators=store.get('network_indicators', []),
                  trusted_hashes=store.get('trusted_hashes', []))
    result.update(inspection_options=store.get('inspection_options',{}),event_processes=store.get('event_processes',True),
                  auto_response=policy_for(store.get('auto_response',None),folders),data_dir=str(store.path.parent),artifact_updates=store.get('artifact_updates',{}))
    result.update(watch_app_changes=store.get('watch_app_changes',False),tracked_settings=store.get('tracked_settings',[]))
    result['evaluation_attestation']=store.get('evaluation_attestation',False) is True
    if store.get('kernel_collector',''): result['kernel_collector']=store.get('kernel_collector','')
    for name in ('processes', 'sysmon', 'behavior', 'network'):
        result[name] = store.get('watch_' + name, name in ('processes', 'behavior'))
        if type(result[name]) is not bool:
            raise ValueError('Invalid monitoring source setting')
    return result


def launch(data):
    """Start the background engine as a separate, detached process for this data folder."""
    if getattr(sys, 'frozen', False):
        command = [sys.executable]
    else:
        python = Path(sys.executable).with_name('pythonw.exe') if os.name == 'nt' else Path(sys.executable)
        command = [str(python), str((PROJECT_ROOT/'app.py'))]
    command += ['--engine-host', '--data-dir', str(Path(data).resolve())]
    options = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.name == 'nt':
        options['creationflags'] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options['start_new_session'] = True
    subprocess.Popen(command, **options)

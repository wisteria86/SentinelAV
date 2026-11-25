# Purpose: Opt-in DNS sinkhole: point known malware domains at a local listener and name the process that tries them.
# Works with: monitoring.deception.common
# Used by: monitoring.deception

"""Opt-in DNS sinkhole: point known malware domains at a local listener and name the process that tries them.

Domains come from abuse.ch URLhaus's public host file. They are written to the
Windows hosts file between SentinelAV's own marker lines, mapped to 127.0.0.3,
where a listener records which program tried to reach which domain. Editing the
hosts file needs administrator rights; removal deletes only SentinelAV's block.
"""
import os
import re
import socket
import subprocess
import threading
import urllib.request
from pathlib import Path

from sentinelav.monitoring.deception.common import connection_owner, describe, event, flag

SINK = '127.0.0.3'
SOURCE = 'https://urlhaus.abuse.ch/downloads/hostfile/'
BEGIN, END = '# >>> SentinelAV sinkhole (malware domains; managed automatically)', '# <<< SentinelAV sinkhole'
DOMAIN = re.compile(r'^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$')
LIMIT = 50000


def hosts_path():
    return Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'drivers' / 'etc' / 'hosts'


def fetch(url=SOURCE, timeout=30):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'SentinelAV-sinkhole/1'}), timeout=timeout) as response:
        return parse(response.read(8 * 1024 * 1024).decode('utf-8', 'replace'))


def parse(text):
    domains = []
    for line in text.splitlines():
        parts = line.split('#', 1)[0].split()
        if len(parts) >= 2 and DOMAIN.match(parts[1].casefold()) and parts[1].casefold() != 'localhost':
            domains.append(parts[1].casefold())
    return sorted(set(domains))[:LIMIT]


def without_block(text):
    return re.sub(re.escape(BEGIN) + r'.*?' + re.escape(END) + r'\r?\n?', '', text, flags=re.S)


def apply(domains, path=None):
    path = Path(path or hosts_path())
    current = path.read_text(encoding='utf-8', errors='replace')
    block = '\n'.join([BEGIN] + [f'{SINK} {domain}' for domain in domains] + [END]) + '\n'
    base = without_block(current)
    path.write_text(base + ('' if base.endswith('\n') or not base else '\n') + block, encoding='utf-8')
    _flush()
    return len(domains)


def remove(path=None):
    path = Path(path or hosts_path())
    try:
        current = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return
    if BEGIN in current:
        path.write_text(without_block(current), encoding='utf-8')
        _flush()


def _flush():
    if os.name == 'nt':
        subprocess.run(['ipconfig', '/flushdns'], capture_output=True, creationflags=0x08000000, timeout=30)


def requested_name(first):
    """The domain a client asked for: the HTTP Host header, or the TLS server name in a ClientHello."""
    match = re.search(rb'\r\nhost:\s*([^\r\n:]+)', first, re.I)
    if match:
        return match.group(1).decode('ascii', 'replace')
    try:
        if first[:1] != b'\x16' or first[5:6] != b'\x01':
            return ''
        offset = 5 + 4 + 2 + 32  # record header, handshake header, version, random
        offset += 1 + first[offset]  # session id
        offset += 2 + int.from_bytes(first[offset:offset + 2], 'big')  # cipher suites
        offset += 1 + first[offset]  # compression methods
        end = offset + 2 + int.from_bytes(first[offset:offset + 2], 'big')
        offset += 2
        while offset + 4 <= min(end, len(first)):
            kind, length = int.from_bytes(first[offset:offset + 2], 'big'), int.from_bytes(first[offset + 2:offset + 4], 'big')
            if kind == 0:  # server_name: list length, name type, name length, name
                size = int.from_bytes(first[offset + 7:offset + 9], 'big')
                return first[offset + 9:offset + 9 + size].decode('ascii', 'replace')
            offset += 4 + length
    except IndexError:
        pass
    return ''


class SinkholeListener:
    def __init__(self, emit, behavior=None, ports=(80, 443), host=SINK, owner=connection_owner):
        self.emit, self.behavior, self.ports, self.host, self.owner = emit, behavior, ports, host, owner
        self.sockets, self.skipped, self.stop_event = [], [], threading.Event()

    def start(self):
        for port in self.ports:
            server = socket.socket()
            try:
                server.bind((self.host, port))
                server.listen(16)
                server.settimeout(.5)
            except OSError:
                server.close()
                self.skipped.append(port)
                continue
            self.sockets.append(server)
            threading.Thread(target=self._serve, args=(server, port), daemon=True, name=f'sinkhole-{port}').start()
        return [server.getsockname()[1] for server in self.sockets]

    def _serve(self, server, port):
        while not self.stop_event.is_set():
            try:
                connection, (address, peer_port) = server.accept()
            except (socket.timeout, OSError):
                continue
            process = self.owner(address, peer_port)
            with connection:
                connection.settimeout(2)
                try:
                    first = connection.recv(2048)
                except OSError:
                    first = b''
            domain = requested_name(first) or 'unknown domain'
            self.emit(event('Malware domain contacted', f'{describe(process)} tried to reach {domain}, a domain listed for '
                'distributing malware. The connection went to SentinelAV\'s sinkhole instead.', domain=domain, port=port, process=process))
            flag(self.behavior, process, f'Tried to reach the malware domain {domain}', 60)

    def stop(self):
        self.stop_event.set()
        for server in self.sockets:
            server.close()
        self.sockets = []

    close = stop

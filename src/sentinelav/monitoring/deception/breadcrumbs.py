# Purpose: Breadcrumbs that lead to decoy servers on a loopback address, the listeners behind them, and a tarpit mode.
# Works with: monitoring.deception.common, monitoring.deception.registry_decoys, monitoring.honeypots
# Used by: monitoring.deception

"""Breadcrumbs that lead to decoy servers on a loopback address, the listeners behind them, and a tarpit mode.

A saved remote-desktop file, a VPN-portal shortcut and saved PuTTY and WinSCP
sessions all point at 127.0.0.2, where nothing real runs. They work as local
honeytokens: anything that follows one connects to SentinelAV's listener, which
names the connecting process. No data ever leaves this PC.
"""
import secrets
import socket
import threading
import time
from pathlib import Path

from sentinelav.monitoring.deception import registry_decoys
from sentinelav.monitoring.deception.common import DECOY_HOST, MARKER, connection_owner, describe, event, flag, profile_dirs, write_decoy
from sentinelav.monitoring.honeypots import NetworkHoneypot


def free_port(host=DECOY_HOST):
    """Ask the operating system for a free TCP port on the decoy loopback address."""
    with socket.socket() as probe:
        probe.bind((host, 0))
        return probe.getsockname()[1]


def deploy(bitcoin_dir=None):
    """Create the breadcrumbs. Returns state holding file entries, registry records and the decoy ports."""
    home, _, _ = profile_dirs()
    ports = dict(rdp=free_port(), web=free_port(), ssh=free_port(), sftp=free_port(), ftp=21)
    token = secrets.token_hex(6)
    created, entries = [], []
    documents = home / 'Documents'
    if documents.is_dir():
        rdp = (f'full address:s:{DECOY_HOST}:{ports["rdp"]}\r\nusername:s:backup-admin\r\nprompt for credentials:i:1\r\n'
               f'; {MARKER}\r\n').encode('utf-16')
        url = f'[InternetShortcut]\r\nURL=http://{DECOY_HOST}:{ports["web"]}/login?id={token}\r\n; {MARKER}\r\n'.encode('utf-8')
        for name, content in (('Backup server.rdp', rdp), ('Company VPN portal.url', url)):
            entry = write_decoy(documents / name, content, 'breadcrumb', created)
            if entry:
                entries.append(entry)
    specs = [('PuTTY saved session', r'SimonTatham\PuTTY', r'Sessions\Backup%20Server',
              dict(HostName=DECOY_HOST, PortNumber=ports['ssh'], UserName='backup-admin', Protocol='ssh')),
             ('WinSCP saved session', r'Martin Prikryl\WinSCP 2', r'Sessions\backup-admin@files',
              dict(HostName=DECOY_HOST, PortNumber=ports['sftp'], UserName='backup-admin', Password=secrets.token_hex(24)))]
    if bitcoin_dir:
        specs.append(('Bitcoin Core wallet location', r'Bitcoin\Bitcoin-Qt', '', dict(strDataDir=str(bitcoin_dir))))
    registry = registry_decoys.deploy(specs)
    return dict(entries=entries, created=created, registry=registry, ports=ports, token=token)


class DecoyServers:
    """Listens on the decoy ports of 127.0.0.2 and reports every connection with the process that made it."""

    def __init__(self, ports, emit, behavior=None, host=DECOY_HOST, owner=connection_owner):
        """Prepare listeners for the decoy ports ({label: port}); start() opens them."""
        self.labels = {port: name for name, port in ports.items()}
        self.emit, self.behavior, self.host, self.owner = emit, behavior, host, owner
        self.sockets, self.skipped, self.stop_event = [], [], threading.Event()

    def start(self):
        """Open a listener on each decoy port that is free and return the ports actually opened."""
        for port in self.labels:
            server = socket.socket()
            try:
                server.bind((self.host, port))
                server.listen(8)
                server.settimeout(.5)
            except OSError:
                server.close()
                self.skipped.append(port)
                continue
            self.sockets.append(server)
            threading.Thread(target=self._serve, args=(server, port), daemon=True, name=f'decoy-server-{port}').start()
        return [server.getsockname()[1] for server in self.sockets]

    def _serve(self, server, port):
        """Accept connections on one decoy port, identify the connecting process, and raise an alert.
        """
        while not self.stop_event.is_set():
            try:
                connection, (address, peer_port) = server.accept()
            except (socket.timeout, OSError):
                continue
            # Identify the client while its connection is still open.
            process = self.owner(address, peer_port)
            with connection:
                connection.settimeout(2)
                try:
                    first = connection.recv(256)
                except OSError:
                    first = b''
            label = self.labels[port]
            details = (f'Something followed the decoy {label} breadcrumb to {self.host}:{port}: {describe(process)}. '
                       'Only a program searching this PC for saved servers and logins would find it.')
            self.emit(event('Decoy server contacted', details, breadcrumb=label, port=port, process=process, first_bytes=first[:64].hex()))
            flag(self.behavior, process, f'Connected to the decoy {label} server')

    def stop(self):
        """Stop all listeners."""
        self.stop_event.set()
        for server in self.sockets:
            server.close()
        self.sockets = []

    close = stop


class TarpitHoneypot(NetworkHoneypot):
    """Network honeypot that holds each connection open and trickles one byte every few seconds, slowing scanners down."""

    def __init__(self, emit, ports, interval=10, hold=600, slots=32, **options):
        """Like NetworkHoneypot, but hold each connection for up to `hold` seconds, sending a byte
        every `interval` seconds, with at most `slots` held at once.
        """
        super().__init__(emit, ports, **options)
        self.interval, self.hold, self.slots = interval, hold, threading.BoundedSemaphore(slots)

    def _serve(self, server, port):
        """Accept connections, report them, and hand each one to a trickle thread (refusing new ones
        when all slots are busy).
        """
        while not self.stop_event.is_set():
            try:
                connection, (address, peer_port) = server.accept()
            except (socket.timeout, OSError):
                continue
            if not self.slots.acquire(blocking=False):
                connection.close()  # Bounded: never let a flood exhaust this PC instead.
                continue
            self._report(port, address, peer_port)
            threading.Thread(target=self._trickle, args=(connection,), daemon=True).start()

    def _report(self, port, address, peer_port):
        """Record and announce one connection to the tarpit."""
        record = dict(time=time.strftime('%Y-%m-%d %H:%M:%S'), port=port, address=address, peer_port=peer_port, first_bytes='')
        self.records = (self.records + [record])[-self.limit:]
        local = address.startswith('127.') or address == '::1'
        self.emit(dict(record, kind='Network honeypot contacted', source='Honeypot', level='Warning' if local else 'Alert',
            details=f'{address}:{peer_port} connected to decoy port {port} and is being held in a tarpit.'))

    def _trickle(self, connection):
        """Keep a connection busy by sending a single byte every few seconds until the hold time is up.
        """
        deadline = time.monotonic() + self.hold
        try:
            with connection:
                while time.monotonic() < deadline and not self.stop_event.wait(self.interval):
                    connection.sendall(b'\r')
        except OSError:
            pass
        finally:
            self.slots.release()


def remove(state):
    """Remove the breadcrumb registry entries and files, returning any files left because their content
    changed.
    """
    from sentinelav.monitoring.deception.common import remove_decoys
    registry_decoys.remove(state.get('registry', []))
    return remove_decoys(state.get('entries', []), state.get('created', []))

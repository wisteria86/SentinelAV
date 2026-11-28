# Purpose: Explainable heuristics. Scores indicate suspicion, never proof of infection.
# Works with: sibling modules in monitoring
# Used by: lab.lab, monitoring.monitor_loop, monitoring.monitoring, ui.protection_pages

"""Explainable heuristics. Scores indicate suspicion, never proof of infection."""

import hashlib
import ipaddress
import os
import time
import uuid
from collections import OrderedDict
from pathlib import Path


def create_canary(folder):
    """Create a harmless 'canary' file in a folder and return its path and hash.

    Canaries are bait: nobody should ever touch them, so if one changes, ransomware is a likely
    culprit.
    """
    path = Path(folder) / f'SentinelAV-canary-{uuid.uuid4().hex[:10]}.txt'
    content = b'SentinelAV monitoring canary. Leave this harmless file unchanged.\r\n'
    with path.open('xb') as stream:
        stream.write(content)
    return dict(path=str(path.resolve()), sha256=hashlib.sha256(content).hexdigest())


USER_WRITABLE = {'temp', 'tmp', 'downloads', 'public', 'appdata'}
REMOTE_CONTROL_PORTS = {
    1337,
    1604,
    3333,
    4444,
    4445,
    5552,
    6666,
    6667,
    6668,
    6669,
    6697,
    7777,
    8888,
    9001,
    12345,
    31337,
    54321,
}
COMMON_PORTS = {
    21,
    22,
    25,
    53,
    80,
    110,
    123,
    143,
    443,
    465,
    587,
    853,
    993,
    995,
    3478,
    5222,
    5228,
    8080,
    8443,
}


class BehaviorEngine:
    """Watches activity for suspicious behaviour and raises explainable alerts.

    Every observation adds a weighted indicator to an 'entity' (a process or a watched folder).
    Indicators older than WINDOW seconds are forgotten. When an entity's total weight reaches 30 a
    Warning is raised, and at 70 (with at least two different indicators) an Alert. Each alert lists
    its reasons, and the same alert is not repeated within a minute.
    """

    WINDOW = 60

    def __init__(self, emit, canaries=(), networks=(), clock=time.monotonic):
        """Set up empty state. emit receives alert events, canaries are the bait files to watch,
        networks are IP ranges the user flagged as bad, and clock can be replaced in tests.
        """
        self.emit, self.clock = emit, clock
        self.canaries = list(canaries)
        self.networks = [
            ipaddress.ip_network(n.strip(), strict=False) for n in networks if n.strip()
        ]
        self.entities = OrderedDict()
        self.last_alert = OrderedDict()
        self.file_activity = OrderedDict()
        self.connections = OrderedDict()
        self.canary_states = {}
        self.attributed_writes = OrderedDict()
        self.flagged_images = OrderedDict()

    def flag_image(self, path, verdict):
        """Remember a program the file scanner flagged, so its network activity can be correlated."""
        self.flagged_images[os.path.normcase(str(path))] = verdict
        while len(self.flagged_images) > 4096:
            self.flagged_images.popitem(last=False)

    def attributed_file_event(self, event, roots, exclusions):
        """Handle a file write that kernel telemetry tied to a specific process: flag bursts of writes
        and any write to a canary.
        """
        info = event['process']
        path = Path(event['path']).resolve()
        if (
            not info.get('create_time')
            or self.excluded(path, exclusions)
            or not any(path.is_relative_to(root) for root in roots)
        ):
            return
        if info.get('exe') and self.excluded(info['exe'], exclusions):
            return
        entity = f"process:{info['pid']}:{info['create_time']}"
        now = self.clock()
        paths = self.attributed_writes.setdefault(entity, OrderedDict())
        self.attributed_writes.move_to_end(entity)
        paths[str(path)] = now
        paths.move_to_end(str(path))
        while paths and (len(paths) > 1024 or now - next(iter(paths.values())) > 10):
            paths.popitem(last=False)
        metadata = dict(
            pid=info['pid'],
            path=str(info.get('exe') or ''),
            attribution='Kernel ETW with process creation-time verification',
        )
        if len(paths) >= 30:
            self.indicator(
                entity,
                'attributed_write_burst',
                35,
                f'{len(paths)} distinct file writes in 10 seconds',
                **metadata,
            )
        for canary in self.canaries:
            if path == Path(canary['path']).resolve():
                self.indicator(
                    entity,
                    'attributed_canary_write',
                    70,
                    'Kernel telemetry attributes a canary write to this process',
                    **metadata,
                )
        while len(self.attributed_writes) > 512:
            self.attributed_writes.popitem(last=False)

    def excluded(self, path, exclusions):
        """Tell whether a path is inside one of the excluded folders."""
        path = Path(path).resolve()
        return any(path == p or p in path.parents for p in exclusions)

    def indicator(self, entity, category, weight, reason, **metadata):
        """Record one indicator for an entity and raise a Warning or Alert if its combined score is
        high enough.
        """
        now = self.clock()
        facts = self.entities.setdefault(entity, {})
        self.entities.move_to_end(entity)
        facts[category] = (now, weight, reason)
        facts = {k: v for k, v in facts.items() if now - v[0] <= self.WINDOW}
        self.entities[entity] = facts
        while len(self.entities) > 2048:
            self.entities.popitem(last=False)
        score = min(100, sum(v[1] for v in facts.values()))
        level = 'Alert' if score >= 70 and len(facts) >= 2 else 'Warning' if score >= 30 else None
        if level is None:
            return
        key = (entity, level)
        if now - self.last_alert.get(key, -1000) < 60:
            return
        self.last_alert[key] = now
        if len(self.last_alert) > 4096:
            self.last_alert.popitem(last=False)
        reasons = [v[2] for v in facts.values()]
        self.emit(
            dict(
                time=time.strftime('%Y-%m-%d %H:%M:%S'),
                kind='Behavioral risk',
                details=f'Score {score}/100: ' + '; '.join(reasons),
                source='Behavior',
                level=level,
                score=score,
                indicators=[dict(category=k, weight=v[1], reason=v[2]) for k, v in facts.items()],
                entity=entity,
                classification='Suspicious activity; review required',
                **metadata,
            )
        )

    def file_event(self, kind, path, roots, exclusions):
        """Handle a file change in a watched folder, flagging bursts of changes or renames (a typical
        sign of ransomware encrypting files).
        """
        path = Path(path).resolve()
        if self.excluded(path, exclusions):
            return
        root = next((r for r in roots if path.is_relative_to(r)), None)
        if root is None:
            return
        now = self.clock()
        key = (str(root), kind, str(path))
        self.file_activity[key] = now
        self.file_activity.move_to_end(key)
        while self.file_activity and (
            len(self.file_activity) > 4096 or now - next(iter(self.file_activity.values())) > 10
        ):
            self.file_activity.popitem(last=False)
        entity = 'folder:' + str(root)
        counts = {
            k: sum(
                1
                for (r, t, p), stamp in self.file_activity.items()
                if r == str(root) and t == k and now - stamp <= 10
            )
            for k in ['modified', 'moved']
        }
        if counts['modified'] >= 30:
            self.indicator(
                entity,
                'write_burst',
                30,
                f"{counts['modified']} distinct files changed within 10 seconds",
                path=str(root),
            )
        if counts['moved'] >= 15:
            self.indicator(
                entity,
                'rename_burst',
                40,
                f"{counts['moved']} distinct rename destinations within 10 seconds",
                path=str(root),
            )

    def check_canaries(self, roots, exclusions):
        """Check every canary file and raise an indicator the first time one is changed, missing,
        replaced or unreadable.
        """
        for entry in self.canaries:
            path = Path(entry['path']).absolute()
            root = next((r for r in roots if path.is_relative_to(r)), None)
            if root is None or self.excluded(path, exclusions):
                continue
            try:
                # Only read a bounded amount; a replaced, large canary is suspicious too.
                if path.is_symlink() or not path.resolve().is_relative_to(root):
                    state = 'redirected'
                else:
                    with path.open('rb') as stream:
                        current = hashlib.sha256(stream.read(4097)).hexdigest()
                    state = 'unchanged' if current == entry['sha256'] else 'changed'
            except FileNotFoundError:
                state = 'missing'
            except OSError:
                state = 'unreadable'
            if state != 'unchanged' and self.canary_states.get(str(path)) != state:
                self.indicator(
                    'folder:' + str(root),
                    'canary',
                    70,
                    f'Canary {state}: {path.name}',
                    path=str(root),
                )
            self.canary_states[str(path)] = state

    def process(self, info, parent_name='', context_only=False, ancestors=()):
        """Check a newly seen process: running from Temp or Downloads, a command shell started by an
        Office program, or PowerShell with an encoded command.

        With context_only=True only the location is checked. Returns the entity name for the
        process, or None if it has no start time.
        """
        if not info.get('create_time'):
            return None
        entity = f"process:{info['pid']}:{info['create_time']}"
        path = str(info.get('exe') or '')
        metadata = dict(pid=info['pid'], path=path)
        parts = set(path.lower().replace('\\', '/').split('/'))
        if parts.intersection({'temp', 'tmp', 'downloads'}):
            self.indicator(
                entity,
                'user_location',
                25,
                'Executable runs from a temporary or Downloads directory',
                **metadata,
            )
        if context_only:
            return entity
        name = (info.get('name') or '').lower()
        shells = {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'}
        if name in shells and parent_name.lower() in {
            'winword.exe',
            'excel.exe',
            'powerpnt.exe',
            'outlook.exe',
        }:
            self.indicator(
                entity,
                'office_shell',
                35,
                'An Office application launched a command interpreter',
                **metadata,
            )
        elif name in shells and any(
            a.get('name', '').lower() in {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'}
            for a in ancestors
        ):
            self.indicator(
                entity,
                'office_shell',
                35,
                'An Office process is in the verified interpreter ancestry',
                **metadata,
            )
        commands = [str(v).lower() for v in info.get('cmdline') or []]
        if name in {'powershell.exe', 'pwsh.exe'} and any(
            v in {'-enc', '-encodedcommand', '-e'} for v in commands
        ):
            self.indicator(
                entity,
                'encoded_command',
                30,
                'PowerShell was launched with an encoded command',
                **metadata,
            )
        return entity

    def network(self, connections, processes):
        """Check established network connections: links to flagged IP ranges, connections from programs
        the scanner flagged, unusual ports from user folders, and contacting many different servers
        quickly.
        """
        now = self.clock()
        for connection in connections:
            if connection.status != 'ESTABLISHED' or not connection.raddr:
                continue
            info = processes.get(connection.pid)
            if not info or not info.get('create_time'):
                continue
            ip = ipaddress.ip_address(connection.raddr.ip)
            entity = f"process:{info['pid']}:{info['create_time']}"
            metadata = dict(pid=info['pid'], path=str(info.get('exe') or ''))
            # Explicit user-provided indicators may include private lab addresses.
            if any(ip in network for network in self.networks):
                self.indicator(
                    entity,
                    'network_list',
                    70,
                    f'Connection to a configured IP/CIDR indicator: {ip}',
                    **metadata,
                )
            if not ip.is_global:
                continue
            image = str(info.get('exe') or '')
            verdict = self.flagged_images.get(os.path.normcase(image))
            if verdict:
                self.indicator(
                    entity,
                    'flagged_image_network',
                    45,
                    f'A program rated {verdict} by the file scanner connected to {ip}',
                    **metadata,
                )
            parts = set(image.lower().replace('\\', '/').split('/'))
            if parts.intersection(USER_WRITABLE) and connection.raddr.port in REMOTE_CONTROL_PORTS:
                self.indicator(
                    entity,
                    'remote_control_port',
                    45,
                    f'A program in a user-writable folder connected to {ip} on port {connection.raddr.port}, commonly used for remote control',
                    **metadata,
                )
            elif parts.intersection(USER_WRITABLE) and connection.raddr.port not in COMMON_PORTS:
                self.indicator(
                    entity,
                    'uncommon_port_from_user_folder',
                    20,
                    f'A program in a user-writable folder connected to {ip} on uncommon port {connection.raddr.port}',
                    **metadata,
                )
            peers = self.connections.setdefault(entity, {})
            self.connections.move_to_end(entity)
            peers[str(ip)] = now
            if len(peers) > 256:
                peers.pop(next(iter(peers)))
            self.connections[entity] = {p: stamp for p, stamp in peers.items() if now - stamp <= 60}
            if len(self.connections[entity]) >= 20:
                self.indicator(
                    entity,
                    'network_fanout',
                    45,
                    'At least 20 public remote IPs observed within 60 seconds',
                    **metadata,
                )
        while len(self.connections) > 2048:
            self.connections.popitem(last=False)

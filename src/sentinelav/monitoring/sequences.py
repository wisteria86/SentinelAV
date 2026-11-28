# Purpose: Process-attributed ordered event correlation from an existing Sysmon channel.
# Works with: paths
# Used by: lab.qualification.telemetry, lab.runtime_job, monitoring.change_monitor, monitoring.monitoring

"""Process-attributed ordered event correlation from an existing Sysmon channel.

Never infers a file writer from timing or PID proximity. No automatic response.
"""

from collections import OrderedDict
from datetime import datetime, timezone
import ipaddress
import json
import re
import time
import uuid
import xml.etree.ElementTree as ET
from sentinelav.paths import RESOURCE_ROOT

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}


def parse_event(xml):
    """Parse one Sysmon event's XML safely into {'id', 'record', 'fields'}, rejecting oversized or
    unexpected input.
    """
    if (
        not isinstance(xml, str)
        or len(xml) > 64 * 1024
        or '<!DOCTYPE' in xml.upper()
        or '<!ENTITY' in xml.upper()
    ):
        raise ValueError('Invalid or oversized event XML')
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise ValueError('Malformed event XML') from error
    provider = root.find('e:System/e:Provider', NS)
    if provider is None or provider.get('Name') != 'Microsoft-Windows-Sysmon':
        raise ValueError('Unexpected telemetry provider')
    event_id = int(root.findtext('e:System/e:EventID', namespaces=NS))
    record = int(root.findtext('e:System/e:EventRecordID', namespaces=NS))
    fields = {}
    for node in root.findall('e:EventData/e:Data', NS):
        name = node.get('Name')
        if name in fields:
            raise ValueError('Duplicate event field')
        fields[name] = node.text or ''
    if event_id == 8:
        for target, aliases in {
            'ProcessGuid': ('SourceProcessGUID', 'SourceProcessGuid'),
            'ProcessId': ('SourceProcessId',),
            'Image': ('SourceImage',),
        }.items():
            for alias in aliases:
                if alias in fields:
                    fields[target] = fields[alias]
                    break
    return dict(id=event_id, record=record, fields=fields)


def categories(event):
    """Map a Sysmon event to a behaviour step such as 'encoded_interpreter', 'autorun_write' or
    'external_connection', or None if it is not interesting.
    """
    fields = event['fields']
    if event['id'] == 1:
        image = fields.get('Image', '').replace('\\', '/').rsplit('/', 1)[-1].casefold()
        command = fields.get('CommandLine', '')
        if image in ('powershell.exe', 'pwsh.exe') and re.search(
            r'(?i)(?:^|\s)-(?:enc|encodedcommand|e)(?:\s|$)', command
        ):
            return 'encoded_interpreter'
    if event['id'] == 13:
        target = fields.get('TargetObject', '').casefold()
        # Match whole registry key components, not filenames or malware families.
        if re.search(
            r'\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\(?:run|runonce)\\[^\\]+$',
            target,
        ):
            return 'autorun_write'
    if event['id'] == 3 and fields.get('Initiated', '').casefold() == 'true':
        try:
            if ipaddress.ip_address(fields.get('DestinationIp', '')).is_global:
                return 'external_connection'
        except ValueError:
            pass
    if event['id'] == 11:
        return 'file_create'
    if event['id'] in (23, 26):
        return 'file_delete'
    if event['id'] == 8:
        return 'remote_thread'
    if event['id'] == 25:
        return 'process_tampering'
    return None


class SequenceDetector:
    """Detects one ordered chain of behaviour steps performed by the same process.

    A policy file lists the steps (for example: encoded PowerShell, then an autorun registry write,
    then an outside connection). When one process does them all, in order and within the time
    window, an alert is raised. Processes are tracked by Sysmon's unique process GUID, never guessed
    from timing.
    """

    def __init__(self, emit, clock=time.monotonic, window=120, capacity=2048, policy=None):
        """Load and validate the sequence policy (from the default file unless one is given)."""
        self.emit = emit
        self.clock = clock
        self.window = window
        self.capacity = capacity
        self.entities = OrderedDict()
        self.last_record = 0
        if policy is None:
            path = RESOURCE_ROOT / 'behavior/sequence-policy.json'
            if path.is_symlink() or path.stat().st_size > 8192:
                raise ValueError('Invalid sequence policy file')
            policy = json.loads(path.read_text(encoding='utf-8'))
        self.policy = policy
        steps = self.policy.get('steps')
        allowed = {
            'encoded_interpreter',
            'autorun_write',
            'external_connection',
            'file_create',
            'file_delete',
            'remote_thread',
            'process_tampering',
        }
        if (
            self.policy.get('schema') != 1
            or not isinstance(self.policy.get('id'), str)
            or not isinstance(steps, list)
            or not 2 <= len(steps) <= 8
            or any(not isinstance(s, str) or s not in allowed for s in steps)
            or len(set(steps)) != len(steps)
            or not isinstance(self.policy.get('description'), str)
        ):
            raise ValueError('Invalid sequence policy schema')
        self.pattern = tuple(steps)

    def consume(self, event):
        """Feed one parsed Sysmon event in, advancing that process's progress through the sequence and
        alerting when it completes.
        """
        if event['record'] <= self.last_record:
            return
        self.last_record = event['record']
        now = self.clock()
        while self.entities and now - next(iter(self.entities.values()))['seen'] > self.window:
            self.entities.popitem(last=False)
        kind = categories(event)
        fields = event['fields']
        if kind is None:
            return
        try:
            guid = str(uuid.UUID(fields.get('ProcessGuid', '')))
            if guid == str(uuid.UUID(int=0)):
                return
            pid = int(fields['ProcessId'])
            observed = datetime.fromisoformat(fields['UtcTime'].replace('Z', '+00:00'))
            stamp = (
                observed.replace(tzinfo=timezone.utc).timestamp()
                if observed.tzinfo is None
                else observed.timestamp()
            )
        except (ValueError, KeyError, TypeError):
            return
        image = fields.get('Image', '')
        if not image or not 0 < pid < 2**32:
            return
        entity = self.entities.get(guid)
        if entity is None:
            if kind != self.pattern[0]:
                return
            entity = dict(seen=now, start=stamp, pid=pid, image=image, events=[])
            self.entities[guid] = entity
        if entity['pid'] != pid or entity['image'].casefold() != image.casefold():
            return
        if stamp < entity['start'] or stamp - entity['start'] > self.window:
            return
        if entity['events'] and stamp < entity['events'][-1]['timestamp']:
            return
        entity['seen'] = now
        self.entities.move_to_end(guid)
        while len(self.entities) > self.capacity:
            self.entities.popitem(last=False)
        index = len(entity['events'])
        if index == len(self.pattern) or kind != self.pattern[index]:
            return
        entity['events'].append(dict(category=kind, record_id=event['record'], timestamp=stamp))
        if len(entity['events']) == len(self.pattern):
            self.emit(
                dict(
                    time=time.strftime('%Y-%m-%d %H:%M:%S'),
                    kind='Suspicious behavior sequence',
                    details=self.policy['description'],
                    rule_id=self.policy['id'],
                    source='Sysmon correlation',
                    level='Alert',
                    pid=pid,
                    path=image,
                    process_guid=guid,
                    sequence=list(entity['events']),
                    classification='Suspicious sequence; review required',
                    automatic_response_eligible=False,
                )
            )


class BehaviorCorrelator:
    """Multiple ordered policies and attributed destructive-activity windows."""

    def __init__(self, emit, clock=time.monotonic):
        """Load every additional sequence policy and prepare the detectors."""
        self.emit = emit
        self.clock = clock
        path = RESOURCE_ROOT / 'behavior/additional-sequences.json'
        if path.is_symlink() or path.stat().st_size > 32768:
            raise ValueError('Invalid behavior policies')
        policies = json.loads(path.read_text(encoding='utf-8'))
        if (
            policies.get('schema') != 1
            or not isinstance(policies.get('rules'), list)
            or len(policies['rules']) > 16
        ):
            raise ValueError('Invalid behavior policy set')
        self.detectors = [SequenceDetector(emit, clock=clock)] + [
            SequenceDetector(emit, clock=clock, policy=p) for p in policies['rules']
        ]
        self.activity = OrderedDict()
        self.last_record = 0
        self.parents = OrderedDict()

    def consume(self, event):
        """Feed one event to every detector, remember parent links, and alert when one process creates
        and deletes many files within 10 seconds (a possible sign of destructive activity).
        """
        if event['record'] <= self.last_record:
            return
        self.last_record = event['record']
        for detector in self.detectors:
            detector.consume(event)
        fields = event['fields']
        now = self.clock()
        try:
            guid = str(uuid.UUID(fields.get('ProcessGuid', '')))
            pid = int(fields['ProcessId'])
        except (ValueError, TypeError, KeyError):
            return
        if not 0 < pid < 2**32 or not fields.get('Image'):
            return
        if event['id'] == 1:
            try:
                parent = str(uuid.UUID(fields.get('ParentProcessGuid', '')))
            except ValueError:
                parent = None
            self.parents[guid] = dict(parent=parent, pid=pid, image=fields['Image'], seen=now)
            self.parents.move_to_end(guid)
            while len(self.parents) > 2048:
                self.parents.popitem(last=False)
        if event['id'] not in (11, 23, 26):
            return
        target = fields.get('TargetFilename')
        if not target:
            return
        state = self.activity.setdefault(
            guid, dict(pid=pid, image=fields['Image'], paths=OrderedDict(), warned=0)
        )
        self.activity.move_to_end(guid)
        if state['pid'] != pid or state['image'].casefold() != fields['Image'].casefold():
            return
        state['paths'][(event['id'] == 11, target.casefold())] = now
        state['paths'].move_to_end((event['id'] == 11, target.casefold()))
        while state['paths'] and (
            len(state['paths']) > 1024 or now - next(iter(state['paths'].values())) > 10
        ):
            state['paths'].popitem(last=False)
        creates = sum(created for created, path in state['paths'])
        deletes = sum(not created for created, path in state['paths'])
        # A scoped operational threshold, not a learned malware probability.
        if creates >= 30 and deletes >= 30 and now - state['warned'] >= 60:
            state['warned'] = now
            lineage = []
            current = guid
            visited = set()
            for _ in range(8):
                if current in visited or current not in self.parents:
                    break
                visited.add(current)
                node = self.parents[current]
                if now - node['seen'] > 600:
                    break
                lineage.append(dict(process_guid=current, pid=node['pid'], image=node['image']))
                current = node['parent']
            self.emit(
                dict(
                    time=time.strftime('%Y-%m-%d %H:%M:%S'),
                    kind='Attributed file churn',
                    details=f'{creates} created and {deletes} deleted paths within 10 seconds; review possible destructive activity.',
                    source='Sysmon correlation',
                    level='Alert',
                    pid=pid,
                    path=state['image'],
                    process_guid=guid,
                    lineage=lineage,
                    classification='Suspicious activity; not confirmed ransomware',
                    automatic_response_eligible=False,
                )
            )
        while len(self.activity) > 512:
            self.activity.popitem(last=False)

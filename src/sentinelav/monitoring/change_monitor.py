# Purpose: Compare inventories and record observed changes in the encrypted journal.
# Works with: data.change_journal, data.contracts, monitoring.sequences, monitoring.windows_inventory,
#   platform.service_changes
# Used by: monitoring.app_changes

"""Read-only persistence inventory, honest attribution, and encrypted reconciliation."""

import os
import threading
import time
import queue
from sentinelav.data.contracts import change_record, fingerprint
from sentinelav.data.change_journal import ChangeJournal

MAX_FILE = 1024 * 1024
RUN_KEYS = (
    r'Software\Microsoft\Windows\CurrentVersion\Run',
    r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
)
from .windows_inventory import WindowsInventory


class ChangeTracker:
    """Compares the current list of autostart entries with the last saved one and records every
    difference.
    """

    def __init__(self, journal, inventory):
        """Use `journal` to store snapshots and changes, and `inventory` to list the current autostart
        entries.
        """
        self.journal, self.inventory = journal, inventory

    def poll(self, observations=(), inventory_result=None):
        """Take a fresh inventory, record new, changed and removed entries, and return the changes.

        If Sysmon telemetry (observations) shows exactly which process wrote a registry value, the
        change is marked as Verified for that process; a looser match is marked Correlated. Entries
        seen during the very first inventory are recorded as pre-existing rather than as new
        changes.
        """
        result = inventory_result or self.inventory.collect()
        seen = set()
        changes = []
        for target, state in result['rows']:
            key = fingerprint(target)
            if key in seen:
                continue
            seen.add(key)
            prior = self.journal.snapshot(target)
            if prior and fingerprint(prior['state']) == fingerprint(state):
                continue
            baseline = prior is None and not self.journal.initialized(target['kind'])
            record = change_record(
                target,
                prior['state'] if prior else (None if baseline else dict(exists=False)),
                state,
                baseline=baseline,
            )
            matches = [o for o in observations if o.get('resource_id') == key]
            if (
                len(matches) == 1
                and matches[0].get('after_hash') == fingerprint(state)
                and matches[0].get('source') == 'Sysmon13'
            ):
                record = change_record(
                    target,
                    record['before'],
                    state,
                    baseline=baseline,
                    attribution='Verified',
                    process=matches[0]['process'],
                )
            elif matches:
                record['attribution'] = 'Correlated'
                record['process'] = matches[-1].get('process')
            self.journal.commit_observation(target, state, record)
            changes.append(record)
        for prior in self.journal.snapshots():
            target, state = prior['resource'], prior['state']
            if target['kind'] == 'setting_file' and target.get('path') not in list(
                map(str, self.inventory.settings)
            ):
                continue
            if (
                fingerprint(target) not in seen
                and target['kind'] in result['complete']
                and state.get('exists')
            ):
                after = dict(exists=False)
                record = change_record(target, state, after)
                self.journal.commit_observation(target, after, record)
                changes.append(record)
        self.journal.mark_initialized(result['complete'])
        return dict(changes=changes, errors=result['errors'], complete=result['complete'])


class ChangeMonitor:
    """Background thread that tracks changes to autostart locations (Run keys, startup folders, tasks,
    services and chosen setting files) every `interval` seconds.
    """

    def __init__(
        self, folder, settings=(), emit=lambda event: None, interval=30, service_owner=None
    ):
        """Prepare the monitor (the thread is not started yet). emit receives a summary event after
        each round.
        """
        self.folder, self.settings, self.emit, self.interval = folder, settings, emit, interval
        self.service_owner = service_owner
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name='app-change-tracker')
        self.telemetry = queue.Queue(maxsize=1024)
        self.dropped = 0
        self.process_guids = {}

    def start(self):
        """Start the tracking thread."""
        self.thread.start()

    def observe_sysmon(self, row):
        """Queue one raw Sysmon event for the next round (dropped if the queue is full)."""
        try:
            self.telemetry.put_nowait(row)
        except queue.Full:
            self.dropped += 1

    def observations(self, inventory):
        """Turn queued Sysmon events into verified 'this process wrote this registry value' facts.

        Process-creation events (id 1) are matched to a live process by id and exact start time;
        registry-write events (id 13) from those processes are then matched to watched registry
        values.
        """
        from sentinelav.monitoring.sequences import parse_event
        from datetime import datetime, timezone
        import psutil

        result = []
        for _ in range(1024):
            try:
                raw = self.telemetry.get_nowait()
            except queue.Empty:
                break
            try:
                event = parse_event(raw['Xml'])
                fields = event['fields']
                guid = fields.get('ProcessGuid')
                if event['id'] == 1:
                    process = psutil.Process(int(fields['ProcessId']))
                    creation = process.create_time()
                    observed = (
                        datetime.fromisoformat(fields['UtcTime'].replace(' ', 'T'))
                        .replace(tzinfo=timezone.utc)
                        .timestamp()
                    )
                    if abs(creation - observed) > 0.05 or os.path.normcase(
                        process.exe()
                    ) != os.path.normcase(fields.get('Image', '')):
                        continue
                    self.process_guids[guid] = dict(
                        pid=process.pid,
                        creation=creation,
                        path=process.exe(),
                        source='Sysmon process creation',
                    )
                    if len(self.process_guids) > 4096:
                        self.process_guids.pop(next(iter(self.process_guids)))
                elif event['id'] == 13 and guid in self.process_guids:
                    identity = self.process_guids[guid]
                    if identity['pid'] != int(fields['ProcessId']):
                        continue
                    # Exact value, resource and process-start evidence are required.
                    for prior in inventory:
                        target = prior['resource']
                        if target['kind'] != 'registry':
                            continue
                        native = target['hive'] + '\\' + target['key'] + '\\' + target['name']
                        if target['view'] == 32 and target['hive'] == 'HKLM':
                            native = native.replace('\\Software\\', '\\Software\\WOW6432Node\\')
                        if fields.get('TargetObject', '').casefold() != native.casefold():
                            continue
                        state = dict(exists=True, value=fields.get('Details', ''), type=1)
                        result.append(
                            dict(
                                resource_id=fingerprint(target),
                                after_hash=fingerprint(state),
                                process=identity,
                                source='Sysmon13',
                            )
                        )
            except (ValueError, KeyError, OSError, psutil.Error):
                self.dropped += 1
        return result

    def run(self):
        """Main loop: inventory, match telemetry, record changes, and emit a summary, until stopped."""
        journal = None
        try:
            journal = ChangeJournal(self.folder)
            tracker = ChangeTracker(
                journal, WindowsInventory(self.settings, service_scope=bool(self.service_owner))
            )
            while not self.stop.is_set():
                inventory = tracker.inventory.collect()
                observations = self.observations(
                    [dict(resource=target, state=state) for target, state in inventory['rows']]
                )
                result = tracker.poll(observations, inventory)
                if self.service_owner:
                    from sentinelav.platform.service_changes import publish_view

                    publish_view(self.folder.parent, journal, self.service_owner, result['errors'])
                from sentinelav.response.remediation import referenced_paths

                candidates = []
                for record in result['changes']:
                    try:
                        candidates.extend(referenced_paths(record))
                    except (ValueError, KeyError):
                        pass
                self.emit(
                    dict(
                        kind='App change tracking',
                        source='App Changes',
                        level='Warning' if result['errors'] else 'Info',
                        time=time.strftime('%Y-%m-%d %H:%M:%S'),
                        details=f"{len(result['changes'])} recorded changes; {len(result['errors'])} inventory omissions",
                        change_ids=[r['id'] for r in result['changes']],
                        candidate_paths=list(dict.fromkeys(candidates))[:64],
                        omissions=result['errors'][:16],
                        telemetry_dropped=self.dropped,
                    )
                )
                self.stop.wait(self.interval)
        except Exception as error:
            self.emit(
                dict(
                    kind='App change tracking unavailable',
                    source='App Changes',
                    level='Warning',
                    details=str(error),
                )
            )
        finally:
            if journal:
                journal.close()

    def close(self):
        """Stop the thread and wait for it to finish."""
        self.stop.set()
        self.thread.join()

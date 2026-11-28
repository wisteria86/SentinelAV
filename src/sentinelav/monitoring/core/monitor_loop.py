# Purpose: Own monitoring startup, event draining, periodic work, and shutdown.
# Works with: detection.inspection, detection.helpers.reputation, monitoring.app_changes, monitoring.core.behavior,
#   monitoring.core.event_sources
# Used by: monitoring.monitoring

"""Bounded, read-only monitoring. No files are removed and no processes are stopped."""

import time
import queue
from pathlib import Path
from watchdog.observers import Observer
import psutil
from sentinelav.detection.inspection import IsolatedScanner as Scanner
from sentinelav.monitoring.core.behavior import BehaviorEngine
from sentinelav.monitoring.core.process_telemetry import ProcessEvents
from .event_sources import Changes, SysmonReader
from .health import verified_network_processes


class MonitorLoopMixin:
    """The main real-time protection loop used by Monitor."""

    def run(self):
        """Start every enabled protection source and keep them running until stop is set.

        Setup: create the persistent scanner, optional update, reputation, auto-response, behaviour,
        honeypot, deception and kernel components, and start watching the chosen folders. Then,
        roughly every 100 ms, the loop polls each source on its own schedule (processes every 3 s,
        Sysmon every 15 s, network every 5 s, canaries every 2 s), scans one queued file, and
        publishes a status summary every 2 s. On exit every component is closed, and failures are
        reported rather than hidden.
        """
        observer = Observer()
        try:
            if self.config.get('watch_app_changes') and self.config.get('data_dir'):
                from sentinelav.monitoring.app_changes import ChangeMonitor

                def change_event(event):
                    """Pass on an app-change event and queue any programs it references for scanning."""
                    self.emit(event)
                    for candidate in event.get('candidate_paths', []):
                        self.pending.add(candidate, 'App Changes')

                self.change_monitor = ChangeMonitor(
                    Path(self.config['data_dir']) / 'app-changes',
                    self.config.get('tracked_settings', []),
                    change_event,
                    service_owner=self.config.get('service_owner'),
                )
                self.change_monitor.start()
            from sentinelav.platform.core.engine_policy import inspection_options

            self.config['inspection_options'] = inspection_options(
                self.config.get('inspection_options')
            )
            if self.config.get('artifact_updates', {}).get('enabled') and self.config.get(
                'data_dir'
            ):
                options = dict(self.config.get('inspection_options', {}))
                options.setdefault(
                    'analysis_store', str(Path(self.config['data_dir']) / 'analysis-data')
                )
                self.config['inspection_options'] = options
            scanner = Scanner(
                self.config['signatures'],
                self.config['rules'],
                self.config['max_mb'],
                self.config['exclusions'],
                self.config.get('trusted_hashes', []),
                options=self.config.get('inspection_options'),
                persistent=True,
            )
            for warning in scanner.warnings:
                self.event('Engine warning', warning, 'Engine', 'Warning')
            update_config = self.config.get('artifact_updates', {})
            if update_config.get('enabled') and self.config.get('data_dir'):
                try:
                    from sentinelav.updates.agent import ArtifactUpdater
                    from sentinelav.paths import RESOURCE_ROOT

                    folder = self.config.get('inspection_options', {}).get(
                        'analysis_store', str(Path(self.config['data_dir']) / 'analysis-data')
                    )
                    trust = self.config['inspection_options'].get(
                        'analysis_trust', str(RESOURCE_ROOT / 'trusted-update-keys.json')
                    )
                    self.artifact_updater = ArtifactUpdater(update_config, folder, trust)
                except Exception as error:
                    self.event(
                        'Analysis updates unavailable', str(error), 'Signed updates', 'Warning'
                    )
            if self.config.get('inspection_options', {}).get('reputation'):
                try:
                    from sentinelav.updates.artifacts import active
                    from sentinelav.detection.helpers.reputation import ReputationIndex
                    from sentinelav.paths import RESOURCE_ROOT

                    folder = self.config.get('inspection_options', {}).get(
                        'analysis_store', str(RESOURCE_ROOT / 'analysis-data')
                    )
                    trust = self.config['inspection_options'].get(
                        'analysis_trust', str(RESOURCE_ROOT / 'trusted-update-keys.json')
                    )
                    self.network_reputation = ReputationIndex(*active(folder, trust, 'reputation'))
                except Exception as error:
                    self.event(
                        'DNS reputation unavailable',
                        str(error)[:300],
                        'Signed reputation',
                        'Warning',
                    )
            roots = []
            for item in self.config['folders']:
                original = Path(item)
                root = original.resolve()
                if not root.is_dir() or original.is_symlink() or original.is_junction():
                    raise ValueError(f'Monitor folder is unavailable or a link: {root}')
                if scanner.excluded(root):
                    raise ValueError(f'Monitor folder is excluded: {root}')
                # Collapse nested roots so watchdog cannot schedule duplicate trees.
                if not any(root == r or r in root.parents for r in roots):
                    roots = [r for r in roots if root not in r.parents]
                    roots.append(root)
            self.allowed_roots = roots
            self.exclusions = scanner.exclusions
            policy = self.config.get('auto_response', {})
            if policy.get('enabled') and self.config.get('data_dir'):
                from sentinelav.response.auto_response import AutoResponder

                self.responder = AutoResponder(
                    self.config['data_dir'],
                    Path(self.config['signatures']).parent,
                    policy,
                    self.emit,
                )
            if self.config.get('behavior') or self.config.get('network'):
                self.behavior = BehaviorEngine(
                    self.emit,
                    self.config.get('canaries', []),
                    self.config.get('network_indicators', []),
                )
            from sentinelav.monitoring.helpers.honeypots import HoneypotWatcher, NetworkHoneypot

            self.honeypots = (
                HoneypotWatcher(self.config['honeypots'], self.emit, self.behavior)
                if self.config.get('honeypots')
                else None
            )
            from sentinelav.monitoring.deception.breadcrumbs import TarpitHoneypot

            self.network_honeypot = (
                (TarpitHoneypot if self.config.get('tarpit') else NetworkHoneypot)(
                    self.emit, self.config['network_honeypot']
                )
                if self.config.get('network_honeypot')
                else None
            )
            if self.config.get('deception'):
                from sentinelav.monitoring.deception import DeceptionRuntime

                self.deception = DeceptionRuntime(
                    self.config['deception'],
                    self.emit,
                    self.behavior,
                    self.config.get('data_dir') or '.',
                )
                self.deception.start()
            if self.network_honeypot:
                bound = self.network_honeypot.start()
                self.event(
                    'Network honeypot listening',
                    f'Ports {bound}; ports already in use were left alone: {self.network_honeypot.skipped}',
                    'Honeypot',
                )
            if self.config.get('kernel_collector') and self.config.get('behavior'):
                try:
                    from sentinelav.monitoring.helpers.kernel_telemetry import KernelFileEvents

                    self.kernel_reader = KernelFileEvents(self.config['kernel_collector'])
                except Exception as error:
                    self.event('Kernel telemetry unavailable', str(error), 'Kernel ETW', 'Warning')
                    self.health.unavailable('Kernel ETW', error)
            if (
                not roots
                and not self.config['processes']
                and not self.config['sysmon']
                and not self.config.get('network')
                and not self.change_monitor
            ):
                raise ValueError('Choose at least one monitoring source')
            for root in roots:
                observer.schedule(
                    Changes(self.pending, self.file_activity if self.behavior else None),
                    str(root),
                    recursive=True,
                )
            if roots:
                observer.start()
            self.event(
                'Monitoring started',
                f'{len(roots)} folder(s); process tracking: {self.config["processes"]}',
                'Protection',
            )
            reader = SysmonReader() if self.config['sysmon'] else None
            process_reader = None
            if self.config['processes'] and self.config.get('event_processes', False):
                try:
                    process_reader = ProcessEvents()
                    process_reader.start()
                except Exception as error:
                    self.event(
                        'Process event source unavailable',
                        str(error),
                        'WMI process events',
                        'Warning',
                    )
                    self.health.unavailable('Process events', error)
                    if process_reader:
                        process_reader.close()
                    process_reader = None
            next_process = 0
            next_sysmon = 0
            next_status = 0
            next_network = 0
            next_canary = 0
            network_available = self.config.get('network', False)
            denied = 0
            # Main loop. Each source is polled on its own timer so a slow one never starves the
            # others.
            while not self.stop.is_set():
                now = time.monotonic()
                if self.artifact_updater:
                    for update in self.artifact_updater.poll():
                        self.event(
                            'Analysis update ' + update['kind'],
                            str(update),
                            'Signed updates',
                            'Warning' if update['kind'] == 'failed' else 'Info',
                        )
                        if update['kind'] == 'updated':
                            scanner.close()  # Persistent scanner reinitializes on its next request.
                            if update['channel'] == 'reputation':
                                try:
                                    from sentinelav.updates.artifacts import active
                                    from sentinelav.detection.helpers.reputation import (
                                        ReputationIndex,
                                    )
                                    from sentinelav.paths import RESOURCE_ROOT

                                    if self.config['inspection_options'].get('reputation'):
                                        self.network_reputation = ReputationIndex(
                                            *active(
                                                self.artifact_updater.store,
                                                self.artifact_updater.trust,
                                                'reputation',
                                            )
                                        )
                                except Exception as error:
                                    self.event(
                                        'DNS reputation refresh failed',
                                        str(error),
                                        'Signed updates',
                                        'Warning',
                                    )
                if self.kernel_reader:
                    for event in self.kernel_reader.poll():
                        if self.behavior:
                            self.behavior.attributed_file_event(event, roots, self.exclusions)
                    self.health.lost(
                        'Kernel ETW',
                        sum(
                            getattr(self.kernel_reader, k, 0)
                            for k in (
                                'dropped',
                                'native_dropped',
                                'etw_lost',
                                'unresolved_paths',
                                'unresolved_identities',
                            )
                        ),
                        cumulative=True,
                    )
                    if self.kernel_reader.error:
                        self.event(
                            'Kernel telemetry unavailable',
                            self.kernel_reader.error,
                            'Kernel ETW',
                            'Warning',
                        )
                        self.health.unavailable('Kernel ETW', self.kernel_reader.error)
                        self.kernel_reader.close()
                        self.kernel_reader = None
                if process_reader:
                    try:
                        for event in process_reader.poll():
                            self.process_event(event)
                        self.process_event_drops = process_reader.dropped
                        self.health.lost(
                            'Process events', self.process_event_drops, cumulative=True
                        )
                    except Exception as error:
                        self.event(
                            'Process event source unavailable',
                            str(error) + '; snapshot polling remains active',
                            'WMI process events',
                            'Warning',
                        )
                        self.health.unavailable('Process events', error)
                        process_reader.close()
                        process_reader = None
                if (self.config['processes'] or network_available) and now >= next_process:
                    denied = self.processes() or 0
                    next_process = now + 3
                if reader and now >= next_sysmon:
                    try:
                        for row in reader.poll():
                            self.sysmon_event(row)
                    except Exception as error:
                        self.event('Sysmon unavailable', str(error), 'Sysmon', 'Warning')
                        self.health.unavailable('Sysmon', error)
                        reader = None
                        if (
                            not roots
                            and not self.config['processes']
                            and not network_available
                            and not self.change_monitor
                        ):
                            raise RuntimeError(
                                'No monitoring sources remain available. Add a watched folder or enable process tracking.'
                            )
                    next_sysmon = now + 15
                if self.behavior:
                    for _ in range(100):
                        try:
                            kind, path = self.activity.get_nowait()
                        except queue.Empty:
                            break
                        if self.config.get('behavior'):
                            self.behavior.file_event(kind, path, roots, self.exclusions)
                    if self.config.get('behavior') and now >= next_canary:
                        self.behavior.check_canaries(roots, self.exclusions)
                        next_canary = now + 2
                    if network_available and now >= next_network:
                        try:
                            connections = psutil.net_connections(kind='inet')
                            self.network_count = sum(c.status == 'ESTABLISHED' for c in connections)
                            visible, omitted = verified_network_processes(
                                connections,
                                self.process_infos,
                                self.exclusions,
                                self.behavior.excluded,
                            )
                            self.health.lost('Network process identities', omitted)
                            self.behavior.network(connections, visible)
                        except (psutil.Error, OSError, RuntimeError) as error:
                            self.event(
                                'Network telemetry unavailable', str(error), 'Network', 'Warning'
                            )
                            self.health.unavailable('Network', error)
                            network_available = False
                            if (
                                not roots
                                and not self.config['processes']
                                and not reader
                                and not self.change_monitor
                            ):
                                raise RuntimeError('No monitoring sources remain available')
                        next_network = now + 5
                # Scan at most one queued file per round, so the loop stays responsive.
                item = self.pending.pop()
                if item:
                    self.inspect(scanner, *item)
                if now >= next_status:
                    with self.pending.lock:
                        lost = self.pending.dropped
                        self.pending.dropped = 0
                    self.health.lost('Filesystem', lost)
                    self.status(
                        dict(
                            checked=self.checked,
                            processes=self.process_count,
                            denied=denied,
                            queued=len(self.pending.items),
                            folders=len(roots),
                            dropped=lost,
                            sysmon=reader is not None,
                            **self.health.status(),
                            network=network_available,
                            connections=self.network_count,
                            behavior=self.config.get('behavior', False),
                            signature_count=len(scanner.signatures),
                            yara_research_rules=scanner.rule_summary['research_rules'],
                            yara_public_rules=scanner.rule_summary['public_rules'],
                            process_event_source=(
                                'WMI subscribed'
                                if process_reader and process_reader.ready
                                else 'Polling only'
                            ),
                            process_event_drops=self.process_event_drops,
                            uninspected_process_events=self.uninspected_process_events,
                            inspection_isolation='Separate process with Windows job limits',
                            automatic_response=bool(
                                self.responder and self.responder.ready and self.responder.enabled
                            ),
                            inspection_error=self.inspection_error,
                            kernel_file_telemetry=(
                                'Active'
                                if self.kernel_reader and self.kernel_reader.ready
                                else 'Unavailable / not configured'
                            ),
                            kernel_event_drops=(
                                (
                                    self.kernel_reader.dropped
                                    + getattr(self.kernel_reader, 'native_dropped', 0)
                                    + getattr(self.kernel_reader, 'etw_lost', 0)
                                    + getattr(self.kernel_reader, 'unresolved_paths', 0)
                                    + getattr(self.kernel_reader, 'unresolved_identities', 0)
                                )
                                if self.kernel_reader
                                else 0
                            ),
                            kernel_loss_counters_available=bool(
                                self.kernel_reader
                                and getattr(self.kernel_reader, 'last_heartbeat', 0)
                            ),
                            sequence_telemetry=(
                                'Sysmon channel connected; event coverage depends on its configuration'
                                if reader
                                else 'Unavailable; requires Sysmon events 1, 3 and 13'
                            ),
                            signature_database=(
                                scanner.signatures.metadata.get('database')
                                if scanner.signatures.metadata
                                else 'Local JSON'
                            ),
                        )
                    )
                    if lost:
                        self.event(
                            'Monitoring backlog',
                            f'{lost} file events dropped; run an on-demand scan to cover omissions.',
                            'Filesystem',
                            'Warning',
                        )
                    next_status = now + 2
                    if self.honeypots:
                        self.honeypots.poll()
                    if getattr(self, 'deception', None):
                        self.deception.poll()
                if not item:
                    self.stop.wait(0.1)
        finally:
            if self.artifact_updater:
                try:
                    self.artifact_updater.close()
                except Exception as error:
                    self.event(
                        'Update shutdown incomplete', str(error), 'Signed updates', 'Warning'
                    )
                self.artifact_updater = None
            owned = [
                ('app changes', self.change_monitor),
                ('kernel collector', self.kernel_reader),
                ('automatic responder', self.responder),
                ('process events', locals().get('process_reader')),
                ('scanner', locals().get('scanner')),
                ('network honeypot', getattr(self, 'network_honeypot', None)),
                ('deception', getattr(self, 'deception', None)),
            ]
            for name, resource in owned:
                if resource is None:
                    continue
                try:
                    resource.close()
                except Exception as error:
                    self.event(
                        'Monitoring cleanup incomplete',
                        name + ': ' + str(error),
                        'Protection',
                        'Warning',
                    )
            self.kernel_reader = None
            self.responder = None
            if observer.is_alive():
                observer.stop()
                observer.join(timeout=5)
                if observer.is_alive():
                    self.event(
                        'Monitoring cleanup incomplete',
                        'Filesystem observer has not stopped yet',
                        'Protection',
                        'Warning',
                    )
            self.event('Monitoring stopped', 'This monitoring session has stopped.', 'Protection')

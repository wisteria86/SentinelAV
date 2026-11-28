# Purpose: Deploy, run and remove SentinelAV's deception features beyond the basic decoy files.
# Works with: monitoring.deception.* , monitoring.honeypots
# Used by: monitoring.monitor_loop, ui.deception_ui

"""Deploy, run and remove SentinelAV's deception features beyond the basic decoy files.

Deployment (files, registry entries, account, share, hosts file) happens once in
the app; the monitor then runs the live parts: decoy servers, the clipboard
guard, decoy processes, infection markers, the sinkhole listener and the logon
watcher. Decoy files are handed to the existing honeypot watcher, so reads of a
fake browser store are reported exactly like reads of a decoy document.
"""

import time
from pathlib import Path

from sentinelav.monitoring.deception.common import event

# Safe for every user and on by default; the rest are opt-in.
DEFAULTS = dict(
    stores=True,
    breadcrumbs=True,
    clipboard=True,
    vaccines=True,
    clipboard_bait=False,
    bait_processes=False,
    analysis_decoys=False,
    memory_credentials=False,
    tarpit=False,
    sinkhole=False,
    decoy_account=False,
    decoy_share=False,
)


def deploy(options, data_dir):
    """Create every enabled decoy that is not already present. Returns the state to keep, including what failed."""
    from sentinelav.monitoring.deception import breadcrumbs, stores

    options = dict(DEFAULTS, **(options or {}))
    state, problems = dict(options=options), []
    if options['stores']:
        _, state['stores'] = stores.deploy()
    if options['breadcrumbs']:
        wallet = next(
            (
                Path(store['root']) / 'wallets' / 'decoy'
                for store in state.get('stores', [])
                if store['name'] == 'Bitcoin Core'
            ),
            None,
        )
        state['breadcrumbs'] = breadcrumbs.deploy(wallet)
    if options['memory_credentials']:
        from sentinelav.monitoring.deception.processes import fake_credentials

        state['credentials'] = fake_credentials()
    if options['decoy_account']:
        from sentinelav.monitoring.deception import accounts

        try:
            state['account'] = accounts.create_account()
        except Exception as error:
            problems.append(f'Decoy account: needs administrator rights ({str(error)[:80]})')
    if options['decoy_share']:
        from sentinelav.monitoring.deception import accounts
        from sentinelav.monitoring.deception.common import write_decoy

        folder, created = Path(data_dir) / 'decoy-share', []
        files = [
            write_decoy(
                folder / name,
                b'SENTINELAV DECOY. Holds no real data.\r\n'
                + __import__('secrets').token_bytes(512),
                'decoy_share',
                created,
            )
            for name in ('payroll-2026.xlsx', 'server-passwords.kdbx', 'backup-keys.txt')
        ]
        try:
            state['share'] = dict(
                name=accounts.create_share(folder),
                entries=[item for item in files if item],
                created=created,
            )
        except Exception as error:
            problems.append(f'Decoy share: needs administrator rights ({str(error)[:80]})')
    if options['sinkhole']:
        from sentinelav.monitoring.deception import sinkhole

        try:
            state['sinkhole'] = dict(domains=sinkhole.apply(sinkhole.fetch()), updated=time.time())
        except Exception as error:
            problems.append(
                f'Sinkhole: {str(error)[:100]} (editing the hosts file needs administrator rights)'
            )
    state['problems'] = problems
    return state


def file_entries(state):
    """Decoy files for the honeypot watcher, which reports reads, changes and deletions."""
    entries = [entry for store in state.get('stores', []) for entry in store['entries']]
    entries += state.get('breadcrumbs', {}).get('entries', [])
    return entries + state.get('share', {}).get('entries', [])


def remove(state):
    """Remove every deception item described by `state` (stores, breadcrumbs, share, account, sinkhole,
    marker files).

    Returns the decoy files that were left in place because their content had changed (someone or
    something edited them).
    """
    from sentinelav.monitoring.deception import accounts, breadcrumbs, sinkhole, stores, vaccines

    left = stores.remove(state.get('stores', [])) + breadcrumbs.remove(state.get('breadcrumbs', {}))
    if state.get('share'):
        accounts.remove_share(state['share']['name'])
        from sentinelav.monitoring.deception.common import remove_decoys

        left += remove_decoys(state['share']['entries'], state['share']['created'])
    if state.get('account'):
        accounts.remove_account(state['account'])
    if state.get('sinkhole'):
        sinkhole.remove()
    # Marker files are deleted only if they still hold SentinelAV's own text, so passing every known path is safe.
    vaccines.remove_files(
        [path for item in vaccines.markers() if item['type'] == 'file' for path in item['paths']]
    )
    return left


class DeceptionRuntime:
    """The live parts, run by the monitor. Every part is optional and fails on its own without stopping the rest."""

    def __init__(self, state, emit, behavior=None, data_dir='.'):
        """Remember the deployed state; nothing starts until start() is called."""
        self.state, self.emit, self.behavior, self.data_dir = state, emit, behavior, Path(data_dir)
        self.parts, self.notes, self.next_slow = {}, [], 0

    def _try(self, name, build):
        """Build one part, recording a note instead of failing if it cannot start."""
        try:
            self.parts[name] = build()
        except Exception as error:
            self.notes.append(f'{name}: {str(error)[:120]}')

    def start(self):
        """Start every live part the state asks for and announce which ones are running. Returns their
        names.
        """
        options = self.state.get('options', {})
        if self.state.get('breadcrumbs'):
            from sentinelav.monitoring.deception.breadcrumbs import DecoyServers

            self._try(
                'decoy servers',
                lambda: self._started(
                    DecoyServers(self.state['breadcrumbs']['ports'], self.emit, self.behavior)
                ),
            )
        if options.get('clipboard'):
            from sentinelav.monitoring.deception.clipboard import ClipboardGuard

            self._try(
                'clipboard guard',
                lambda: ClipboardGuard(
                    self.emit, self.behavior, bait=options.get('clipboard_bait', False)
                ).start(),
            )
        if options.get('vaccines'):
            from sentinelav.monitoring.deception.vaccines import Vaccines

            self._try('infection markers', lambda: self._started(Vaccines()))
        if (
            options.get('bait_processes')
            or options.get('analysis_decoys')
            or self.state.get('credentials')
        ):
            from sentinelav.monitoring.deception.processes import DecoyProcesses

            self._try(
                'decoy processes',
                lambda: self._started(
                    DecoyProcesses(
                        self.emit,
                        self.data_dir / 'decoys',
                        options.get('bait_processes'),
                        options.get('analysis_decoys'),
                        self.state.get('credentials'),
                    )
                ),
            )
        if self.state.get('sinkhole'):
            from sentinelav.monitoring.deception.sinkhole import SinkholeListener

            self._try('sinkhole', lambda: self._started(SinkholeListener(self.emit, self.behavior)))
        names = [
            name
            for name in (
                self.state.get('account'),
                (self.state.get('credentials') or {}).get('user'),
            )
            if name
        ]
        if names:
            from sentinelav.monitoring.deception.accounts import LogonWatcher

            self._try('logon watcher', lambda: LogonWatcher(self.emit, names))
        self.emit(
            event(
                'Deception active',
                'Running: '
                + (', '.join(self.parts) or 'nothing')
                + ('. Unavailable: ' + '; '.join(self.notes) if self.notes else '.'),
                level='Info',
            )
        )
        return list(self.parts)

    @staticmethod
    def _started(part):
        """Start a part and return it (a helper for one-line construction)."""
        part.start()
        return part

    def poll(self):
        """Poll the parts that need regular checks, dropping any part that fails, and run the slow
        checks once a minute.
        """
        for name in ('clipboard guard', 'decoy processes', 'logon watcher'):
            if name in self.parts:
                try:
                    self.parts[name].poll()
                except Exception as error:
                    self.notes.append(f'{name}: {str(error)[:120]}')
                    del self.parts[name]
        if time.monotonic() >= self.next_slow:
            self.next_slow = time.monotonic() + 60
            self._slow_checks()

    def _slow_checks(self):
        """Retire decoy stores for apps that have since been installed, and report decoy registry
        entries that were changed or deleted.
        """
        from sentinelav.monitoring.deception import registry_decoys, stores

        kept, retired = stores.retire_installed(self.state.get('stores', []))
        if retired:
            self.state['stores'] = kept
            self.emit(
                event(
                    'Decoy stores retired',
                    'Removed decoys for apps now installed: ' + ', '.join(retired),
                    level='Info',
                )
            )
        for entry, change in registry_decoys.changed(
            self.state.get('breadcrumbs', {}).get('registry', [])
        ):
            if entry.get('reported') == change:
                continue
            entry['reported'] = change
            self.emit(
                event(
                    'Decoy registry entry ' + change,
                    f"The decoy {entry['label']} in the registry was {change}. "
                    'Nothing legitimate edits it; a program is tampering with saved sessions.',
                    path=entry['path'],
                )
            )

    def stop(self):
        """Stop every running part, ignoring errors."""
        for part in self.parts.values():
            if hasattr(part, 'stop'):
                try:
                    part.stop()
                except Exception:
                    pass
        self.parts = {}

    close = stop

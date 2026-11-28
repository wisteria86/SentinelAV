# Purpose: Settings and lifecycle for the deception features beyond decoy files.
# Works with: monitoring.deception, ui.honeypot_ui, ui.protection
# Used by: ui.application

"""Settings and lifecycle for the deception features beyond decoy files."""

from PySide6.QtWidgets import QCheckBox, QGridLayout, QLabel, QMessageBox, QTabWidget

OPTIONS = (
    ('stores', 'Decoy browser, wallet, chat and FTP data for apps you do not have', False),
    (
        'breadcrumbs',
        'Breadcrumbs (saved RDP, VPN and SSH entries) that lead to local decoy servers',
        False,
    ),
    ('clipboard', 'Warn when a copied crypto address is swapped by another program', False),
    ('vaccines', 'Infection markers that published malware families avoid', False),
    (
        'clipboard_bait',
        'Leave a decoy crypto address on an empty clipboard while you are away',
        False,
    ),
    ('bait_processes', 'Bait processes that detect code injection', False),
    (
        'analysis_decoys',
        'Fake analysis tools that make evasive malware stay dormant (some games\' anti-cheat may object)',
        False,
    ),
    (
        'memory_credentials',
        'Fake network credentials in memory, to expose password-dumping tools',
        False,
    ),
    ('tarpit', 'Tarpit mode for the network honeypot (holds scanners\' connections open)', False),
    ('sinkhole', 'Sinkhole known malware domains through the hosts file', True),
    ('decoy_account', 'Disabled decoy Windows account', True),
    ('decoy_share', 'Read-only decoy network share', True),
)


class DeceptionMixin:
    """Adds the deception options to the Settings page and deploys or removes the decoys."""

    def settings_page(self):
        """Add the deception checkboxes, status line and remove button to the Advanced settings tab."""
        super().settings_page()
        from sentinelav.monitoring.deception import DEFAULTS

        tabs = self.stack.widget(5).findChild(QTabWidget)
        advanced = next(
            tabs.widget(i) for i in range(tabs.count()) if tabs.tabText(i) == 'Advanced'
        )
        layout = advanced.layout()
        intro = QLabel(
            'Deception: decoys that only malware would touch. Each one reports the program involved when Windows can tell; '
            'none of them sends anything off this PC, and processes are never stopped automatically. Items marked * need '
            'SentinelAV to run as administrator.',
            objectName='small',
        )
        intro.setWordWrap(True)
        layout.insertWidget(4, intro)
        grid, saved = QGridLayout(), dict(DEFAULTS, **self.store.get('deception_options', {}))
        self.deception_boxes = {}
        for index, (key, text, admin) in enumerate(OPTIONS):
            box = QCheckBox(text + (' *' if admin else ''))
            box.setChecked(bool(saved.get(key)))
            grid.addWidget(box, index // 2, index % 2)
            self.deception_boxes[key] = box
        layout.insertLayout(5, grid)
        self.deception_status = QLabel(self.deception_summary(), objectName='small')
        self.deception_status.setWordWrap(True)
        layout.insertWidget(6, self.deception_status)
        row = QGridLayout()
        self.action(row, 'Remove Deception Decoys', self.remove_deception)
        layout.insertLayout(7, row)

    def deception_summary(self):
        """Describe what is currently deployed and anything that could not be deployed."""
        state = self.store.get('deception_state', {})
        placed = len([store for store in state.get('stores', [])]) if state else 0
        problems = state.get('problems', []) if state else []
        text = (
            f'{placed} decoy app stores placed'
            if state
            else 'Deception decoys not deployed yet; they deploy when protection starts.'
        )
        return text + ('. Not available: ' + '; '.join(problems) if problems else '')

    def save_settings(self):
        """Save the deception checkboxes along with the other settings."""
        if hasattr(self, 'deception_boxes'):
            self.store.set(
                'deception_options',
                {key: box.isChecked() for key, box in self.deception_boxes.items()},
            )
        super().save_settings()

    def ensure_deception(self):
        """Deploy with the current options, first removing an older deployment made with different options."""
        from sentinelav.monitoring.deception import DEFAULTS, deploy, remove

        options = dict(DEFAULTS, **self.store.get('deception_options', {}))
        state = self.store.get('deception_state', {})
        if state and state.get('options') == options:
            return state
        if state:
            remove(state)
        state = deploy(options, self.store.path.parent) if any(options.values()) else {}
        self.store.set('deception_state', state)
        if hasattr(self, 'deception_status'):
            self.deception_status.setText(self.deception_summary())
        return state

    def honeypot_config(self):
        """Add the deployed decoy files and deception state to the protection configuration, and
        exclude the decoys from scanning.
        """
        config = super().honeypot_config()
        try:
            state = self.ensure_deception()
        except Exception as error:  # A deception problem must never stop protection from starting.
            self.store.set('deception_state', {})
            QMessageBox.warning(self, 'Deception unavailable', str(error)[:300])
            return config
        if not state:
            return config
        from sentinelav.monitoring.deception import file_entries

        entries = file_entries(state)
        config['honeypots'] = list(config.get('honeypots', [])) + entries
        exclusions = self.store.get('exclusions', [])
        missing = [entry['path'] for entry in entries if entry['path'] not in exclusions]
        if missing:
            self.store.set('exclusions', exclusions + missing)
        config.update(deception=state, tarpit=state['options'].get('tarpit', False))
        return config

    def remove_deception(self):
        """Remove every deployed decoy (only while monitoring is stopped) and switch all deception
        options off.
        """
        if self.protection_worker:
            QMessageBox.information(
                self, 'Monitoring active', 'Stop monitoring before removing decoys.'
            )
            return
        from sentinelav.monitoring.deception import file_entries, remove

        state = self.store.get('deception_state', {})
        left = remove(state) if state else []
        removed = (
            {entry['path'] for entry in file_entries(state)} - {entry['path'] for entry in left}
            if state
            else set()
        )
        self.store.set(
            'exclusions', [path for path in self.store.get('exclusions', []) if path not in removed]
        )
        self.store.set('deception_state', {})
        self.store.set('deception_options', {key: False for key, _, _ in OPTIONS})
        for box in getattr(self, 'deception_boxes', {}).values():
            box.setChecked(False)
        if hasattr(self, 'deception_status'):
            self.deception_status.setText(self.deception_summary())
        note = f' {len(left)} changed decoys were left in place for you to inspect.' if left else ''
        QMessageBox.information(
            self,
            'Deception removed',
            f'Decoys, registry entries, account, share and sinkhole removed.{note}',
        )

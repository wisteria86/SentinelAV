# Purpose: Settings and lifecycle for decoy files and the opt-in network honeypot.
# Works with: monitoring.helpers.honeypots, ui.core.protection, ui.helpers.protection_pages
# Used by: ui.application

"""Settings and lifecycle for decoy files and the opt-in network honeypot."""

from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QTabWidget


class HoneypotMixin:
    """Settings and lifecycle for decoy files and the network honeypot."""

    def settings_page(self):
        """Add the honeypot options, port list, remove button and status line to the Advanced settings
        tab.
        """
        super().settings_page()
        tabs = self.stack.widget(5).findChild(QTabWidget)
        advanced = next(
            tabs.widget(i) for i in range(tabs.count()) if tabs.tabText(i) == 'Advanced'
        )
        layout = advanced.layout()
        intro = QLabel(
            'Honeypots: hidden decoy files (fake passwords, a fake wallet phrase, fake keys) and a ransomware trap '
            'folder in Documents and Desktop. Nothing legitimate opens them, so any read or change is reported with the '
            'process when it can be identified. They hold no real data.',
            objectName='small',
        )
        intro.setWordWrap(True)
        layout.insertWidget(0, intro)
        self.honeypot_option = QCheckBox('Deploy decoy files when protection starts (recommended)')
        self.honeypot_option.setChecked(self.store.get('honeypots_enabled', True))
        layout.insertWidget(1, self.honeypot_option)
        row = QHBoxLayout()
        self.network_honeypot_option = QCheckBox('Network honeypot on unused ports:')
        self.network_honeypot_option.setChecked(self.store.get('network_honeypot_enabled', False))
        self.network_honeypot_ports = QLineEdit(
            ','.join(str(p) for p in self.store.get('network_honeypot_ports', [23, 2323, 5900]))
        )
        self.network_honeypot_ports.setMaximumWidth(160)
        row.addWidget(self.network_honeypot_option)
        row.addWidget(self.network_honeypot_ports)
        self.action(row, 'Remove Decoys', self.remove_honeypots)
        layout.insertLayout(2, row)
        self.honeypot_status = QLabel(self.honeypot_summary(), objectName='small')
        self.honeypot_status.setWordWrap(True)
        layout.insertWidget(3, self.honeypot_status)

    def honeypot_summary(self):
        """Describe how many decoy files are deployed and whether the network listener is on."""
        count = len(self.store.get('honeypots', []))
        network = (
            'network listener opt-in, off'
            if not self.store.get('network_honeypot_enabled', False)
            else 'network listener on'
        )
        return f'{count} decoy files deployed · {network}. Windows Firewall may ask before the listener accepts connections.'

    def save_settings(self):
        """Validate the port list (1-8 ports) and save the honeypot settings."""
        if hasattr(self, 'honeypot_option'):
            try:
                ports = [
                    int(value)
                    for value in self.network_honeypot_ports.text().replace(' ', '').split(',')
                    if value
                ]
                if not ports or any(not 1 <= port <= 65535 for port in ports) or len(ports) > 8:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(
                    self,
                    'Invalid honeypot ports',
                    'List up to 8 port numbers between 1 and 65535, separated by commas.',
                )
                return
            self.store.set('honeypots_enabled', self.honeypot_option.isChecked())
            self.store.set('network_honeypot_enabled', self.network_honeypot_option.isChecked())
            self.store.set('network_honeypot_ports', ports)
            self.honeypot_status.setText(self.honeypot_summary())
        super().save_settings()

    def ensure_honeypots(self):
        """Deploy missing decoys and keep them out of SentinelAV's own scans."""
        if not self.store.get('honeypots_enabled', True):
            return []
        from sentinelav.monitoring.helpers.honeypots import deploy

        entries = [
            entry
            for entry in self.store.get('honeypots', [])
            if __import__('os').path.exists(entry['path'])
        ]
        try:
            entries += deploy()
        except OSError as error:
            self.store.set('honeypots', entries)
            return entries
        self.store.set('honeypots', entries)
        exclusions = self.store.get('exclusions', [])
        missing = [entry['path'] for entry in entries if entry['path'] not in exclusions]
        if missing:
            self.store.set('exclusions', exclusions + missing)
        return entries

    def honeypot_config(self):
        """Return the honeypot part of the protection configuration: the decoy file entries and the
        ports to listen on.
        """
        entries = self.ensure_honeypots()
        ports = (
            self.store.get('network_honeypot_ports', [23, 2323, 5900])
            if self.store.get('network_honeypot_enabled', False)
            else []
        )
        return dict(honeypots=entries, network_honeypot=ports)

    def remove_honeypots(self):
        """Remove the decoy files (only while monitoring is stopped), keeping any that were changed for
        the user to inspect.
        """
        if self.protection_worker:
            QMessageBox.information(
                self, 'Monitoring active', 'Stop monitoring before removing decoys.'
            )
            return
        from sentinelav.monitoring.helpers.honeypots import remove

        entries = self.store.get('honeypots', [])
        kept = remove(entries)
        removed = {entry['path'] for entry in entries} - {entry['path'] for entry in kept}
        self.store.set('honeypots', kept)
        self.store.set(
            'exclusions', [path for path in self.store.get('exclusions', []) if path not in removed]
        )
        self.store.set('honeypots_enabled', False)
        if hasattr(self, 'honeypot_option'):
            self.honeypot_option.setChecked(False)
            self.honeypot_status.setText(self.honeypot_summary())
        note = f' {len(kept)} changed decoys were left in place for you to inspect.' if kept else ''
        QMessageBox.information(
            self, 'Decoys removed', f'{len(removed)} decoy files removed.{note}'
        )

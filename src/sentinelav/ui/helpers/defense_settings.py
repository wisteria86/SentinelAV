# Purpose: Save analysis settings and manage trusted publishers or collector paths.
# Works with: platform.feature_status, platform.core.integrity, ui.application, updates.analysis_trust,
#   updates.artifacts
# Used by: ui.core.defense_ui

"""Honest layer status, bounded manual inspection, and opt-in response policy."""

import json
import os
from pathlib import Path
import re
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox


class DefenseSettingsMixin:
    """Saving and actions for the Defense settings tab."""

    def save_settings(self):
        """Validate and save the Defense settings: update URLs (HTTPS only), inspection options, and
        the automatic response policy.

        Saving the response policy gives it a new reset_id, which also clears a tripped auto-
        response circuit breaker.
        """
        from urllib.parse import urlsplit

        urls = {
            key: widget.text().strip()
            for key, widget in [
                ('model', self.model_feed_url),
                ('reputation', self.reputation_feed_url),
                ('policy', self.policy_feed_url),
            ]
            if widget.text().strip()
        }
        for url in urls.values():
            try:
                parsed = urlsplit(url)
            except ValueError:
                QMessageBox.warning(
                    self, 'Invalid update URL', 'The update URL could not be parsed.'
                )
                return
            if (
                len(url) > 4096
                or parsed.scheme != 'https'
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
            ):
                QMessageBox.warning(
                    self,
                    'Invalid update URL',
                    'Use HTTPS URLs without embedded credentials or fragments.',
                )
                return
        if self.analysis_updates_option.isChecked():
            from sentinelav.updates.artifacts import bounded_json
            from sentinelav.ui.application import ROOT

            try:
                trust = self.store.path.parent / 'analysis-trust.json'
                if not trust.exists():
                    trust = ROOT / 'trusted-update-keys.json'
                if not urls or not bounded_json(trust, 65536).get('keys'):
                    raise ValueError(
                        'Configure at least one URL and independently reviewed publisher trust pins first.'
                    )
            except Exception as error:
                QMessageBox.warning(self, 'Analysis updates unavailable', str(error))
                return
        hashes = [
            h.strip().lower() for h in self.response_hashes.toPlainText().splitlines() if h.strip()
        ]
        roots = [p.strip() for p in self.response_roots.toPlainText().splitlines() if p.strip()]
        if (
            len(hashes) > 256
            or len(set(hashes)) != len(hashes)
            or any(not re.fullmatch(r'[0-9a-f]{64}', h) for h in hashes)
            or len(roots) > 32
            or any(
                not Path(p).is_absolute()
                or not Path(p).is_dir()
                or (os.name == 'nt' and len(Path(p).drive) != 2)
                for p in roots
            )
            or self.auto_response_option.isChecked()
            and not self.high_confidence_option.isChecked()
            and not (roots and (hashes or self.calibrated_response_option.isChecked()))
        ):
            QMessageBox.warning(
                self,
                'Invalid response policy',
                'Use distinct SHA-256 hashes and existing local folders. Enable either approved hashes or the calibrated-policy option within a bounded folder scope.',
            )
            return
        self.store.set(
            'inspection_options',
            dict(
                archives=self.archive_option.isChecked(),
                amsi=self.amsi_option.isChecked(),
                advanced=self.advanced_option.isChecked(),
                emulation=self.emulation_option.isChecked(),
                documents=self.document_option.isChecked(),
                model=self.model_option.isChecked(),
                neural=self.neural_option.isChecked(),
                reputation=self.reputation_option.isChecked(),
                analysis_store=str(self.store.path.parent / 'analysis-data'),
                analysis_trust=self.analysis_trust_path(),
            ),
        )
        self.store.set(
            'artifact_updates',
            dict(
                enabled=self.analysis_updates_option.isChecked(), urls=urls, interval_seconds=3600
            ),
        )
        self.store.set('event_processes', self.event_option.isChecked())
        import uuid

        self.store.set(
            'auto_response',
            dict(
                enabled=self.auto_response_option.isChecked(),
                approved_hashes=hashes,
                roots=roots,
                allow_calibrated_unknown=self.calibrated_response_option.isChecked(),
                high_confidence=self.high_confidence_option.isChecked(),
                reset_id=uuid.uuid4().hex,
            ),
        )
        policy = self.store.get('auto_response', {})
        policy['auto_persistence'] = self.persistence_response_option.isChecked()
        self.store.set('auto_response', policy)
        super().save_settings()
        self.refresh_defense_layers()

    def import_analysis_artifact(self):
        """Let the user import a signed model, reputation feed or policy file and make it active (only
        while nothing else is running).
        """
        if (
            self.worker
            or self.protection_worker
            or self.inspection_worker
            or self.response_worker
            or self.definition_worker
        ):
            QMessageBox.information(
                self,
                'Operation active',
                'Stop scanning, monitoring and response operations before importing analysis data.',
            )
            return
        kind, okay = QInputDialog.getItem(
            self,
            'Signed analysis data',
            'Artifact type:',
            ['model', 'reputation', 'policy'],
            0,
            False,
        )
        if not okay:
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import signed ' + kind, '', 'JSON (*.json)')
        if not path:
            return
        try:
            from sentinelav.updates.artifacts import activate
            from sentinelav.ui.application import ROOT

            record = activate(
                path, self.store.path.parent / 'analysis-data', self.analysis_trust_path(), kind
            )
            options = self.store.get('inspection_options', {})
            options['analysis_store'] = str(self.store.path.parent / 'analysis-data')
            options['analysis_trust'] = self.analysis_trust_path()
            self.store.set('inspection_options', options)
            self.store.save_event(
                dict(
                    time=__import__('time').strftime('%Y-%m-%d %H:%M:%S'),
                    kind='Analysis artifact activated',
                    source='Signed updates',
                    level='Info',
                    details=kind + ' revision ' + str(record['revision']),
                )
            )
            self.inspection_note.setText(
                'Signed '
                + kind
                + ' imported. Experimental analysis remains opt-in; next scan uses the new data.'
            )
        except Exception as error:
            QMessageBox.warning(self, 'Artifact rejected', str(error))

    def analysis_trust_path(self):
        """Return the trust file to use: the user's own pins if they exist, otherwise the bundled one."""
        from sentinelav.ui.application import ROOT

        local = self.store.path.parent / 'analysis-trust.json'
        return str(local if local.exists() else ROOT / 'trusted-update-keys.json')

    def analysis_master_changed(self, enabled):
        """When content analysis is switched off, switch off every option that depends on it."""
        if not enabled:
            for control in (
                self.emulation_option,
                self.model_option,
                self.reputation_option,
                self.neural_option,
            ):
                control.setChecked(False)

    def pin_analysis_publisher(self):
        """Ask for a publisher key id and public key, show its fingerprint for confirmation, and pin
        it.
        """
        if (
            self.worker
            or self.protection_worker
            or self.inspection_worker
            or self.response_worker
            or self.definition_worker
        ):
            QMessageBox.information(
                self, 'Operation active', 'Stop scanning and monitoring before changing trust.'
            )
            return
        key_id, okay = QInputDialog.getText(self, 'Analysis publisher', 'Publisher key ID:')
        if not okay:
            return
        public, okay = QInputDialog.getText(
            self,
            'Analysis publisher',
            'Ed25519 public key (64 hex characters, obtained independently):',
        )
        if not okay:
            return
        try:
            from sentinelav.updates.analysis_trust import fingerprint, update_pin

            digest = fingerprint(public.strip())
            if (
                QMessageBox.question(
                    self,
                    'Trust analysis publisher?',
                    f'Publisher: {key_id}\nSHA-256 fingerprint: {digest}\n\nTrust this publisher for your analysis models and reputation? This does not change Windows trust.',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                return
            update_pin(
                self.store.path.parent / 'analysis-trust.json', key_id.strip(), public.strip()
            )
            options = self.store.get('inspection_options', {})
            options['analysis_trust'] = self.analysis_trust_path()
            self.store.set('inspection_options', options)
            self.inspection_note.setText(
                'Analysis publisher pinned. Restart monitoring after applying settings.'
            )
        except Exception as error:
            QMessageBox.warning(self, 'Publisher pin rejected', str(error))

    def remove_analysis_publisher(self):
        """Let the user pick one of their pinned publishers and remove it."""
        if (
            self.worker
            or self.protection_worker
            or self.inspection_worker
            or self.response_worker
            or self.definition_worker
        ):
            QMessageBox.information(
                self, 'Operation active', 'Stop scanning and monitoring before changing trust.'
            )
            return
        try:
            from sentinelav.updates.artifacts import bounded_json
            from sentinelav.updates.analysis_trust import update_pin

            path = self.store.path.parent / 'analysis-trust.json'
            keys = sorted(bounded_json(path, 65536)['keys']) if path.exists() else []
            if not keys:
                self.inspection_note.setText('No per-user analysis publishers are pinned.')
                return
            key_id, okay = QInputDialog.getItem(
                self, 'Remove analysis publisher', 'Publisher:', keys, 0, False
            )
            if okay:
                update_pin(path, key_id)
                self.inspection_note.setText(
                    'Publisher removed; its artifacts will fail verification on the next scanner initialization.'
                )
        except Exception as error:
            QMessageBox.warning(self, 'Trust update failed', str(error))

    def show_feature_dependencies(self):
        """Show which optional analysis dependencies are installed."""
        from sentinelav.platform.feature_status import feature_status

        box = QMessageBox(self)
        box.setWindowTitle('Analysis dependencies')
        box.setText('Dependency presence does not establish protection or validation.')
        box.setDetailedText(
            json.dumps(feature_status(self.store.get('inspection_options', {})), indent=2)
        )
        box.exec()

    def choose_kernel_collector(self):
        """Let the user select the installed native telemetry collector, checking it lives under
        Program Files with locked-down permissions.
        """
        if self.protection_worker:
            QMessageBox.information(
                self, 'Monitoring active', 'Stop monitoring before changing the collector.'
            )
            return
        path, _ = QFileDialog.getOpenFileName(
            self, 'Select deployed native collector', '', 'Executable (*.exe)'
        )
        if not path:
            return
        try:
            from sentinelav.platform.core.integrity import verify_windows_acl

            target = Path(path).absolute()
            protected = Path(os.environ.get('ProgramFiles', 'C:/Program Files')).resolve()
            if (
                not target.resolve().is_relative_to(protected)
                or target.name != 'SentinelAV.Telemetry.exe'
            ):
                raise ValueError('Select the installed collector under protected Program Files.')
            for component in (target, *target.parents):
                if component.is_symlink() or component.is_junction():
                    raise ValueError('Linked collector path refused')
            verify_windows_acl(target)
            self.store.set('kernel_collector', str(target))
            self.collector_note.setText(
                str(target) + ' — Windows ETW authorization is checked when monitoring starts.'
            )
        except Exception as error:
            QMessageBox.warning(self, 'Collector unavailable', str(error))

    def clear_kernel_collector(self):
        """Forget the configured telemetry collector (only while monitoring is stopped)."""
        if self.protection_worker:
            QMessageBox.information(
                self, 'Monitoring active', 'Stop monitoring before disconnecting the collector.'
            )
            return
        self.store.set('kernel_collector', '')
        self.collector_note.setText('Native file-write collector: not configured')

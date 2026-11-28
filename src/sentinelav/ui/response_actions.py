# Purpose: Dispatch reviewed quarantine, restore, exclusion, and process actions.
# Works with: sibling modules in ui
# Used by: ui.response_ui

"""Explicit response actions; no automatic quarantine or process termination."""

from pathlib import Path
from PySide6.QtWidgets import QFileDialog, QInputDialog
import psutil


class ResponseActionsMixin:
    """Button handlers for acting on detected and quarantined files. Every action asks for confirmation
    first.
    """

    def quarantine_selected(self):
        """Quarantine the selected detected file after confirmation."""
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if detection and self.confirm(
            'Quarantine file?',
            f"Encrypt and isolate this file, removing its original copy?\n\n{detection['path']}",
        ):
            self.launch_response('quarantine_file', detection)

    def remove_selected(self):
        """Permanently delete the selected detected file after confirmation."""
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if detection and self.confirm(
            'Permanently remove file?',
            f"Delete this file for good? It cannot be restored afterwards.\n\n{detection['path']}\n\nChoose Quarantine instead if you are unsure.",
        ):
            self.launch_response('remove_file', detection)

    def restore_selected(self, trust):
        """Restore the selected quarantined file to a new location; with trust=True its hash is also
        trusted afterwards.
        """
        if not self.ready_for_response():
            return
        record = self.selected_quarantine()
        if not record:
            return
        target, _ = QFileDialog.getSaveFileName(
            self, 'Choose restore destination (no overwrite)', record['original']
        )
        if target and self.confirm(
            'Restore detected file?',
            f"Restore this detected content to:\n{target}\n\nIt may be unsafe. "
            + (
                'Its exact SHA-256 will be trusted in future scans.'
                if trust
                else 'It may trigger detection again.'
            ),
        ):
            self.launch_response(
                'restore', record['id'], target, trust_hash=record['sha256'] if trust else None
            )

    def delete_selected(self):
        """Permanently delete the selected quarantined copy after confirmation."""
        if not self.ready_for_response():
            return
        record = self.selected_quarantine()
        if record and self.confirm(
            'Permanently delete?',
            f"Delete the encrypted quarantine copy of {record['original']}?\nThis cannot be restored by SentinelAV.",
        ):
            self.launch_response('delete', record['id'])

    def recover_selected(self):
        """Finish or tidy up an interrupted quarantine action."""
        if not self.ready_for_response():
            return
        record = self.selected_quarantine()
        if record and self.confirm(
            'Recover interrupted action?',
            'Verify the pending operation and reconcile its recorded state? A verified restored copy may allow removal of its redundant encrypted backup.',
        ):
            self.launch_response('recover', record['id'])

    def trust_hash(self, sha):
        """Add a SHA-256 to the trusted list so that exact content is no longer flagged."""
        hashes = self.store.get('trusted_hashes', [])
        if sha not in hashes:
            hashes.append(sha)
            self.store.set('trusted_hashes', hashes)
            self.trusted_list.addItem(sha)
            self.audit_response('Exact hash trusted', sha)

    def trust_selected(self):
        """Trust the selected detected file's exact content after confirmation."""
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if detection and self.confirm(
            'Trust exact file content?',
            f"Stop flagging this exact content on future scans?\n{detection['sha256']}\nBehavior warnings remain enabled.",
        ):
            self.trust_hash(detection['sha256'])
            self.refresh()

    def exclude_selected(self):
        """Exclude the selected file's path from future scans after confirmation."""
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if detection and self.confirm(
            'Exclude file path?',
            f"Skip future inspection of this path, including changed content?\n{detection['path']}",
        ):
            paths = self.store.get('exclusions', [])
            if detection['path'] not in paths:
                paths.append(detection['path'])
                self.store.set('exclusions', paths)
                self.exclusions.setPlainText('\n'.join(paths))
            self.audit_response('File path excluded', detection['path'])
            self.refresh()

    def remove_trust(self):
        """Remove the selected hash from the trusted list."""
        if not self.ready_for_response():
            return
        row = self.trusted_list.currentRow()
        if row >= 0:
            hashes = self.store.get('trusted_hashes', [])
            removed = hashes.pop(row)
            self.store.set('trusted_hashes', hashes)
            self.trusted_list.takeItem(row)
            self.audit_response('Hash trust removed', removed)
            self.refresh()

    def terminate_selected(self):
        """Find running processes of the selected detected program and stop the one the user picks."""
        if not self.ready_for_response():
            return
        detection = self.selected_detection()
        if not detection:
            return
        matches = {}
        for process in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            info = process.info
            if info.get('exe') and Path(info['exe']).resolve() == Path(detection['path']).resolve():
                matches[f"{info['name']} — PID {info['pid']}"] = info
        if not matches:
            self.response_status.setText(
                'No accessible running process matches the selected executable.'
            )
            return
        selected, ok = QInputDialog.getItem(
            self, 'Select process', 'Matching executable:', list(matches), 0, False
        )
        if ok and self.confirm(
            'Terminate process?',
            f"Terminate {selected}? Unsaved work may be lost.\nThe executable must still match a detection; protected processes are blocked.",
        ):
            info = matches[selected]
            self.launch_response('terminate', info['pid'], info['create_time'], detection)

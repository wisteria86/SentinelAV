# Purpose: Handle scan selection, progress, cancellation, and completion.
# Works with: paths, ui.application_workers
# Used by: ui.application

from sentinelav.paths import RESOURCE_ROOT
import json
import time
from pathlib import Path
from PySide6.QtWidgets import QFileDialog, QMessageBox

ROOT = RESOURCE_ROOT
from .application_workers import ScanWorker


def finding_row(finding):
    """Turn one finding into a row for the results table."""
    return (
        finding['path'],
        finding.get('verdict', 'Malicious'),
        finding.get('score', ''),
        finding.get('confidence', ''),
        finding.get('threat_name', ''),
        '; '.join(finding.get('reasons', [])),
    )


def finding_summary(finding):
    """Write a plain-language explanation of why a file was flagged, listing its strongest indicators."""
    lines = [
        finding['path'],
        '',
        f"{finding.get('verdict','Malicious')} · score {finding.get('score','?')}/100 · {finding.get('confidence','?')} confidence · {finding.get('threat_name','')}",
        '',
    ]
    if finding.get('member_chain'):
        lines += ['Found inside the archive at: ' + '!/'.join(finding['member_chain']), '']
    indicators = finding.get('indicators') or []
    lines += [
        f"• {item['explanation']}" + (f"  ({item['evidence']})" if item.get('evidence') else '')
        for item in indicators[:14]
    ] or ['• ' + reason for reason in finding.get('reasons', [])]
    if finding.get('trusted_signature'):
        lines += ['', 'This file has a valid trusted signature, which lowered its score.']
    if finding.get('verdict') != 'Malicious' or finding.get('detection_scope') == 'heuristic':
        lines += [
            '',
            'This is an assessment of the file\'s traits, not proof of malware. You can trust the file if you know it is legitimate.',
        ]
    return '\n'.join(lines)


class ScanActionsMixin:
    """Starting, tracking and showing the results of on-demand scans."""

    def quick_scan(self):
        """Start a Quick Scan of the usual malware locations, running programs and startup entries."""
        from sentinelav.detection.scan_targets import quick_targets

        self.start_scan(quick_targets(), 'Quick Scan')

    def choose_folder(self):
        """Let the user pick a folder and scan it."""
        path = QFileDialog.getExistingDirectory(self, 'Choose folder')
        if path:
            self.start_scan([path], 'Custom Folder')

    def full_scan(self):
        """After confirmation, scan every local fixed drive."""
        from sentinelav.detection.scan_targets import fixed_drives

        drives = fixed_drives()
        names = ', '.join(str(drive) for drive in drives)
        if (
            QMessageBox.question(
                self,
                'Start Full Scan?',
                f'Scan every file on all fixed drives ({names})? This can take a long time. You can cancel at any point.',
            )
            == QMessageBox.StandardButton.Yes
        ):
            self.start_scan(drives, 'Full Scan')

    def choose_files(self):
        """Let the user pick individual files and scan them."""
        paths, _ = QFileDialog.getOpenFileNames(self, 'Choose files')
        if paths:
            self.start_scan(paths, 'Selected Files')

    def start_scan(self, roots, kind):
        """Reset the scan page and start a ScanWorker for the given roots (only one scan at a time)."""
        self.navigate(1)
        if self.worker is not None:
            QMessageBox.information(
                self, 'Scan active', 'Wait for the active scan or cancel it first.'
            )
            return
        self.kind = kind
        self.select_scan_tab(0 if kind == 'Quick Scan' else 1 if kind == 'Full Scan' else 2)
        self.scan_start.setEnabled(False)
        self.select_files_button.setEnabled(False)
        for tab in self.scan_tabs:
            tab.setEnabled(False)
        self.scan_started = time.monotonic()
        self.live_stats[0].setText('0')
        self.live_stats[1].setText('0')
        self.live_stats[2].setText('00:00:00')
        self.elapsed_timer.start(1000)
        self.results.setRowCount(0)
        self.scan_status.setText('Scanning…')
        self.progress.setRange(0, 0)
        self.cancel.setEnabled(True)
        self.worker = ScanWorker(
            roots,
            self.store.get('max_mb', 100),
            self.store.get('exclusions', []) + [str(self.store.path.parent)],
            self.store.get('trusted_hashes', []),
            self.store.get('inspection_options', {}),
            resource_root=self.resource_root,
        )
        self.worker.progress.connect(self.update_scan)
        self.worker.completed.connect(self.finished_scan)
        self.worker.failed.connect(self.failed_scan)
        self.worker.finished.connect(self.release_worker)
        self.worker.start()

    def update_scan(self, path, scanned, threats):
        """Show live progress from the scan worker."""
        self.path_label.setText(path)
        self.count.setText(f'{scanned:,} files inspected • {threats} detections')
        self.live_stats[0].setText(f'{scanned:,}')
        self.live_stats[1].setText(str(threats))

    def cancel_scan(self):
        """Ask the running scan to stop."""
        if self.worker:
            self.worker.requestInterruption()
            self.cancel.setEnabled(False)
            self.scan_status.setText('Cancelling…')

    def release_worker(self):
        """Tidy up after the scan worker and re-enable the controls."""
        self.worker.deleteLater()
        self.worker = None
        self.scan_start.setEnabled(True)
        self.select_files_button.setEnabled(True)
        for tab in self.scan_tabs:
            tab.setEnabled(True)

    def failed_scan(self, error):
        """Show that the scan failed and why."""
        self.elapsed_timer.stop()
        self.scan_status.setText('Scan failed')
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.cancel.setEnabled(False)
        self.path_label.setText(error)

    def finished_scan(self, result):
        """Save the result to history and fill the results table with findings, incompletely inspected
        files and engine warnings.
        """
        self.elapsed_timer.stop()
        self.live_stats[0].setText(f"{result['scanned']:,}")
        self.live_stats[1].setText(str(len(result['detections'])))
        self.live_stats[2].setText(time.strftime('%H:%M:%S', time.gmtime(result['elapsed'])))
        result['kind'] = self.kind
        try:
            self.store.save_scan(result)
        except Exception as error:
            QMessageBox.warning(self, 'History write failed', str(error))
        self.scan_status.setText(result['status'])
        self.progress.setRange(0, 100)
        self.progress.setValue(0 if result['status'] == 'Cancelled' else 100)
        self.cancel.setEnabled(False)
        self.count.setText(
            f"{result['scanned']:,} inspected • {len(result['detections'])} detections • {result['skipped']} oversized • {len(result['errors'])} errors • {result['elapsed']}s"
        )
        suspicious = result.get('suspicious_total', len(result.get('suspicious', [])))
        if suspicious:
            self.count.setText(self.count.text() + f' • {suspicious} suspicious')
        self.path_label.setText(
            'Nothing was changed. Double-click a row to see why it was flagged; act on findings under Quarantine.'
        )
        self.scan_findings = sorted(
            result['detections'] + result.get('suspicious', []), key=lambda d: -d.get('score', 0)
        )
        rows = [finding_row(d) for d in self.scan_findings]
        rows += [
            (e.split(': ', 1)[0], 'Not fully inspected', '', '', '', e.split(': ', 1)[-1])
            for e in result['errors'][:500]
        ]
        rows += [('Engine', 'Warning', '', '', '', w) for w in result['warnings']]
        self.fill(self.results, rows)
        self.refresh()

    def show_scan_finding(self, row, column):
        """Explain a double-clicked finding from the results table."""
        if row < len(getattr(self, 'scan_findings', [])):
            self.show_finding(self.scan_findings[row])

    def show_finding(self, finding):
        """Show the 'Why was this flagged?' dialog for one finding."""
        box = QMessageBox(self)
        box.setWindowTitle('Why was this flagged?')
        box.setText(finding_summary(finding))
        box.setDetailedText(
            json.dumps(
                {
                    key: finding.get(key)
                    for key in (
                        'path',
                        'sha256',
                        'member_chain',
                        'groups',
                        'indicators',
                        'arms',
                        'file_kind',
                        'yara_matches',
                    )
                    if key in finding
                },
                indent=2,
            )
        )
        box.exec()

# Purpose: Handle scan selection, progress, cancellation, and completion.
# Works with: paths, ui.application_workers
# Used by: ui.application

from sentinelav.paths import RESOURCE_ROOT
import os
import time
from pathlib import Path
from PySide6.QtWidgets import QFileDialog, QMessageBox

ROOT = RESOURCE_ROOT
from .application_workers import ScanWorker


class ScanActionsMixin:
    def quick_scan(self):
        roots = [p for p in [Path.home()/'Downloads', Path(os.getenv('TEMP', str(Path.home()/'AppData/Local/Temp'))) ] if p.is_dir()]
        self.start_scan(roots, 'Quick Scan')

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose folder')
        if path:
            self.start_scan([path], 'Custom Folder')

    def full_scan(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose drive or root folder')
        if path:
            self.start_scan([path], 'Full Scan')

    def choose_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Choose files')
        if paths:
            self.start_scan(paths, 'Selected Files')

    def start_scan(self, roots, kind):
        self.navigate(1)
        if self.worker is not None:
            QMessageBox.information(self, 'Scan active', 'Wait for the active scan or cancel it first.')
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
        self.worker = ScanWorker(roots, self.store.get('max_mb', 100), self.store.get('exclusions', [])+[str(self.store.path.parent)],self.store.get('trusted_hashes',[]),self.store.get('inspection_options',{}),resource_root=self.resource_root)
        self.worker.progress.connect(self.update_scan)
        self.worker.completed.connect(self.finished_scan)
        self.worker.failed.connect(self.failed_scan)
        self.worker.finished.connect(self.release_worker)
        self.worker.start()

    def update_scan(self, path, scanned, threats):
        self.path_label.setText(path)
        self.count.setText(f'{scanned:,} files inspected • {threats} detections')
        self.live_stats[0].setText(f'{scanned:,}')
        self.live_stats[1].setText(str(threats))

    def cancel_scan(self):
        if self.worker:
            self.worker.requestInterruption()
            self.cancel.setEnabled(False)
            self.scan_status.setText('Cancelling…')

    def release_worker(self):
        self.worker.deleteLater()
        self.worker = None
        self.scan_start.setEnabled(True)
        self.select_files_button.setEnabled(True)
        for tab in self.scan_tabs:
            tab.setEnabled(True)

    def failed_scan(self, error):
        self.elapsed_timer.stop()
        self.scan_status.setText('Scan failed')
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.cancel.setEnabled(False)
        self.path_label.setText(error)

    def finished_scan(self, result):
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
        self.count.setText(f"{result['scanned']:,} inspected • {len(result['detections'])} detections • {result['skipped']} oversized • {len(result['errors'])} errors • {result['elapsed']}s")
        reviews=result.get('advanced_review_total',0)
        if reviews: self.count.setText(self.count.text()+f' • {reviews} analysis reviews')
        self.path_label.setText('Files remain unchanged. Review detections and scan coverage below.')
        rows = [(d['path'], '; '.join(d['reasons'])) for d in result['detections']]
        rows += [('Unreadable / omitted', e) for e in result['errors']]
        rows += [('Engine warning', w) for w in result['warnings']]
        for item in result.get('structural_review',[]):
            rows.append(('Structural review (not confirmed malware)',item['path']+' — '+
                '; '.join(signal['explanation'] for signal in item['signals'])))
        for item in result.get('advanced_reviews',[]):
            rows.append(('Experimental analysis — review',item['path']+' — '+'; '.join(item['reasons'])))
        if result.get('structural_review_total',0)>len(result.get('structural_review',[])):
            rows.append(('Structural review', 'Showing the first 100 files; total: '+str(result['structural_review_total'])))
        self.fill(self.results, rows)
        self.refresh()

# Purpose: Harmless UI response lifecycle; only temporary demo-marker files are isolated.
# Works with: paths, ui.application, ui.design
# Used by: unittest discovery

"""Harmless UI response lifecycle; only temporary demo-marker files are isolated."""

from sentinelav.paths import SCREENSHOTS_DIR
import os

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
import tempfile
from pathlib import Path
from unittest.mock import patch
from PySide6.QtCore import QTimer, QEventLoop
from PySide6.QtWidgets import QApplication, QFileDialog, QTabWidget
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app

app = QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait_for(predicate):
    loop = QEventLoop()
    found = [False]

    def check():
        if predicate():
            found[0] = True
            loop.quit()

    timer = QTimer()
    timer.timeout.connect(check)
    timer.start(25)
    QTimer.singleShot(15000, loop.quit)
    loop.exec()
    assert found[0], 'Response UI timed out'


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    marker = root / 'harmless-demo.txt'
    content = b'SENTINELAV_DEMO_THREAT_7C23A'
    marker.write_bytes(content)
    window = Window(data_dir=root / 'state')
    window.show()
    try:
        window.start_scan([marker], 'Response Test')
        wait_for(lambda: window.worker is None)
        assert window.pending_table.rowCount() == 1
        window.navigate(3)
        window.pending_table.selectRow(0)
        # Simulate explicit user confirmation for operations on this one fixture.
        with patch.object(window, 'confirm', return_value=True):
            window.quarantine_selected()
            wait_for(lambda: window.response_worker is None)
            assert not marker.exists(), window.response_status.text()
            assert window.quarantine_records[0]['state'] == 'Quarantined'
            window.quarantine_table.selectRow(0)
            tabs = window.stack.widget(3).findChild(QTabWidget)
            tabs.setCurrentIndex(1)
            app.processEvents()
            window.grab().save(str(SCREENSHOTS_DIR / 'preview-quarantine.png'))
            with patch.object(QFileDialog, 'getSaveFileName', return_value=(str(marker), '')):
                window.restore_selected(True)
                wait_for(lambda: window.response_worker is None)
            assert marker.read_bytes() == content
            assert window.quarantine_records[0]['state'] == 'Restored'
            assert len(window.store.get('trusted_hashes', [])) == 1
            window.start_scan([marker], 'Trusted Test')
            wait_for(lambda: window.worker is None)
            assert window.store.history()[0]['detections'] == []
            window.trusted_list.setCurrentRow(0)
            window.remove_trust()
            window.start_scan([marker], 'Trust Removed Test')
            wait_for(lambda: window.worker is None)
            assert len(window.store.history()[0]['detections']) == 1
            window.pending_table.selectRow(0)
            window.quarantine_selected()
            wait_for(lambda: window.response_worker is None)
            window.quarantine_table.selectRow(0)
            window.delete_selected()
            wait_for(lambda: window.response_worker is None)
            assert window.quarantine_records[0]['state'] == 'Deleted'
            assert not marker.exists()
            kinds = {e['kind'] for e in window.store.events()}
            assert {
                'File quarantined',
                'File restored',
                'Quarantine file deleted',
                'Exact hash trusted',
                'Hash trust removed',
            }.issubset(kinds)
    finally:
        if window.response_worker:
            wait_for(lambda: window.response_worker is None)
        window.close()
print(
    'PASS: scan -> encrypted quarantine -> restore/trust -> rescan -> untrust -> quarantine/delete; action audit verified'
)

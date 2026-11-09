# Purpose: Safe canary and burst simulation, confined to newly created temporary files.
# Works with: paths, ui.application, ui.design
# Used by: unittest discovery

"""Safe canary and burst simulation, confined to newly created temporary files."""
from sentinelav.paths import SCREENSHOTS_DIR
import os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
import tempfile
from pathlib import Path
from PySide6.QtWidgets import QApplication, QTabWidget, QFileDialog
from PySide6.QtCore import QEventLoop, QTimer
from unittest.mock import patch
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app

app = QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait_for(predicate, timeout=10000):
    loop = QEventLoop()
    success = [False]
    def check():
        if predicate():
            success[0] = True
            loop.quit()
    timer = QTimer()
    timer.timeout.connect(check)
    timer.start(30)
    QTimer.singleShot(timeout,loop.quit)
    loop.exec()
    assert success[0], 'Behavior verification timed out'


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    watched = root/'harmless-simulation'
    watched.mkdir()
    window = Window(data_dir=root/'state')
    window.show()
    try:
        with patch.object(QFileDialog,'getExistingDirectory',return_value=str(watched)):
            window.add_canary()
        assert window.canary_list.count()==1
        canary = Path(window.store.get('canaries',[])[0]['path'])
        assert canary.exists()
        window.process_option.setChecked(False)
        window.network_option.setChecked(False)
        window.behavior_option.setChecked(True)
        window.begin_protection()
        wait_for(lambda:window.monitor_state=='Active')
        canary.write_text('Harmless canary edit during a controlled test')
        wait_for(lambda:any(e.get('score')==70 for e in window.session_events))
        warning = next(e for e in window.session_events if e.get('score')==70)
        assert warning['level']=='Warning'
        # Only ordinary text files created inside this temporary directory are changed.
        for i in range(35):
            (watched/f'harmless-{i}.txt').write_text('ordinary sample text')
        wait_for(lambda:any(e.get('score')==100 for e in window.session_events))
        event = next(e for e in window.store.events() if e.get('score')==100)
        assert event['level']=='Alert'
        assert len(event['indicators'])>=2
        assert 'pid' not in event
        assert 'RISK ALERT' in window.alert_banner.text()
        assert window.metric_values[2].text() == '0', 'Behavioral suspicion must not count as confirmed malware'
        window.change_report(2)
        assert window.history_table.rowCount()>=3
        window.navigate(2)
        app.processEvents()
        window.grab().save(str(SCREENSHOTS_DIR/'preview-behavior.png'))
        window.stop_protection()
        wait_for(lambda:window.protection_worker is None)
        window.navigate(5)
        tabs = window.stack.widget(5).findChild(QTabWidget)
        tabs.setCurrentIndex(next(i for i in range(tabs.count()) if tabs.tabText(i)=='Advanced'))
        app.processEvents()
        window.grab().save(str(SCREENSHOTS_DIR/'preview-advanced-settings.png'))
        # Stop tracking is reversible and must leave the canary itself intact.
        window.canary_list.setCurrentRow(0)
        window.remove_canary()
        assert window.store.get('canaries',[])==[]
        assert canary.exists()
    finally:
        if window.protection_worker:
            window.protection_worker.stop()
            wait_for(lambda:window.protection_worker is None)
        window.close()
print('PASS: canary creation/change, warning, combined-risk alert, persisted evidence, advanced settings, stop tracking')

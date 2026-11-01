"""Real watchdog -> Qt worker -> SQLite -> alert/report lifecycle check."""
from sentinelav.paths import SCREENSHOTS_DIR
import os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
import tempfile
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QEventLoop, QTimer
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app

app = QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait_for(predicate, timeout=10000):
    loop = QEventLoop()
    found = [False]
    def check():
        if predicate():
            found[0] = True
            loop.quit()
    timer = QTimer()
    timer.timeout.connect(check)
    timer.start(30)
    QTimer.singleShot(timeout,loop.quit)
    loop.exec()
    assert found[0], 'Timed out waiting for protection UI state'


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    watched = root/'watched'
    watched.mkdir()
    window = Window(data_dir=root/'state')
    window.show()
    try:
        window.watch_folders.setPlainText(str(watched))
        window.process_option.setChecked(True)
        window.begin_protection()
        wait_for(lambda: window.monitor_state == 'Active')
        assert window.dashboard_badge_label.text() == 'ON'
        assert not window.start_protection.isEnabled()
        assert not window.watch_folders.isEnabled()
        marker = watched/'harmless-marker.txt'
        marker.write_text('SENTINELAV_DEMO_THREAT_7C23A')
        wait_for(lambda: any(e['level']=='Alert' for e in window.session_events))
        assert 'DETECTED' in window.alert_banner.text()
        assert marker.exists()
        window.change_report(1)
        assert window.history_table.rowCount() == 1
        window.change_report(2)
        assert window.history_table.rowCount() >= 2
        window.navigate(2)
        app.processEvents()
        window.grab().save(str(SCREENSHOTS_DIR/'preview-protection-active.png'))
        window.stop_protection()
        wait_for(lambda: window.protection_worker is None)
        assert window.dashboard_badge_label.text() == 'OFF'
        assert window.start_protection.isEnabled()
        # A second start and closing while active must shut down without a blocking dialog.
        window.begin_protection()
        wait_for(lambda: window.monitor_state == 'Active')
        window.close()
        wait_for(lambda: not window.isVisible())
    finally:
        if window.protection_worker:
            window.protection_worker.stop()
            wait_for(lambda: window.protection_worker is None)
        if window.isVisible():
            window.close()
print('PASS: live detection, dashboard state, SQLite reports, stop/restart, and close during monitoring')

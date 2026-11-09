# Purpose: Real watchdog -> Qt worker -> SQLite -> alert/report lifecycle check.
# Works with: paths, ui.application, ui.design
# Used by: unittest discovery

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
    assert found[0], 'Timed out waiting for protection UI state: '+str(getattr(globals().get('window'),'last_protection_state',{}))


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    watched = root/'watched'
    watched.mkdir()
    window = Window(data_dir=root/'state')
    window.show()
    try:
        window.watch_folders.setPlainText(str(watched))
        # This lifecycle check owns filesystem fixtures. Unrelated process
        # launches can legitimately degrade coverage and must not determine
        # whether the controlled filesystem source recovered.
        window.process_option.setChecked(False)
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
        # Inject an incomplete-coverage status, then verify a real status
        # update restores Active without hiding the existing event history.
        state=dict(folders=1,checked=1,processes=0,denied=0,queued=0,sysmon=False,
                   inspection_error='Latest file inspection incomplete')
        window.receive_status(state)
        assert window.monitor_state=='Degraded'
        assert window.dashboard_badge_label.text()=='DEGRADED'
        assert window.dashboard_title.text()=='Monitoring needs attention'
        assert 'incomplete' in window.protection_stats.text()
        wait_for(lambda:window.monitor_state=='Active')
        window.receive_status(dict(state,inspection_error='',telemetry_error='Sysmon: channel unavailable'))
        assert window.monitor_state=='Degraded'
        assert 'channel unavailable' in window.protection_stats.text()
        window.receive_status(dict(state,inspection_error='',dropped=3))
        assert window.monitor_state=='Degraded'
        wait_for(lambda:window.monitor_state=='Active')
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

# Purpose: Scheduling preference UI test; Windows persistence is mocked, never enabled.
# Works with: paths, platform.runtime, ui.application, ui.design
# Used by: unittest discovery

"""Scheduling preference UI test; Windows persistence is mocked, never enabled."""

from sentinelav.paths import SCREENSHOTS_DIR
import os

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch
from PySide6.QtWidgets import QApplication, QMessageBox, QFileDialog, QTabWidget
from PySide6.QtCore import QTimer, QEventLoop
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app
from sentinelav.platform.runtime import ZONE

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
    QTimer.singleShot(10000, loop.quit)
    loop.exec()
    assert found[0], 'Finalization UI timed out'


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    files = root / 'files'
    files.mkdir()
    (files / 'demo.txt').write_text('SENTINELAV_DEMO_THREAT_7C23A')
    window = Window(data_dir=root / 'state')
    window.show()
    try:
        window.schedule_option.setChecked(True)
        window.schedule_kind.setCurrentText('Folder')
        window.schedule_folder.setText(str(files))
        with (
            patch('sentinelav.ui.finalization.set_startup') as startup,
            patch('sentinelav.ui.finalization.register_schedule') as register,
            patch.object(QMessageBox, 'information'),
        ):
            window.apply_schedule()
            wait_for(lambda: window.preferences_worker is None)
            startup.assert_called_once_with(window.startup_option.isChecked())
            register.assert_called_once()
        schedule = window.store.get('schedule', {})
        assert schedule['enabled'] and schedule['windows_task']
        schedule['next_run'] = (datetime.now(ZONE) - timedelta(days=2)).isoformat()
        window.store.set('schedule', schedule)
        window.check_schedule()
        wait_for(lambda: window.worker is None)
        assert window.store.history()[0]['kind'] == 'Scheduled Folder'
        assert len(window.store.history()[0]['detections']) == 1
        window.check_schedule()
        assert window.worker is None
        for kind in ['html', 'json', 'csv']:
            path = root / ('export.' + kind)
            with patch.object(QFileDialog, 'getSaveFileName', return_value=(str(path), '')):
                window.export()
            assert path.stat().st_size > 20
        window.navigate(5)
        tabs = window.stack.widget(5).findChild(QTabWidget)
        tabs.setCurrentIndex(
            next(i for i in range(tabs.count()) if tabs.tabText(i) == 'Scheduling')
        )
        app.processEvents()
        window.grab().save(str(SCREENSHOTS_DIR / 'preview-scheduling.png'))
    finally:
        window.close()
print(
    'PASS: async preference application (mocked Windows writes), daily catchup once, scheduled detection, HTML/JSON/CSV exports'
)

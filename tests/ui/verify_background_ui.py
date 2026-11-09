# Purpose: Harmless real-process test: close GUI, detect fixture, reconnect, stop.
# Works with: data.storage, monitoring.background, paths, ui.application, ui.design
# Used by: unittest discovery

"""Harmless real-process test: close GUI, detect fixture, reconnect, stop."""
from sentinelav.paths import SCREENSHOTS_DIR
import os
os.environ['QT_QPA_PLATFORM']='offscreen'
import tempfile
import time
from pathlib import Path
from PySide6.QtWidgets import QApplication
from sentinelav.ui.application import Window
from sentinelav.monitoring.background import request
from sentinelav.ui.design import configure_app
from sentinelav.data.storage import Store

app=QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait(predicate, timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        app.processEvents()
        if predicate(): return
        time.sleep(.03)
    raise AssertionError('Timed out waiting for independent engine lifecycle')


with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    watched=root/'watched'
    watched.mkdir()
    data=root/'state'
    windows=[]
    try:
        window=Window(data_dir=data)
        windows.append(window)
        window.show()
        window.watch_folders.setPlainText(str(watched))
        window.process_option.setChecked(False)
        window.behavior_option.setChecked(False)
        window.background_option.setChecked(True)
        window.begin_protection()
        wait(lambda: window.monitor_state=='Active')
        window.close()
        wait(lambda: not window.isVisible())
        assert request(data,'status')['state']=='Active', 'Closing GUI stopped engine'
        marker=watched/'harmless-marker.txt'
        marker.write_text('SENTINELAV_DEMO_THREAT_7C23A')
        store=Store(data/'sentinelav.db')
        try:
            wait(lambda:any(e.get('path')==str(marker) and e['level']=='Alert' for e in store.events()))
            alerts=[e for e in store.events() if e['level']=='Alert']
            assert len(alerts)==1
        finally:
            store.db.close()
        window=Window(data_dir=data)
        windows.append(window)
        window.show()
        wait(lambda:window.monitor_state=='Active')
        window.navigate(2)
        app.processEvents()
        window.grab().save(str(SCREENSHOTS_DIR/'preview-background.png'))
        marker2=watched/'second-harmless-marker.txt'
        marker2.write_text('SENTINELAV_DEMO_THREAT_7C23A')
        wait(lambda:any(e.get('path')==str(marker2) and e['level']=='Alert' for e in window.session_events))
        assert len([e for e in window.store.events() if e['level']=='Alert'])==2, 'GUI duplicated persisted events'
        window.stop_protection()
        wait(lambda:window.protection_worker is None)
        try:
            request(data,'status')
        except ConnectionError:
            pass
        else:
            raise AssertionError('Explicit Stop did not release engine process')
        window.close()
        wait(lambda:not window.isVisible())
        def disconnected():
            try: request(data,'status')
            except ConnectionError: return True
            except RuntimeError: return False
            return False
        wait(disconnected)
    finally:
        for window in windows:
            if window.protection_worker:
                window.protection_worker.detach()
                wait(lambda:window.protection_worker is None)
            if window.isVisible(): window.close()
        try: request(data,'shutdown')
        except (ConnectionError,RuntimeError): pass
        wait(lambda:not (data/'sentinelav.detection.engine.lock').exists())
print('PASS: independent engine detection after GUI exit, reconnect, exactly-once persistence, explicit stop, shutdown')

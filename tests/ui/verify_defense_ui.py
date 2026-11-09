# Purpose: Defense controls and approved-hash response using harmless owned fixtures.
# Works with: paths, response.response, ui.application, ui.design
# Used by: unittest discovery

"""Defense controls and approved-hash response using harmless owned fixtures."""
from sentinelav.paths import RESOURCE_ROOT, SCREENSHOTS_DIR
import os
os.environ['QT_QPA_PLATFORM']='offscreen'
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
from unittest.mock import patch
from PySide6.QtWidgets import QApplication,QTabWidget
import sentinelav.ui.application as application
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app
from sentinelav.response.response import ResponseService

ROOT=RESOURCE_ROOT
app=QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait(predicate,seconds=20):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        app.processEvents()
        if predicate(): return
        time.sleep(.03)
    raise AssertionError('Timed out waiting for defense UI state')


with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    shutil.copytree(ROOT/'rules',root/'rules')
    payload=b'Approved exact-hash quarantine fixture. Harmless text.'
    digest=hashlib.sha256(payload).hexdigest()
    (root/'signatures.json').write_text(json.dumps({digest:'Approved fixture hash'}))
    (root/'trusted-update-keys.json').write_text('{"schema":1,"keys":{}}')
    watched=root/'watched'; watched.mkdir()
    with patch.object(application,'ROOT',root):
        window=Window(data_dir=root/'state')
        window.show()
        try:
            wait(lambda:window.rules_worker is None and 'Compiled' in window.yara_health.text())
            window.navigate(5)
            tabs=window.stack.widget(5).findChild(QTabWidget)
            tabs.setCurrentIndex(next(i for i in range(tabs.count()) if tabs.tabText(i)=='Defense'))
            tabs=window.defense_tabs
            def select(name):
                tabs.setCurrentIndex(next(i for i in range(tabs.count()) if tabs.tabText(i)==name)); app.processEvents()
            select('Layers')
            assert window.layer_table.rowCount()==10
            assert 'global enforcement unavailable' in window.layer_details[3]['state']
            assert 'native provider not deployed' in window.layer_details[2]['state']
            for width,height in [(960,600),(1440,900)]:
                window.resize(width,height); app.processEvents()
                assert window.centralWidget().width()<=window.width()
            window.resize(1000,620); app.processEvents()
            window.grab().save(str(SCREENSHOTS_DIR/'preview-defense-layers.png'))
            select('Inspection')
            ordinary=watched/'ordinary.txt'; ordinary.write_text('Ordinary manual pre-execution check')
            with patch('sentinelav.ui.defense_ui.QFileDialog.getOpenFileName',return_value=(str(ordinary),'TXT')):
                window.begin_bounded_inspection('file')
            wait(lambda:window.inspection_worker is None)
            assert window.last_inspection['verdict']['decision']=='Not approved'
            assert ordinary.exists()
            assert 'No file was launched' in window.inspection_note.text()
            window.grab().save(str(SCREENSHOTS_DIR/'preview-defense-inspection.png'))
            select('Response Policy')
            assert not window.auto_response_option.isChecked()
            window.auto_response_option.setChecked(True)
            window.response_hashes.setPlainText(digest)
            window.response_roots.setPlainText(str(watched))
            window.event_option.setChecked(False)
            with patch('sentinelav.ui.application.QMessageBox.information'):
                window.save_settings()
            window.watch_folders.setPlainText(str(watched))
            window.process_option.setChecked(False)
            window.behavior_option.setChecked(False)
            window.begin_protection()
            wait(lambda:window.monitor_state=='Active')
            target=watched/'approved-fixture.txt'; target.write_bytes(payload)
            wait(lambda:not target.exists() and any(r['state']=='Quarantined' for r in window.store.quarantine()))
            window.stop_protection(); wait(lambda:window.protection_worker is None)
            record=next(r for r in window.store.quarantine() if r['state']=='Quarantined')
            restored=watched/'restored-fixture.txt'
            ResponseService(window.store,root).restore(record['id'],restored)
            assert restored.read_bytes()==payload
            assert ordinary.read_text()=='Ordinary manual pre-execution check'
            window.close(); wait(lambda:not window.isVisible())
        finally:
            if window.protection_worker:
                window.protection_worker.stop(); wait(lambda:window.protection_worker is None)
            if window.inspection_worker:
                window.inspection_worker.requestInterruption(); wait(lambda:window.inspection_worker is None)
            if window.isVisible(): window.close(); wait(lambda:not window.isVisible())
print('PASS: honest layer states, bounded check without execution, opt-in approved-hash quarantine/restore, scope and sizing')

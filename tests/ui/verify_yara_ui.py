# Purpose: YARA status/provenance UI check using copied text rules only.
# Works with: paths, ui.application, ui.design
# Used by: unittest discovery

"""YARA status/provenance UI check using copied text rules only."""
from sentinelav.paths import RESOURCE_ROOT, SCREENSHOTS_DIR
import os
os.environ['QT_QPA_PLATFORM']='offscreen'
from pathlib import Path
import shutil
import tempfile
import time
from unittest.mock import patch
from PySide6.QtWidgets import QApplication,QTabWidget
import sentinelav.ui.application as application
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app

ROOT=RESOURCE_ROOT
app=QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait(predicate):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        app.processEvents()
        if predicate(): return
        time.sleep(.02)
    raise AssertionError('Timed out waiting for YARA UI validation')


with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    shutil.copytree(ROOT/'rules',root/'rules')
    (root/'signatures.json').write_text('{}')
    (root/'trusted-update-keys.json').write_text('{"schema":1,"keys":{}}')
    with patch.object(application,'ROOT',root):
        window=Window(data_dir=root/'state')
        window.show()
        try:
            wait(lambda:window.rules_worker is None and 'Compiled' in window.yara_health.text())
            window.navigate(5)
            tabs=window.stack.widget(5).findChild(QTabWidget)
            tabs.setCurrentIndex(next(i for i in range(tabs.count()) if tabs.tabText(i)=='YARA Rules'))
            app.processEvents()
            assert '15 research rules' in window.yara_health.text()
            assert '2 private helpers' in window.yara_health.text()
            assert window.yara_table.rowCount()==11
            assert all(f.get('source_revision') for f in window.yara_files)
            for width,height in [(960,600),(1440,900)]:
                window.resize(width,height)
                app.processEvents()
                assert window.centralWidget().width()<=window.width()
                assert window.yara_validate_button.geometry().top()>window.yara_table.geometry().bottom(), 'Rule table overlaps validation control'
            window.resize(1000,620)
            app.processEvents()
            window.grab().save(str(SCREENSHOTS_DIR/'preview-yara.png'))
            modified=root/'rules/eset_redline_panel.yar'
            original=modified.read_bytes()
            modified.write_bytes(original+b'\n// Fixture tampering\n')
            window.validate_yara_rules()
            wait(lambda:window.rules_worker is None)
            assert 'validation failed' in window.yara_health.text()
            assert 'checksum mismatch' in window.yara_health.text()
            assert window.yara_table.rowCount()==0
            modified.write_bytes(original)
            window.validate_yara_rules()
            wait(lambda:window.rules_worker is None)
            assert 'Compiled' in window.yara_health.text()
            window.validate_yara_rules()
            window.close()
            wait(lambda:not window.isVisible())
        finally:
            if window.rules_worker: wait(lambda:window.rules_worker is None)
            if window.isVisible(): window.close()
print('PASS: YARA rule counts/provenance, checksum failure/recovery, sizing, and close during validation')

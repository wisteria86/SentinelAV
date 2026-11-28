# Purpose: Definition UI regressions with tiny harmless hash-only fixture feeds.
# Works with: paths, ui.application, ui.design, updates.definition_updates, updates.hash_archive
# Used by: unittest discovery

"""Definition UI regressions with tiny harmless hash-only fixture feeds."""

from sentinelav.paths import SCREENSHOTS_DIR
import os

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch
from zipfile import ZipFile
from PySide6.QtWidgets import QApplication, QTabWidget
import sentinelav.ui.application as application
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app
from sentinelav.updates.hash_archive import import_archive
from sentinelav.updates.definition_updates import load_active

app = QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait(predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for definition UI operation')


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    (root / 'signatures.json').write_text('{}')
    (root / 'trusted-update-keys.json').write_text('{"schema":1,"keys":{}}')
    archive = root / 'full.zip'
    with ZipFile(archive, 'w') as zipped:
        zipped.writestr(
            'full.csv',
            '# "sha256_hash","signature"\n' + f'"{"a"*64}","Fixture A"\n"{"b"*64}","Fixture B"\n',
        )
    import_archive(archive, root / 'signature-data', True)
    recent = root / 'recent.csv'
    recent.write_text('# "sha256_hash","signature"\n' + f'"{"c"*64}","Fixture C"\n')
    corrections = root / 'corrections.json'
    corrections.write_text(json.dumps(dict(upserts=[], removals=['a' * 64])))
    with patch.object(application, 'ROOT', root):
        window = Window(data_dir=root / 'state')
        window.show()
        try:
            window.navigate(5)
            tabs = window.stack.widget(5).findChild(QTabWidget)
            tabs.setCurrentIndex(
                next(i for i in range(tabs.count()) if tabs.tabText(i) == 'Definitions')
            )
            app.processEvents()
            assert '2 full-feed hashes' in window.definition_health.text()
            assert 'not configured' in window.definition_health.text()
            with patch(
                'sentinelav.ui.updates_ui.QFileDialog.getOpenFileName',
                return_value=(str(recent), 'CSV'),
            ):
                window.begin_definition_update('recent')
            assert not window.definition_buttons[0].isEnabled()
            wait(lambda: window.definition_worker is None)
            assert load_active(root / 'signature-data')['unique_sha256'] == 3
            assert 'Activated 3' in window.definition_result.text()
            window.begin_definition_update('rollback')
            wait(lambda: window.definition_worker is None)
            assert load_active(root / 'signature-data')['unique_sha256'] == 2
            with patch(
                'sentinelav.ui.updates_ui.QFileDialog.getOpenFileName',
                return_value=(str(corrections), 'JSON'),
            ):
                window.begin_definition_update('corrections')
            wait(lambda: window.definition_worker is None)
            assert load_active(root / 'signature-data')['unique_sha256'] == 1
            assert (
                len([e for e in window.store.events() if e['kind'] == 'Definitions updated']) == 3
            )
            for width, height in [(960, 600), (1440, 900)]:
                window.resize(width, height)
                app.processEvents()
                assert window.centralWidget().width() <= window.width()
            window.resize(1000, 620)
            app.processEvents()
            window.grab().save(str(SCREENSHOTS_DIR / 'preview-definitions.png'))
            # Invalid signed-package structure fails without altering active definitions.
            before = (root / 'signature-data/active.json').read_bytes()
            with patch(
                'sentinelav.ui.updates_ui.QFileDialog.getOpenFileName',
                return_value=(str(archive), 'ZIP'),
            ):
                window.begin_definition_update('signed')
            wait(lambda: window.definition_worker is None)
            assert 'Update failed' in window.definition_result.text()
            assert (root / 'signature-data/active.json').read_bytes() == before
            with patch(
                'sentinelav.ui.updates_ui.QFileDialog.getOpenFileName',
                return_value=(str(recent), 'CSV'),
            ):
                window.begin_definition_update('recent')
            window.close()
            wait(lambda: not window.isVisible())
        finally:
            if window.definition_worker:
                wait(lambda: window.definition_worker is None)
            if window.isVisible():
                window.close()
print(
    'PASS: definition UI import, correction, rollback, failed-package preservation, audit, sizing, and close during update'
)

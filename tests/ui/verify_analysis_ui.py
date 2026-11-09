# Purpose: Pin/import/save/scan/quarantine/restore/revoke using harmless local data.
# Works with: paths, ui.application, ui.design, tests.unit.test_analysis_artifacts
# Used by: unittest discovery

"""Pin/import/save/scan/quarantine/restore/revoke using harmless local data."""
import os
os.environ['QT_QPA_PLATFORM']='offscreen'
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PySide6.QtWidgets import QApplication,QMessageBox,QTabWidget,QScrollArea
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app
from tests.unit.test_analysis_artifacts import signed,minimal_model,public_hex

app=QApplication([]); app.setQuitOnLastWindowClosed(False); configure_app(app)


def wait(predicate,seconds=25):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        app.processEvents()
        if predicate(): return
        time.sleep(.03)
    raise AssertionError('Timed out waiting for analysis UI operation')


with tempfile.TemporaryDirectory() as temp:
    root=Path(temp); window=Window(data_dir=root/'state'); window.show()
    global_trust=(RESOURCE_ROOT/'trusted-update-keys.json').read_bytes()
    try:
        wait(lambda:window.rules_worker is None)
        window.resize(960,600); window.navigate(5)
        outer=window.stack.widget(5).findChild(QTabWidget)
        outer.setCurrentIndex(next(i for i in range(outer.count()) if outer.tabText(i)=='Defense'))
        window.defense_tabs.setCurrentIndex(next(i for i in range(window.defense_tabs.count()) if window.defense_tabs.tabText(i)=='Analysis Data'))
        app.processEvents()
        page=window.defense_tabs.currentWidget()
        assert isinstance(page,QScrollArea)
        assert page.widget().height()>=page.widget().minimumSizeHint().height()
        page.verticalScrollBar().setValue(page.verticalScrollBar().maximum())
        app.processEvents()
        assert page.verticalScrollBar().value()==page.verticalScrollBar().maximum()
        key=Ed25519PrivateKey.generate()
        with patch('sentinelav.ui.defense_ui.QInputDialog.getText',side_effect=[('fixture',True),(public_hex(key),True)]),patch('sentinelav.ui.defense_ui.QMessageBox.question',return_value=QMessageBox.StandardButton.Yes):
            window.pin_analysis_publisher()
        assert json.loads((root/'state/analysis-trust.json').read_text())['keys']['fixture']==public_hex(key)
        candidate=root/'model.json'; candidate.write_text(json.dumps(signed(minimal_model(),'model',key)))
        with patch('sentinelav.ui.defense_ui.QInputDialog.getItem',return_value=('model',True)),patch('sentinelav.ui.defense_ui.QFileDialog.getOpenFileName',return_value=(str(candidate),'JSON')):
            window.import_analysis_artifact()
        assert 'model' in json.loads((root/'state/analysis-data/active.json').read_text())
        window.model_option.setChecked(True)
        assert window.advanced_option.isChecked()
        with patch('sentinelav.ui.application.QMessageBox.information'):
            window.save_settings()
        assert window.store.get('inspection_options',{})['model']
        target=root/'encoded.ps1'; payload=base64.b64encode(b'SENTINELAV_DEMO_THREAT_7C23A'); target.write_bytes(payload)
        window.start_scan([target],'Derived-content integration')
        wait(lambda:window.worker is None)
        scan=window.store.history()[0]
        assert scan['decision']['verdict']=='Detected',scan
        assert any(d.get('detection_scope')=='derived content' for d in scan['detections'])
        window.refresh()
        row=next(i for i,d in enumerate(window.pending_detections) if d['path']==str(target.resolve()))
        window.pending_table.selectRow(row)
        with patch('sentinelav.ui.response_ui.QMessageBox.question',return_value=QMessageBox.StandardButton.Yes):
            window.quarantine_selected()
        wait(lambda:window.response_worker is None)
        assert not target.exists(),window.response_status.text()
        record=next(r for r in window.store.quarantine() if r['state']=='Quarantined')
        row=next(i for i,r in enumerate(window.quarantine_records) if r['id']==record['id'])
        window.quarantine_table.selectRow(row)
        with patch('sentinelav.ui.response_ui.QFileDialog.getSaveFileName',return_value=(str(target),'TXT')),patch('sentinelav.ui.response_ui.QMessageBox.question',return_value=QMessageBox.StandardButton.Yes):
            window.restore_selected(False)
        wait(lambda:window.response_worker is None)
        assert target.read_bytes()==payload
        with patch('sentinelav.ui.defense_ui.QInputDialog.getItem',return_value=('fixture',True)):
            window.remove_analysis_publisher()
        assert json.loads((root/'state/analysis-trust.json').read_text())['keys']=={}
        assert (RESOURCE_ROOT/'trusted-update-keys.json').read_bytes()==global_trust
        assert any(window.lab_tabs.tabText(i)=='Offline Guest Job' for i in range(window.lab_tabs.count()))
    finally:
        window.close(); wait(lambda:not window.isVisible())
print('PASS: user publisher pin/import/revoke, saved model options, derived detection, fresh quarantine and byte-exact restore; no OS trust changes')

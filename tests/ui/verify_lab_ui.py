# Purpose: Harmless lab navigation, runner lifecycle, export, and evidence isolation.
# Works with: paths, ui.application, ui.design
# Used by: unittest discovery

"""Harmless lab navigation, runner lifecycle, export, and evidence isolation."""
from sentinelav.paths import SCREENSHOTS_DIR
import os
os.environ['QT_QPA_PLATFORM']='offscreen'
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
from PySide6.QtCore import QTimer,QEventLoop,Qt
from PySide6.QtWidgets import QApplication,QFileDialog
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app

app=QApplication([])
app.setQuitOnLastWindowClosed(False)
configure_app(app)


def wait_for(predicate):
    loop=QEventLoop()
    found=[False]
    def check():
        if predicate():
            found[0]=True
            loop.quit()
    timer=QTimer()
    timer.timeout.connect(check)
    timer.start(25)
    QTimer.singleShot(15000,loop.quit)
    loop.exec()
    assert found[0], 'Lab UI check timed out'


with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    window=Window(data_dir=root/'state')
    window.show()
    try:
        assert window.stack.count()==8
        window.navigate(6)
        assert window.buttons[6].isChecked()
        with patch('sentinelav.ui.lab_ui_workers.capabilities',return_value=dict(hyperv_tools=False,vm_service='Not configured',note='No containment claimed.')):
            window.check_lab_system()
            wait_for(lambda:window.capability_worker is None)
        for row in range(window.lab_queue.rowCount()):
            window.lab_queue.item(row,0).setCheckState(Qt.CheckState.Checked)
        window.start_lab()
        wait_for(lambda:window.lab_worker is None)
        assert window.lab_runs[0]['status']=='Checks passed'
        assert window.lab_runs[0]['workspace_reset']
        assert window.store.history()==[]
        assert not any(e['level']=='Alert' for e in window.store.events())
        window.lab_results_table.selectRow(0)
        target=root/'lab-evidence.json'
        with patch.object(QFileDialog,'getSaveFileName',return_value=(str(target),'')):
            window.export_lab_result()
        assert json.loads(target.read_text())['mode']=='local_safe_simulation'
        for tab in range(4):
            window.lab_tabs.setCurrentIndex(tab)
            app.processEvents()
            window.grab().save(str(SCREENSHOTS_DIR/f'preview-lab-{tab}.png'))
        for size in [(960,600),(1440,900),(1920,1080)]:
            window.resize(*size)
            app.processEvents()
            assert window.stack.widget(6).horizontalScrollBar().maximum()==0
        window.start_lab()
        window.close()
        wait_for(lambda:not window.isVisible())
    finally:
        if window.lab_worker:
            window.stop_lab()
            wait_for(lambda:window.lab_worker is None)
        if window.isVisible():
            window.close()
print('PASS: seven-page navigation, capability states, four safe profiles, isolated evidence/export, sizing, and close during simulation')

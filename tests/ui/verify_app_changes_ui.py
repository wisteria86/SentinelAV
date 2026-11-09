# Purpose: Compact layout and reviewed-change workflow with generated registry-like data.
# Works with: data.contracts, monitoring.app_changes, ui.application, ui.design
# Used by: unittest discovery

"""Compact layout and reviewed-change workflow with generated registry-like data."""
import os
os.environ['QT_QPA_PLATFORM']='offscreen'
from pathlib import Path
import tempfile
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QEventLoop,QTimer
from sentinelav.ui.application import Window
from sentinelav.ui.design import configure_app
from sentinelav.data.contracts import change_record
from sentinelav.monitoring.app_changes import resource

app=QApplication([]);configure_app(app)
with tempfile.TemporaryDirectory() as folder:
    window=Window(Path(folder));window.resize(960,600);window.show();window.navigate(7);app.processEvents()
    target=resource('registry',hive='HKCU',key='Software/fixture',name='Generated fixture',view=64)
    row=change_record(target,None,dict(exists=True,value='Ordinary fixture'),baseline=True)
    window.change_completed(dict(rows=[row],receipts=[],errors=['Fixture: attribution unavailable']))
    window.change_table.selectRow(0);window.show_change(0)
    assert window.stack.currentIndex()==7
    assert window.change_table.rowCount()==1
    assert 'Unattributed'==window.change_table.item(0,2).text()
    assert 'baseline_trusted' in window.change_details.toPlainText()
    assert not window.change_execute.isEnabled()
    assert window.change_table.width()>400
    window.change_source.setCurrentIndex(1);app.processEvents()
    assert not window.track_changes.isEnabled()
    assert window.change_table.rowCount()==0
    assert 'UAC' in window.change_status.text()
    window.change_source.setCurrentIndex(0);app.processEvents()
    assert window.track_changes.isEnabled()
    loop=QEventLoop();timer=QTimer()
    timer.timeout.connect(lambda:loop.quit() if window.rules_worker is None else None)
    timer.start(20);QTimer.singleShot(10000,loop.quit);loop.exec();timer.stop()
    assert window.rules_worker is None
    window.close();app.processEvents()
print('PASS: compact App Changes page, attribution, before/after and disabled unapproved action')

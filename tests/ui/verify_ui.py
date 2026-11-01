"""Offscreen integration check with a harmless marker and isolated SQLite data."""
from sentinelav.paths import SCREENSHOTS_DIR
import os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
import tempfile
from pathlib import Path
from PySide6.QtWidgets import QApplication, QComboBox
from PySide6.QtCore import QTimer, QEventLoop, QPoint
from PySide6.QtGui import QFontDatabase
from sentinelav.ui.application import Window, STYLE

app = QApplication([])
from sentinelav.ui.design import configure_app
configure_app(app)
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    marker = root/'demo.txt'
    marker.write_text('SENTINELAV_DEMO_THREAT_7C23A')
    window = Window(data_dir=root/'state')
    window.show()
    window.start_scan([marker], 'Integration Test')
    timed_out = [True]
    loop = QEventLoop()
    def check():
        if window.worker is None:
            timed_out[0] = False
            loop.quit()
    timer = QTimer()
    timer.timeout.connect(check)
    timer.start(50)
    QTimer.singleShot(10000, loop.quit)
    loop.exec()
    assert not timed_out[0], 'Worker timed out'
    report = window.store.history()[0]
    assert report['scanned'] == 1
    assert len(report['detections']) == 1
    assert window.results.rowCount() == 1
    window.navigate(0)
    app.processEvents()
    window.grab().save(str(SCREENSHOTS_DIR/'preview.png'))
    for page in range(window.stack.count()):
        window.navigate(page)
        app.processEvents()
        assert window.stack.currentIndex() == page
        window.grab().save(str(SCREENSHOTS_DIR/f'preview-{page}.png'))
    window.change_report(1)
    assert window.history_table.rowCount() == 1
    window.change_report(0)
    window.select_scan_tab(2)
    assert window.scan_start.text() == 'Choose Folder…'
    window.path_label.setText('C:/' + 'a-very-long-folder-name/' * 40 + 'sample.exe')
    for width, height in [(960,600), (1440,900), (1920,1080)]:
        window.resize(width,height)
        for page in range(window.stack.count()):
            window.navigate(page)
            app.processEvents()
            scroll = window.stack.currentWidget()
            assert scroll.widget().width() <= 930
            assert scroll.horizontalScrollBar().maximum() == 0, (width,page,'horizontal overflow')
            title = scroll.widget().findChild(__import__('PySide6.QtWidgets',fromlist=['QLabel']).QLabel,'title')
            assert title.mapTo(scroll.widget(),QPoint(0,0)).y() == 23, (width,page,'header alignment')
    window.resize(1000,620)
    window.navigate(5)
    app.processEvents()
    combo = next(c for c in window.findChildren(QComboBox) if c.currentText()=='Light')
    combo.showPopup()
    app.processEvents()
    assert combo.view().model().index(0,0).data() == 'Light'
    combo.view().window().grab().save(str(SCREENSHOTS_DIR/'preview-dropdown.png'))
    combo.hidePopup()
    for page in range(window.stack.count()):
        window.navigate(page)
        app.processEvents()
        window.grab().save(str(SCREENSHOTS_DIR/f'preview-{page}.png'))
    window.close()
print('PASS: background scan, YARA detection, history, all navigation pages, and screenshot')

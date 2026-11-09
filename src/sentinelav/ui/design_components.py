# Purpose: Share reusable widgets, SVG icons, fonts, and the orange/cream stylesheet.
# Works with: paths
# Used by: ui.design, ui.design_dashboard, ui.design_reports, ui.design_scan

"""Reference-inspired desktop components; all icons are resolution-independent SVGs."""
from sentinelav.paths import RESOURCE_ROOT
from PySide6.QtCore import Qt, QByteArray, QRectF
from PySide6.QtGui import QIcon, QPixmap, QPainter, QColor
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QWidget, QLabel, QSizePolicy


class InactiveSwitch(QWidget):
    """Draw the unavailable switch without relying on a font glyph."""
    def __init__(self):
        super().__init__()
        self.active = False
        self.setFixedSize(39, 22)
        self.setToolTip('Not available in this prototype')
        self.setAccessibleName('Protection off; feature not available')

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QColor('#d6c3ab'))
        painter.setBrush(QColor('#ee8129' if self.active else '#e9ddcc'))
        painter.drawRoundedRect(QRectF(1, 1, 37, 20), 10, 10)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor('#fffaf2'))
        painter.drawEllipse(QRectF(20 if self.active else 3, 3, 16, 16))


class PathLabel(QLabel):
    """Keep long paths from changing the size of the scan card."""
    def __init__(self, text='', **kwargs):
        super().__init__('', **kwargs)
        self.full_text = text
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(22)
        self.setText(text)

    def setText(self, text):
        self.full_text = text
        self.setToolTip(text)
        super().setText(self.fontMetrics().elidedText(text, Qt.TextElideMode.ElideMiddle, max(0, self.width())))

    def resizeEvent(self, event):
        self.setText(self.full_text)
        super().resizeEvent(event)


def configure_app(app):
    from PySide6.QtGui import QFontDatabase
    app.setStyle('Fusion')
    for name in ['segoeui.ttf', 'segoeuib.ttf', 'seguisb.ttf']:
        QFontDatabase.addApplicationFont('C:/Windows/Fonts/' + name)
    app.setStyleSheet(STYLE)

PATHS = {
 'lab': '<path d="M9 2h6M10 2v7L4 19q-1 3 2 3h12q3 0 2-3L14 9V2M7 15h10"/>',
 'shield': '<path d="M12 2 21 6v6c0 6-9 10-9 10S3 18 3 12V6Z"/><path d="m8 12 3 3 5-6"/>',
 'home': '<path d="m3 11 9-8 9 8M5 10v11h5v-7h4v7h5V10"/>',
 'scan': '<circle cx="10" cy="10" r="7"/><path d="m15 15 7 7"/>',
 'box': '<rect x="3" y="7" width="18" height="14" rx="2"/><path d="M2 3h20v4H2zM10 12h4"/>',
 'report': '<path d="M5 2h10l4 4v16H5zM14 2v6h5M8 12h8M8 16h8"/>',
 'settings': '<path d="m9 3 1-2h4l1 2 3 2 3 1v4l-2 2v3l1 3-3 3-3-1h-3l-2 2-4-2v-3l-2-3-2-1V9l3-1 2-3z"/><circle cx="12" cy="12" r="3"/>',
 'bars': '<path d="M4 21V13M9 21V7M14 21V2M19 21V10"/>',
 'folder': '<path d="M2 6h8l2 3h10v12H2zM2 6V3h8l2 3h9v3"/>',
 'play': '<path d="m8 3 13 9L8 21Z"/>',
 'network': '<circle cx="12" cy="12" r="10"/><ellipse cx="12" cy="12" rx="4" ry="10"/><path d="M2 12h20M4 6h16M4 18h16"/>',
 'lock': '<rect x="5" y="10" width="14" height="12" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4M12 15v3"/>',
}

def pixmap(name, color='#ed7b23', size=24, filled=False):
    body = PATHS.get(name, PATHS['shield'])
    if filled and name == 'shield':
        body = '<path fill="'+color+'" stroke="'+color+'" d="M12 2 21 6v6c0 6-9 10-9 10S3 18 3 12V6Z"/><path stroke="white" d="m8 12 3 3 5-6"/>'
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    result = QPixmap(size*2, size*2)
    result.fill(Qt.GlobalColor.transparent)
    painter = QPainter(result)
    QSvgRenderer(QByteArray(svg.encode())).render(painter)
    painter.end()
    result.setDevicePixelRatio(2)
    return result

def icon(name, color='#ed7b23'):
    return QIcon(pixmap(name, color))

def art(name, size=24, color='#ed7b23', filled=False):
    label = QLabel()
    label.setPixmap(pixmap(name, color, size, filled))
    label.setFixedSize(size, size)
    label.setStyleSheet('background:transparent;border:0;')
    return label

STYLE = '''
QWidget {font-family:'Segoe UI';font-size:13px;color:#241a12;background:#fff6e8;}
QMainWindow {background:#fff6e8;}
QLabel {background:transparent;border:0;}
QFrame#sidebar {background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #342315,stop:1 #22180f);border-right:1px solid #493322;}
QFrame#sidebar QLabel {color:#fff2df;}
QFrame#sidebar QPushButton {background:transparent;color:#fff2df;text-align:left;border:0;padding:10px 12px;font-size:12px;border-radius:6px;}
QFrame#sidebar QPushButton:hover {background:#473020;}
QFrame#sidebar QPushButton:checked {background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #f69539,stop:1 #ed7c23);color:#21170e;}
QLabel#brand {font-size:19px;font-weight:700;}
QLabel#title {font-size:26px;font-weight:700;}
QLabel#statusTitle {font-size:23px;font-weight:700;}
QLabel#muted {color:#6f665d;font-size:12px;}
QLabel#small {color:#6f665d;font-size:11px;}
QLabel#value {font-size:17px;font-weight:600;}
QFrame#card {border:1px solid #e7dac8;border-radius:8px;background:#fff8ed;}
QFrame#badge {border:0;border-radius:7px;background:#fbedda;}
QPushButton {background:#fff1df;border:1px solid #edbc90;padding:9px 18px;border-radius:5px;}
QPushButton:hover {background:#ffe4c7;}
QPushButton#primary {background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #ef8a32,stop:1 #ed7921);border:1px solid #e97c26;color:white;font-weight:600;}
QPushButton:disabled {background:#f0e7da;color:#a2978b;border-color:#e5d9c8;}
QPushButton#primary:disabled {background:#f0e7da;color:#a2978b;border-color:#e5d9c8;}
QPushButton#tab {background:transparent;border:0;border-bottom:2px solid transparent;border-radius:0;padding:10px 20px;}
QPushButton#tab:checked {color:#df6815;border-bottom:2px solid #f17c25;font-weight:600;}
QProgressBar {border:0;border-radius:7px;background:#f0e5d5;height:14px;color:#6b5946;text-align:center;}
QProgressBar::chunk {background:#ed812b;border-radius:7px;}
QTableWidget {background:#fff8ed;alternate-background-color:#fcf2e3;border:1px solid #e6d9c7;border-radius:6px;gridline-color:#eee2d1;font-size:12px;selection-background-color:#ffe2be;selection-color:#251b11;}
QHeaderView::section {background:#f5ead9;border:0;border-bottom:1px solid #e6d9c7;padding:8px;font-size:11px;}
QTabWidget::pane {border:1px solid #e7dac8;border-radius:6px;background:#fff8ed;}
QTabBar::tab {background:transparent;padding:10px 16px;border-bottom:2px solid transparent;font-size:12px;}
QTabBar::tab:selected {color:#df6815;border-bottom:2px solid #f17c25;}
QPlainTextEdit,QSpinBox,QComboBox,QLineEdit,QTimeEdit {background:#fff8ed;border:1px solid #e5cfb6;border-radius:5px;padding:7px;}
QComboBox {color:#291e15;min-height:22px;padding:5px 30px 5px 10px;}
QComboBox::drop-down {width:25px;border:0;border-left:1px solid #e5cfb6;background:#f9ecd9;border-top-right-radius:5px;border-bottom-right-radius:5px;}
QComboBox QAbstractItemView {background:#fff8ed;color:#291e15;selection-background-color:#f18a32;selection-color:#21180f;border:1px solid #ddc5a7;outline:0;padding:4px;}
QComboBox QAbstractItemView::item {min-height:30px;padding:4px 10px;color:#291e15;}
QScrollArea {border:0;background:#fff6e8;}
QScrollBar:vertical {width:8px;background:#fff6e8;margin:0;}
QScrollBar::handle:vertical {background:#dac7af;border-radius:4px;min-height:30px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {height:0;}
QFrame#separator {background:#ebdfce;max-height:1px;border:0;}
QToolTip {background:#2e2117;color:#fff5e6;border:1px solid #6c4b2e;padding:6px;}
'''
STYLE += 'QComboBox::down-arrow {image:url("' + (RESOURCE_ROOT/'assets/chevron.svg').as_posix() + '");width:10px;height:6px;}'

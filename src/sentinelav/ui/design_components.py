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
        """Create the switch in its 'off' state with a fixed size and tooltip."""
        super().__init__()
        self.active = False
        self.setFixedSize(39, 22)
        self.setToolTip('Not available in this prototype')
        self.setAccessibleName('Protection off; feature not available')

    def paintEvent(self, event):
        """Draw the rounded track and the round knob (on the right when active)."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QColor('#e0cbb0'))
        painter.setBrush(QColor('#ee8129' if self.active else '#efe4d4'))
        painter.drawRoundedRect(QRectF(1, 1, 37, 20), 10, 10)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor('#fffaf2'))
        painter.drawEllipse(QRectF(20 if self.active else 3, 3, 16, 16))


class PathLabel(QLabel):
    """Keep long paths from changing the size of the scan card."""
    def __init__(self, text='', **kwargs):
        """Create the label; long text is shortened with an ellipsis in the middle."""
        super().__init__('', **kwargs)
        self.full_text = text
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(22)
        self.setText(text)

    def setText(self, text):
        """Show the text, shortened to fit, with the full text as a tooltip."""
        self.full_text = text
        self.setToolTip(text)
        super().setText(self.fontMetrics().elidedText(text, Qt.TextElideMode.ElideMiddle, max(0, self.width())))

    def resizeEvent(self, event):
        """Re-shorten the text whenever the label changes size."""
        self.setText(self.full_text)
        super().resizeEvent(event)


def configure_app(app):
    """Apply the app-wide look: Fusion style, Segoe UI fonts and the SentinelAV stylesheet."""
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
    """Draw one of the built-in line icons (see PATHS) as a crisp, high-resolution image."""
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
    """Return a built-in icon as a QIcon, for buttons."""
    return QIcon(pixmap(name, color))

def art(name, size=24, color='#ed7b23', filled=False):
    """Return a built-in icon as a fixed-size QLabel, for placing in layouts."""
    label = QLabel()
    label.setPixmap(pixmap(name, color, size, filled))
    label.setFixedSize(size, size)
    label.setStyleSheet('background:transparent;border:0;')
    return label

STYLE = '''
QWidget {font-family:'Segoe UI';font-size:13px;color:#2a1f16;background:#fbf3e7;}
QMainWindow {background:#fbf3e7;}
QLabel {background:transparent;border:0;}
QFrame#sidebar {background:qlineargradient(x1:0,y1:0,x2:0.35,y2:1,stop:0 #3a2717,stop:1 #1f160e);border-right:1px solid #120c07;}
QFrame#sidebar QLabel {color:#fff2df;}
QFrame#sidebar QLabel#small {color:#a8927a;}
QFrame#sidebar QPushButton {background:transparent;color:#ead9c3;text-align:left;border:0;padding:10px 14px;font-size:12px;border-radius:9px;}
QFrame#sidebar QPushButton:hover {background:rgba(255,226,190,0.08);color:#fff4e4;}
QFrame#sidebar QPushButton:checked {background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #f59a42,stop:1 #ec7a22);color:#1f150c;font-weight:600;}
QLabel#brand {font-size:19px;font-weight:700;letter-spacing:0.3px;}
QLabel#title {font-size:26px;font-weight:700;color:#21170e;}
QLabel#statusTitle {font-size:23px;font-weight:700;color:#21170e;}
QLabel#muted {color:#7a6c5e;font-size:12px;}
QLabel#small {color:#85776a;font-size:11px;}
QLabel#value {font-size:19px;font-weight:700;color:#21170e;}
QFrame#card {border:1px solid #eedfcb;border-bottom:1px solid #e3d0b7;border-radius:12px;background:#fffbf5;}
QFrame#badge {border:0;border-radius:12px;background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #fff0dc,stop:1 #fbe3c6);}
QFrame#chip {border:0;border-radius:10px;background:#fdecd7;}
QPushButton {background:#fffbf5;border:1px solid #ecc9a4;color:#3b2a1c;padding:9px 18px;border-radius:8px;}
QPushButton:hover {background:#fff1e0;border-color:#e9a565;}
QPushButton:pressed {background:#fde3c4;}
QPushButton:focus {outline:0;}
QPushButton#primary {background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #f39340,stop:1 #ea7520);border:1px solid #df6e1c;color:white;font-weight:600;}
QPushButton#primary:hover {background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #f69f52,stop:1 #ee7f2b);}
QPushButton#primary:pressed {background:#dc6a18;}
QPushButton:disabled {background:#f3eadd;color:#ab9f92;border-color:#e9dece;}
QPushButton#primary:disabled {background:#f3eadd;color:#ab9f92;border-color:#e9dece;}
QPushButton#tab {background:transparent;border:0;border-bottom:2px solid transparent;border-radius:0;padding:10px 20px;color:#6d5e50;}
QPushButton#tab:hover {color:#2a1f16;border-bottom:2px solid #f0d2b0;}
QPushButton#tab:checked {color:#dc6514;border-bottom:2px solid #f17c25;font-weight:600;}
QProgressBar {border:0;border-radius:6px;background:#f1e5d4;max-height:12px;color:#6b5946;text-align:center;font-size:10px;}
QProgressBar::chunk {background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #f6a052,stop:1 #ea7520);border-radius:6px;}
QTableWidget, QTableView, QListWidget, QTreeWidget {background:#fffbf5;alternate-background-color:#fcf4e8;border:1px solid #eedfcb;border-radius:10px;gridline-color:#f1e6d6;font-size:12px;selection-background-color:#ffe4c4;selection-color:#251b11;outline:0;}
QTableWidget::item, QTableView::item {padding:4px 6px;}
QHeaderView {background:transparent;}
QHeaderView::section {background:#f7ecdc;color:#5c4b3b;border:0;border-bottom:1px solid #eadac4;padding:9px 8px;font-size:11px;font-weight:600;}
QTableCornerButton::section {background:#f7ecdc;border:0;}
QTabWidget::pane {border:1px solid #eedfcb;border-radius:10px;background:#fffbf5;}
QTabBar {background:transparent;}
QTabWidget > QStackedWidget, QTabWidget > QStackedWidget > QWidget {background:transparent;}
QTabBar::tab {background:transparent;color:#6d5e50;padding:10px 16px;border:0;border-bottom:2px solid transparent;font-size:12px;}
QTabBar::tab:hover {color:#2a1f16;border-bottom:2px solid #f0d2b0;}
QTabBar::tab:selected {color:#dc6514;border-bottom:2px solid #f17c25;font-weight:600;}
QTabBar QToolButton {background:#fffbf5;border:1px solid #eedfcb;border-radius:6px;}
QPlainTextEdit,QTextEdit,QSpinBox,QComboBox,QLineEdit,QTimeEdit,QDoubleSpinBox {background:#fffdf9;border:1px solid #e8d3ba;border-radius:8px;padding:7px;selection-background-color:#f6b878;selection-color:#21170e;}
QPlainTextEdit:hover,QTextEdit:hover,QSpinBox:hover,QComboBox:hover,QLineEdit:hover,QTimeEdit:hover,QDoubleSpinBox:hover {border-color:#e2bb92;}
QPlainTextEdit:focus,QTextEdit:focus,QSpinBox:focus,QComboBox:focus,QLineEdit:focus,QTimeEdit:focus,QDoubleSpinBox:focus {border:1px solid #ef8a32;}
QComboBox {color:#291e15;min-height:22px;padding:5px 30px 5px 10px;}
QComboBox::drop-down {width:26px;border:0;border-left:1px solid #eedcc5;background:transparent;border-top-right-radius:8px;border-bottom-right-radius:8px;}
QComboBox QAbstractItemView {background:#fffbf5;color:#291e15;selection-background-color:#fde1bf;selection-color:#21180f;border:1px solid #e6cfb2;border-radius:6px;outline:0;padding:4px;}
QComboBox QAbstractItemView::item {min-height:30px;padding:4px 10px;color:#291e15;border-radius:5px;}
QCheckBox, QRadioButton {spacing:8px;background:transparent;}
QCheckBox::indicator {width:16px;height:16px;border:1px solid #dcc2a3;border-radius:5px;background:#fffdf9;}
QCheckBox::indicator:hover {border-color:#ef8a32;}
QCheckBox::indicator:checked {background:#ee7f26;border-color:#e2731d;}
QCheckBox::indicator:disabled {background:#f3eadd;border-color:#e9dece;}
QRadioButton::indicator {width:16px;height:16px;border:1px solid #dcc2a3;border-radius:9px;background:#fffdf9;}
QRadioButton::indicator:hover {border-color:#ef8a32;}
QRadioButton::indicator:checked {background:qradialgradient(cx:0.5,cy:0.5,radius:0.5,fx:0.5,fy:0.5,stop:0 #ee7f26,stop:0.45 #ee7f26,stop:0.55 #fffdf9,stop:1 #fffdf9);border-color:#ee7f26;}
QScrollArea {border:0;background:#fbf3e7;}
QScrollArea > QWidget > QWidget {background:#fbf3e7;}
QScrollBar:vertical {width:10px;background:transparent;margin:2px;}
QScrollBar:horizontal {height:10px;background:transparent;margin:2px;}
QScrollBar::handle:vertical {background:#e0cdb4;border-radius:3px;min-height:30px;}
QScrollBar::handle:horizontal {background:#e0cdb4;border-radius:3px;min-width:30px;}
QScrollBar::handle:hover {background:#cfb592;}
QScrollBar::add-line,QScrollBar::sub-line {height:0;width:0;}
QScrollBar::add-page,QScrollBar::sub-page {background:transparent;}
QFrame#separator {background:#efe3d2;max-height:1px;border:0;}
QToolTip {background:#2e2117;color:#fff5e6;border:1px solid #5a3e26;border-radius:6px;padding:6px 8px;}
QMenu {background:#fffbf5;border:1px solid #e6cfb2;border-radius:8px;padding:4px;}
QMenu::item {padding:6px 18px;border-radius:5px;}
QMenu::item:selected {background:#fde1bf;color:#21170e;}
QMessageBox, QDialog {background:#fbf3e7;}
'''
STYLE += 'QCheckBox::indicator:checked {image:url("' + (RESOURCE_ROOT/'assets/check.svg').as_posix() + '");}'
STYLE += 'QComboBox::down-arrow {image:url("' + (RESOURCE_ROOT/'assets/chevron.svg').as_posix() + '");width:10px;height:6px;}'

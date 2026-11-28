# Purpose: Build shared scrollable page frames and dashboard status indicators.
# Works with: ui.design_components
# Used by: ui.design

"""Reference-inspired desktop components; all icons are resolution-independent SVGs."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QSizePolicy, QScrollArea
from .design_components import InactiveSwitch


class DesignShellMixin:
    """Shared page scaffolding used by every page builder."""
    def page(self, title, subtitle):
        """Create a new scrollable page with a title and subtitle, add it to the page stack, and return
        its layout to fill in.
        """
        page = QWidget()
        page.setMaximumWidth(930)
        page.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 23, 24, 22)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        header_widget = QWidget()
        header_widget.setFixedHeight(54)
        header = QVBoxLayout(header_widget)
        header.setContentsMargins(0,0,0,0)
        header.setSpacing(3)
        header.addWidget(QLabel(title, objectName='title'))
        label = QLabel(subtitle, objectName='muted')
        label.setWordWrap(True)
        header.addWidget(label)
        layout.addWidget(header_widget)
        layout.addSpacing(6)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(page)
        self.stack.addWidget(scroll)
        return layout

    def toggle(self):
        """Return a decorative on/off switch."""
        return InactiveSwitch()


# Purpose: Build shared window controls and render or export scan history.
# Works with: paths
# Used by: ui.application

from sentinelav.paths import RESOURCE_ROOT
import json
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QVBoxLayout,
    QPushButton,
    QFrame,
    QFileDialog,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QSizePolicy,
)

ROOT = RESOURCE_ROOT


class WindowWidgetsMixin:
    """Small widget helpers shared by every page."""

    def card(self, layout):
        """Add a rounded 'card' frame to a layout and return the layout inside it."""
        frame = QFrame(objectName='card')
        inner = QVBoxLayout(frame)
        inner.setContentsMargins(22, 22, 22, 22)
        inner.setSpacing(12)
        inner.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(frame)
        return inner

    def action(self, layout, text, callback, primary=False):
        """Add a push button that calls `callback` when clicked (primary=True gives it the orange
        style) and return it.
        """
        button = QPushButton(text, objectName='primary' if primary else '')
        button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        button.clicked.connect(callback)
        layout.addWidget(button)
        return button

    def table(self, headings):
        """Create a read-only, row-selecting table with the given column headings."""
        table = QTableWidget(0, len(headings))
        table.setHorizontalHeaderLabels(headings)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        table.verticalHeader().setDefaultSectionSize(36)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.verticalHeader().hide()
        table.setWordWrap(False)
        return table

    def fit_columns(self, table, *wide):
        """Give spare width to the columns that hold long text, and size short values to their content."""
        header = table.horizontalHeader()
        for column in range(table.columnCount()):
            header.setSectionResizeMode(
                column,
                (
                    QHeaderView.ResizeMode.Stretch
                    if column in wide
                    else QHeaderView.ResizeMode.ResizeToContents
                ),
            )

    def fill(self, table, rows):
        """Replace a table's contents with the given rows, adding tooltips for long values."""
        table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                table.setItem(i, j, item)

    def show_report(self, row, column):
        """Show the full JSON of a saved scan in a dialog."""
        report = self.store.history()[row]
        box = QMessageBox(self)
        box.setWindowTitle('Scan report')
        box.setText(f"{report['started']} — {report['status']}")
        box.setDetailedText(json.dumps(report, indent=2))
        box.exec()

    def export(self):
        """Save the scan history as a JSON file."""
        path, _ = QFileDialog.getSaveFileName(
            self, 'Export report', 'sentinelav-report.json', 'JSON (*.json)'
        )
        if path:
            try:
                Path(path).write_text(json.dumps(self.store.history(), indent=2), encoding='utf-8')
            except OSError as error:
                QMessageBox.warning(self, 'Export failed', str(error))

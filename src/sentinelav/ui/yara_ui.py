# Purpose: Rule provenance and compilation status in the existing Settings layout.
# Works with: detection.inspection, ui.application
# Used by: ui.application

"""Rule provenance and compilation status in the existing Settings layout."""
import json
from PySide6.QtCore import QThread,Signal,QTimer,Qt
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QTabWidget,QHeaderView,QMessageBox


class RuleCheckWorker(QThread):
    completed=Signal(dict)
    failed=Signal(str)

    def __init__(self,folder):
        super().__init__()
        self.folder=folder

    def run(self):
        scanner=None
        try:
            from sentinelav.detection.inspection import IsolatedScanner
            scanner=IsolatedScanner(self.folder.parent/'signatures.json',self.folder)
            self.completed.emit(scanner.rule_summary)
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            if scanner: scanner.close()


class YaraMixin:
    def settings_page(self):
        super().settings_page()
        tabs=self.stack.widget(5).findChild(QTabWidget)
        page=QWidget()
        layout=QVBoxLayout(page)
        layout.setContentsMargins(16,12,16,12)
        self.yara_health=QLabel('Rule validation has not run in this session.',objectName='small')
        self.yara_health.setWordWrap(True)
        self.yara_health.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.yara_health)
        self.yara_table=self.table(['Rule bundle','Public / helper','Source','License'])
        self.yara_table.setFixedHeight(140)
        self.yara_table.setStyleSheet('QTableWidget::item {padding:1px;}')
        self.yara_table.horizontalHeader().setFixedHeight(28)
        self.yara_table.verticalHeader().setMinimumSectionSize(20)
        self.yara_table.verticalHeader().setDefaultSectionSize(20)
        for column in (1,2,3): self.yara_table.horizontalHeader().setSectionResizeMode(column,QHeaderView.ResizeMode.ResizeToContents)
        self.yara_table.cellDoubleClicked.connect(self.yara_details)
        layout.addWidget(self.yara_table)
        row=QHBoxLayout()
        self.yara_validate_button=self.action(row,'Validate Rules',self.validate_yara_rules)
        row.addStretch()
        layout.addLayout(row)
        label=QLabel('Source-reviewed research rules; effectiveness and false-positive evaluation are deferred.\nDouble-click a bundle for its pinned source and review details. Restart monitoring after rule changes.',objectName='small')
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addStretch()
        tabs.addTab(page,'YARA Rules')
        self.yara_files=[]

    def validate_yara_rules(self):
        if self.rules_worker or self.closing: return
        from sentinelav.ui.application import ROOT
        self.yara_health.setText('Validating source checksums and compiling rules…')
        self.yara_validate_button.setEnabled(False)
        self.rules_worker=RuleCheckWorker(ROOT/'rules')
        self.rules_worker.completed.connect(self.yara_checked)
        self.rules_worker.failed.connect(self.yara_check_failed)
        self.rules_worker.finished.connect(self.yara_check_finished)
        self.rules_worker.start()

    def yara_checked(self,summary):
        self.yara_files=summary['files']
        self.fill(self.yara_table,[(f['file'],f"{f.get('public_rules',0)} / {f.get('private_helpers',0)}",
                    'SentinelAV demo' if f.get('demo') else 'ESET Research' if f.get('managed') else 'Local / unreviewed',
                    f.get('license','Unspecified')) for f in self.yara_files])
        self.yara_health.setText(f"{summary['status']} · {summary['research_rules']} research rules · {summary['demo_rules']} demo · "
            f"{summary['private_helpers']} private helpers · {summary['local_rules']} local\n"
            f"YARA {summary.get('yara_version','unavailable')} · Catalog {summary.get('catalog_version') or 'unmanaged'}"+
            ('\n'+'; '.join(summary['warnings']) if summary['warnings'] else ' · No compilation warnings'))

    def yara_check_failed(self,error):
        self.yara_files=[]
        self.yara_table.setRowCount(0)
        self.yara_health.setText('Rule validation failed. New scans cannot load this rule set.\n'+error[:1200])
        self.yara_health.setToolTip(error)

    def yara_check_finished(self):
        self.rules_worker.deleteLater()
        self.rules_worker=None
        self.yara_validate_button.setEnabled(True)

    def yara_details(self,row,column):
        if not 0<=row<len(self.yara_files): return
        record=self.yara_files[row]
        box=QMessageBox(self)
        box.setWindowTitle('YARA rule provenance')
        box.setText(record.get('coverage',record['file']))
        box.setDetailedText(json.dumps(record,indent=2))
        box.exec()

    def closeEvent(self,event):
        if self.rules_worker:
            event.ignore()
            QTimer.singleShot(100,self.close)
            return
        super().closeEvent(event)

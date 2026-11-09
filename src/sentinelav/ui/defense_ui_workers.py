# Purpose: Honest layer status, bounded manual inspection, and opt-in response policy.
# Works with: detection.inspection, detection.preexecution
# Used by: ui.defense_ui

"""Honest layer status, bounded manual inspection, and opt-in response policy."""
from PySide6.QtCore import QThread, Signal
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.detection.preexecution import verdict


class InspectionWorker(QThread):
    completed=Signal(dict)
    failed=Signal(str)
    def __init__(self,root,kind,target,options):
        super().__init__()
        self.root,self.kind,self.target,self.options=root,kind,target,options
    def run(self):
        scanner=None
        try:
            scanner=IsolatedScanner(self.root/'signatures.json',self.root/'rules',options=self.options)
            if self.kind=='memory':
                pid,creation=self.target
                result=scanner.scan_memory(pid,creation,self.isInterruptionRequested)
            else:
                report=scanner.scan([self.target],self.isInterruptionRequested,lambda *a:None)
                result=dict(scope='Manual pre-execution inspection; no file was launched',verdict=verdict(self.target,report),scan=report)
            self.completed.emit(result)
        except Exception as error: self.failed.emit(str(error))
        finally:
            if scanner: scanner.close()

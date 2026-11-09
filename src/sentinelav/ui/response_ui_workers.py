# Purpose: Explicit response actions; no automatic quarantine or process termination.
# Works with: data.storage, response.response
# Used by: ui.response_ui

"""Explicit response actions; no automatic quarantine or process termination."""
from PySide6.QtCore import QThread, Signal
from sentinelav.data.storage import Store
from sentinelav.response.response import ResponseService


class ResponseWorker(QThread):
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self,path,root,method,args):
        super().__init__()
        self.path,self.root,self.method,self.args = path,root,method,args

    def run(self):
        store = None
        try:
            store = Store(self.path)
            service = ResponseService(store,self.root)
            result = getattr(service,self.method)(*self.args)
            self.completed.emit(result)
        except Exception as error:
            if store:
                try:
                    ResponseService(store,self.root).audit('Response failed',f'{self.method}: {error}','Warning')
                except Exception:
                    pass
            self.failed.emit(str(error))
        finally:
            if store:
                store.db.close()

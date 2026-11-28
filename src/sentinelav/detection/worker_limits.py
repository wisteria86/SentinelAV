# Purpose: Enforce memory and process limits for isolated scanner workers.
# Works with: sibling modules in detection
# Used by: detection.inspection

"""JSON-only scan worker with Windows job limits and bounded transport.

Fault/resource isolation, not a VM or an AppContainer security sandbox.
"""
import ctypes
from ctypes import wintypes
import os

MAX_LINE=4*1024*1024
MAX_REQUEST=2*1024*1024


class WindowsJob:
    """Place a process in a Windows job object that caps its memory and how many processes it may
    start.

    If the scan worker misbehaves, Windows enforces these limits, and closing the job kills the
    worker together with anything it started.
    """
    def __init__(self,process,memory=768*1024*1024,process_limit=2):
        """Create the job with the given memory limit (bytes) and process limit, and put `process` into
        it. Does nothing outside Windows.
        """
        if type(process_limit) is not int or not 1<=process_limit<=32:raise ValueError('Invalid job process limit')
        self.handle=None
        if os.name!='nt': return
        class Basic(ctypes.Structure):
            """JOBOBJECT_BASIC_LIMIT_INFORMATION structure."""
            _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',wintypes.DWORD),
                ('minimum_ws',ctypes.c_size_t),('maximum_ws',ctypes.c_size_t),('processes',wintypes.DWORD),
                ('affinity',ctypes.c_size_t),('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
        class IO(ctypes.Structure):
            """IO_COUNTERS structure."""
            _fields_=[(name,ctypes.c_ulonglong) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
        class Extended(ctypes.Structure):
            """JOBOBJECT_EXTENDED_LIMIT_INFORMATION structure (basic limits plus memory limits)."""
            _fields_=[('basic',Basic),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),
                      ('peak_process_memory',ctypes.c_size_t),('peak_job_memory',ctypes.c_size_t)]
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype=wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        handle=self.kernel.CreateJobObjectW(None,None)
        if not handle: raise ctypes.WinError(ctypes.get_last_error())
        info=Extended()
        # Flags: kill everything when the job closes, enforce per-process and per-job memory limits,
        # and limit the number of active processes.
        info.basic.flags=0x2000|0x100|0x200|0x8
        info.basic.processes=process_limit  # Default: venv redirector plus interpreter.
        info.process_memory=info.job_memory=memory
        if not self.kernel.SetInformationJobObject(handle,9,ctypes.byref(info),ctypes.sizeof(info)) or not self.kernel.AssignProcessToJobObject(handle,wintypes.HANDLE(int(process._handle))):
            self.kernel.CloseHandle(handle)
            raise RuntimeError('Cannot enforce scan-worker job limits')
        self.handle=handle

    def close(self):
        """Close the job handle, which also ends every process in the job."""
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle=None

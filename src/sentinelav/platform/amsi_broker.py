# Purpose: Read-only local AMSI buffer broker. Production endpoint is LocalService-only.
# Works with: detection.buffer_scan, detection.inspection, paths, platform.windows_identity
# Used by: platform.remediation_broker, platform.windows_service, tests.integration.verify_amsi_provider,
#   tests.unit.test_amsi_buffers

"""Read-only local AMSI buffer broker. Production endpoint is LocalService-only.

One bounded request per connection, no file paths, execution, content logging,
or response actions. A separate random endpoint is available to inert tests.
"""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import struct
import sys
import threading
import time
from sentinelav.detection.buffer_scan import MAX_BUFFER
from sentinelav.detection.inspection import IsolatedScanner

PIPE_NAME = r'\\.\pipe\SentinelAV.Amsi.v1'
MAGIC = 0x31414D53
HEADER = struct.Struct('<III')


def response_status(result):
    if result.get('kind') != 'buffer': return 2
    if result.get('detected') is True: return 1
    return 0 if result.get('complete') is True else 2


class PipeAPI:
    def __init__(self, stop):
        self.stop = stop
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        class Overlapped(ctypes.Structure):
            _fields_ = [('internal',ctypes.c_size_t),('internal_high',ctypes.c_size_t),
                        ('offset',wintypes.DWORD),('offset_high',wintypes.DWORD),('event',wintypes.HANDLE)]
        class Security(ctypes.Structure):
            _fields_ = [('length',wintypes.DWORD),('descriptor',ctypes.c_void_p),('inherit',wintypes.BOOL)]
        self.Overlapped, self.Security = Overlapped, Security
        declarations = {
            'CreateNamedPipeW': ([wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(Security)],wintypes.HANDLE),
            'CreateEventW': ([ctypes.c_void_p,wintypes.BOOL,wintypes.BOOL,wintypes.LPCWSTR],wintypes.HANDLE),
            'CloseHandle': ([wintypes.HANDLE],wintypes.BOOL),
            'LocalFree': ([ctypes.c_void_p],ctypes.c_void_p),
            'ConnectNamedPipe': ([wintypes.HANDLE,ctypes.POINTER(Overlapped)],wintypes.BOOL),
            'DisconnectNamedPipe': ([wintypes.HANDLE],wintypes.BOOL),
            'CancelIoEx': ([wintypes.HANDLE,ctypes.POINTER(Overlapped)],wintypes.BOOL),
            'GetOverlappedResult': ([wintypes.HANDLE,ctypes.POINTER(Overlapped),ctypes.POINTER(wintypes.DWORD),wintypes.BOOL],wintypes.BOOL),
            'WaitForSingleObject': ([wintypes.HANDLE,wintypes.DWORD],wintypes.DWORD),
            'ReadFile': ([wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(Overlapped)],wintypes.BOOL),
            'WriteFile': ([wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(Overlapped)],wintypes.BOOL)}
        for name,(arguments,result) in declarations.items():
            function=getattr(self.kernel,name); function.argtypes=arguments; function.restype=result
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.DWORD)]

    def create(self,name):
        descriptor=ctypes.c_void_p()
        # AU: generic read + write-data only. No create-pipe-instance, ACL or ownership rights.
        sddl='D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;0x12008b;;;AU)'
        if name!=PIPE_NAME:
            from sentinelav.platform.windows_identity import current_sid
            sddl+=f'(A;;GA;;;{current_sid()})'
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            security=self.Security(ctypes.sizeof(self.Security),descriptor,False)
            handle=self.kernel.CreateNamedPipeW(name,0x40000000|0x00080000|3,8,1,4096,4096,0,ctypes.byref(security))
            if handle==ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
            return handle
        finally: self.kernel.LocalFree(descriptor)

    def operation(self,handle,kind,data=None,length=0,timeout=3):
        event=self.kernel.CreateEventW(None,True,False,None)
        if not event: raise ctypes.WinError(ctypes.get_last_error())
        overlapped=self.Overlapped(); overlapped.event=event
        count=wintypes.DWORD()
        buffer=ctypes.create_string_buffer(data if kind=='write' else length) if kind!='connect' else None
        pending=False
        try:
            if kind=='connect': ok=self.kernel.ConnectNamedPipe(handle,ctypes.byref(overlapped))
            else:
                operation=self.kernel.WriteFile if kind=='write' else self.kernel.ReadFile
                ok=operation(handle,buffer,len(data) if kind=='write' else length,ctypes.byref(count),ctypes.byref(overlapped))
            if not ok:
                error=ctypes.get_last_error()
                if kind=='connect' and error==535: return b''
                if error!=997: raise ctypes.WinError(error)
                pending=True
                deadline=time.monotonic()+timeout if timeout is not None else None
                while self.kernel.WaitForSingleObject(event,50)==258:
                    if self.stop.is_set(): raise InterruptedError('AMSI broker stopping')
                    if deadline is not None and time.monotonic()>deadline: raise TimeoutError('AMSI transport timeout')
                if not self.kernel.GetOverlappedResult(handle,ctypes.byref(overlapped),ctypes.byref(count),False):
                    raise ctypes.WinError(ctypes.get_last_error())
                pending=False
            if kind=='connect': return b''
            return count.value if kind=='write' else buffer.raw[:count.value]
        finally:
            if pending:
                self.kernel.CancelIoEx(handle,ctypes.byref(overlapped))
                self.kernel.GetOverlappedResult(handle,ctypes.byref(overlapped),ctypes.byref(count),True)
            self.kernel.CloseHandle(event)

    def read_exact(self,handle,size):
        result=bytearray(); deadline=time.monotonic()+3
        while len(result)<size:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError('AMSI request timeout')
            part=self.operation(handle,'read',length=min(65536,size-len(result)),timeout=remaining)
            if not part: raise ValueError('Truncated AMSI request')
            result.extend(part)
        return bytes(result)


class AmsiBroker:
    def __init__(self,resources,pipe_name=PIPE_NAME):
        if os.name!='nt': raise RuntimeError('AMSI broker requires Windows')
        if pipe_name==PIPE_NAME:
            from sentinelav.platform.windows_identity import current_sid
            from sentinelav.paths import RESOURCE_ROOT
            if not getattr(sys,'frozen',False) or current_sid()!='S-1-5-19' or Path(resources).resolve()!=RESOURCE_ROOT.resolve():
                raise RuntimeError('Production AMSI broker requires the protected LocalService deployment')
        elif not re.fullmatch(r'\\\\\.\\pipe\\SentinelAV\.Test\.Amsi\.[0-9a-f]{32}',pipe_name):
            raise ValueError('Only a random test endpoint may run outside LocalService')
        self.stop=threading.Event(); self.ready=threading.Event(); self.error=None
        self.resources,self.pipe_name=Path(resources),pipe_name
        self.completed=0; self.omissions=0
        self.thread=threading.Thread(target=self.run,name='amsi-buffer-broker',daemon=True)

    def start(self):
        self.thread.start()
        if not self.ready.wait(35): self.close(); raise TimeoutError('AMSI broker startup timed out')
        if self.error: raise RuntimeError(self.error)
        return self

    def run(self):
        scanner=None; handle=None
        try:
            api=PipeAPI(self.stop)
            scanner=IsolatedScanner(self.resources/'signatures.json',self.resources/'rules',
                                    options=dict(archives=False,amsi=False),persistent=True)
            handle=api.create(self.pipe_name)
            self.ready.set()
            while not self.stop.is_set():
                try:
                    api.operation(handle,'connect',timeout=None)
                    magic,version,size=HEADER.unpack(api.read_exact(handle,HEADER.size))
                    if magic!=MAGIC or version!=1 or size>MAX_BUFFER: raise ValueError('Invalid AMSI frame')
                    content=api.read_exact(handle,size)
                    try: result=scanner.scan_buffer(content,self.stop.is_set)
                    except (RuntimeError,TimeoutError,OSError):
                        result={}
                        scanner.close()
                        scanner=None
                    status=response_status(result)
                    reply=HEADER.pack(MAGIC,1,status)
                    if api.operation(handle,'write',data=reply)!=len(reply): raise ValueError('Truncated AMSI response')
                    self.completed+=1; self.omissions+=status==2
                    # Content and evidence are intentionally not persisted or sent to the GUI.
                    del content,result
                    if scanner is None and not self.stop.is_set():
                        scanner=IsolatedScanner(self.resources/'signatures.json',self.resources/'rules',
                                                options=dict(archives=False,amsi=False),persistent=True)
                except (OSError,ValueError,TimeoutError): self.omissions+=1
                finally: api.kernel.DisconnectNamedPipe(handle)
        except InterruptedError: pass
        except Exception as error: self.error=str(error)
        finally:
            self.ready.set()
            if handle is not None: api.kernel.CloseHandle(handle)
            if scanner: scanner.close()

    def close(self):
        self.stop.set()
        if self.thread.ident is not None: self.thread.join(15)
        if self.thread.is_alive(): raise RuntimeError('AMSI broker has not stopped')

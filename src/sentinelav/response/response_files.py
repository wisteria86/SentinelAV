# Purpose: Share locked-file, identity, encryption, and critical-resource safeguards.
# Works with: paths
# Used by: response.response

"""Windows response operations: user-scoped encrypted storage and verified identities."""
from sentinelav.paths import PROJECT_ROOT
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_path(path):
    original = Path(path).absolute()
    for part in [original,*original.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError('Linked paths are not permitted for response actions')
    resolved = original.resolve()
    protected = [Path(os.environ[k]).resolve() for k in ['WINDIR','ProgramFiles','ProgramFiles(x86)'] if os.environ.get(k)]
    protected += [PROJECT_ROOT.resolve(),Path(sys.executable).parent.resolve()]
    if any(resolved==p or p in resolved.parents for p in protected):
        raise ValueError('Response actions on Windows, installed application, or SentinelAV files are blocked')
    if ':' in str(resolved)[2:]:
        raise ValueError('Alternate data streams are not supported')
    return resolved


class Blob(ctypes.Structure):
    _fields_ = [('size',wintypes.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]


def dpapi(data, decrypt=False, machine=False):
    if os.name != 'nt':
        raise RuntimeError('Protected quarantine requires Windows DPAPI')
    crypt = ctypes.WinDLL('crypt32',use_last_error=True)
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    if decrypt:
        function = crypt.CryptUnprotectData
        function.argtypes = [ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
        args = (ctypes.byref(source),None,None,None,None,1,ctypes.byref(output))
    else:
        function = crypt.CryptProtectData
        function.argtypes = [ctypes.POINTER(Blob),wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
        args = (ctypes.byref(source),'SentinelAV protected data',None,None,None,1|(4 if machine else 0),ctypes.byref(output))
    function.restype = wintypes.BOOL
    if not function(*args):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output.data,output.size)
    finally:
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(output.data)


def locked_file(path,create=False):
    """Hold a Windows exclusive handle that can delete only this exact file object."""
    import msvcrt
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    access=0x80000000|(0x40000000 if create else 0x10000)
    handle = kernel.CreateFileW(str(path),access,0,None,1 if create else 3,0x00200000,None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle,(os.O_RDWR if create else os.O_RDONLY)|os.O_BINARY)
    except Exception:
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle(handle)
        raise
    return os.fdopen(fd,'w+b' if create else 'rb')


def delete_locked(stream):
    import msvcrt
    class Disposition(ctypes.Structure):
        _fields_ = [('delete',ctypes.c_ubyte)]
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    flag = Disposition(1)
    if not kernel.SetFileInformationByHandle(msvcrt.get_osfhandle(stream.fileno()),4,ctypes.byref(flag),ctypes.sizeof(flag)):
        raise ctypes.WinError(ctypes.get_last_error())


def is_critical_process(pid):
    kernel = ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    handle = kernel.OpenProcess(0x1000,False,pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        critical = wintypes.BOOL()
        kernel.IsProcessCritical.argtypes = [wintypes.HANDLE,ctypes.POINTER(wintypes.BOOL)]
        kernel.IsProcessCritical.restype = wintypes.BOOL
        if not kernel.IsProcessCritical(handle,ctypes.byref(critical)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(critical.value)
    finally:
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle(handle)

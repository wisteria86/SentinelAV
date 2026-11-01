"""AMSI consumer only. Does not register SentinelAV as an AMSI provider."""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path


def scan_buffer(data,name='SentinelAV script inspection'):
    if os.name!='nt': raise RuntimeError('AMSI requires Windows')
    if len(data)>4*1024*1024: raise ValueError('AMSI input exceeds 4 MiB cap')
    library=ctypes.WinDLL(str(Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/amsi.dll'),use_last_error=True)
    context=ctypes.c_void_p()
    library.AmsiInitialize.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(ctypes.c_void_p)]
    library.AmsiInitialize.restype=ctypes.c_long
    library.AmsiUninitialize.argtypes=[ctypes.c_void_p]
    library.AmsiScanBuffer.argtypes=[ctypes.c_void_p,ctypes.c_void_p,wintypes.ULONG,wintypes.LPCWSTR,ctypes.c_void_p,ctypes.POINTER(wintypes.ULONG)]
    library.AmsiScanBuffer.restype=ctypes.c_long
    if library.AmsiInitialize('SentinelAV',ctypes.byref(context))<0:
        raise RuntimeError('Installed AMSI provider initialization failed')
    try:
        buffer=ctypes.create_string_buffer(data)
        result=wintypes.ULONG()
        status=library.AmsiScanBuffer(context,buffer,len(data),name,None,ctypes.byref(result))
        if status<0: raise RuntimeError('Installed AMSI provider inspection failed')
        return dict(result=result.value,detected=result.value>=32768,
                    blocked_by_policy=16384<=result.value<=20479,
                    provider='Installed Windows AMSI provider; not a SentinelAV provider')
    finally: library.AmsiUninitialize(context)

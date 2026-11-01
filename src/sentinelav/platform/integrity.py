"""Read-only installed-file integrity checks; ACLs remain the trust boundary."""
import hashlib
import json
from pathlib import Path
import os


def verify_windows_acl(path,service_writable=False):
    """Reject user-owned/writable service code or policy, including permissive ACLs."""
    if os.name!='nt': raise RuntimeError('Protected deployment ACL checks require Windows')
    import ctypes
    from ctypes import wintypes
    advapi=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    advapi.GetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,ctypes.c_int,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.argtypes=[ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(wintypes.LPWSTR)]
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    owner=ctypes.c_void_p(); dacl=ctypes.c_void_p(); descriptor=ctypes.c_void_p()
    code=advapi.GetNamedSecurityInfoW(str(path),1,1|4,ctypes.byref(owner),None,ctypes.byref(dacl),None,ctypes.byref(descriptor))
    if code: raise OSError(code,'Cannot verify protected path ACL')
    def sid_text(sid):
        text=wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid,ctypes.byref(text)): raise RuntimeError('Cannot decode ACL SID')
        try: return text.value
        finally: kernel.LocalFree(text)
    try:
        writers={'S-1-5-18','S-1-5-32-544'}
        if service_writable: writers.add('S-1-5-19')
        if sid_text(owner) not in writers: raise ValueError('Service path is not owned by a trusted administrative/service SID')
        if not dacl.value: raise ValueError('Null service DACL rejected')
        count=ctypes.c_ushort.from_address(dacl.value+4).value
        if count>1024: raise ValueError('Service ACL exceeds limit')
        write_mask=0x10000000|0x40000000|0x00010000|0x00040000|0x00080000|0x2|0x4|0x10|0x40|0x100
        for index in range(count):
            ace=ctypes.c_void_p()
            if not advapi.GetAce(dacl,index,ctypes.byref(ace)): raise RuntimeError('Cannot inspect service ACL')
            kind=ctypes.c_ubyte.from_address(ace.value).value
            if kind==1: continue  # A deny ACE never grants write access.
            if kind!=0: raise ValueError('Unsupported service access-control entry; manual review required')
            mask=ctypes.c_uint32.from_address(ace.value+4).value
            if mask&write_mask and sid_text(ace.value+8) not in writers:
                raise ValueError('Service path grants write access to an untrusted SID')
        return True
    finally: kernel.LocalFree(descriptor)


def file_hash(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while chunk:=stream.read(1024*1024): digest.update(chunk)
    return digest.hexdigest()


def verify_installation(root,protected=False):
    root=Path(root).resolve()
    manifest=root/'code-integrity.json'
    if protected:
        verify_windows_acl(root)
        verify_windows_acl(manifest)
    if manifest.is_symlink() or manifest.stat().st_size>2*1024*1024: raise ValueError('Invalid installation manifest')
    entries=json.loads(manifest.read_text(encoding='utf-8-sig'))
    if not isinstance(entries,dict) or not 1<=len(entries)<=10000: raise ValueError('Invalid installation manifest entries')
    for name,expected in entries.items():
        if not isinstance(name,str) or Path(name).is_absolute() or '..' in Path(name).parts or ':' in name:
            raise ValueError('Invalid integrity path')
        path=root/name
        for part in [path,*path.parents]:
            if part.is_symlink() or part.is_junction(): raise ValueError('Linked installation file rejected')
        if not path.resolve().is_relative_to(root) or file_hash(path)!=expected:
            raise ValueError('Installation integrity mismatch: '+name)
        if protected: verify_windows_acl(path)
    return dict(status='Verified',files=len(entries),publisher_authenticated=False)

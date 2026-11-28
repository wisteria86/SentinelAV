# Purpose: Read-only Authenticode and catalog signature checks; nothing is loaded or run.
# Works with: detection.file_analysis
# Used by: detection.file_analysis, tools.evaluation.evaluate_benign

"""Read-only Authenticode and catalog signature checks; nothing is loaded or run.

A valid signature lowers heuristic weight but never overrides a signature match:
certificates get stolen, so this is evidence rather than an allowlist.
"""

import ctypes
from ctypes import wintypes
import os
import uuid

ACTION_VERIFY = uuid.UUID('{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}')
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_CACHE_ONLY = 0x1000


class GUID(ctypes.Structure):
    """Windows GUID structure for ctypes."""

    _fields_ = [('data', ctypes.c_ubyte * 16)]

    @classmethod
    def of(cls, value):
        """Build a GUID structure from a Python UUID."""
        result = cls()
        ctypes.memmove(result.data, value.bytes_le, 16)
        return result


class FileInfo(ctypes.Structure):
    """WINTRUST_FILE_INFO: describes a file whose embedded signature should be checked."""

    _fields_ = [
        ('size', wintypes.DWORD),
        ('path', wintypes.LPCWSTR),
        ('handle', wintypes.HANDLE),
        ('subject', ctypes.c_void_p),
    ]


class CatalogInfo(ctypes.Structure):
    """WINTRUST_CATALOG_INFO: describes a file whose signature lives in a Windows catalog file."""

    _fields_ = [
        ('size', wintypes.DWORD),
        ('version', wintypes.DWORD),
        ('catalog', wintypes.LPCWSTR),
        ('tag', wintypes.LPCWSTR),
        ('member', wintypes.LPCWSTR),
        ('handle', wintypes.HANDLE),
        ('hash', ctypes.c_void_p),
        ('hash_size', wintypes.DWORD),
        ('context', ctypes.c_void_p),
        ('admin', ctypes.c_void_p),
    ]


class TrustData(ctypes.Structure):
    """WINTRUST_DATA: the request passed to WinVerifyTrust."""

    _fields_ = [
        ('size', wintypes.DWORD),
        ('policy', ctypes.c_void_p),
        ('sip', ctypes.c_void_p),
        ('ui', wintypes.DWORD),
        ('revoke', wintypes.DWORD),
        ('choice', wintypes.DWORD),
        ('info', ctypes.c_void_p),
        ('state_action', wintypes.DWORD),
        ('state', wintypes.HANDLE),
        ('reference', wintypes.LPCWSTR),
        ('provider', wintypes.DWORD),
        ('ui_context', wintypes.DWORD),
        ('signature', ctypes.c_void_p),
    ]


class CatalogName(ctypes.Structure):
    """CATALOG_INFO: receives the path of the catalog file that covers a file."""

    _fields_ = [('size', wintypes.DWORD), ('name', wintypes.WCHAR * 260)]


def _verify(choice, info):
    """Ask Windows (WinVerifyTrust) to validate a signature, with no UI and no network revocation
    check. Returns True if it is valid.
    """
    wintrust = ctypes.WinDLL('wintrust', use_last_error=True)
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    action = GUID.of(ACTION_VERIFY)
    data = TrustData(
        size=ctypes.sizeof(TrustData),
        ui=WTD_UI_NONE,
        revoke=WTD_REVOKE_NONE,
        choice=choice,
        info=ctypes.addressof(info),
        state_action=WTD_STATEACTION_VERIFY,
        provider=WTD_CACHE_ONLY,
    )
    status = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    data.state_action = WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    return status == 0


def _catalog(path):
    """Check whether the file is signed through a Windows catalog (as most built-in system files are)
    rather than an embedded signature.
    """
    wintrust = ctypes.WinDLL('wintrust', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    wintrust.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wintrust.CryptCATCatalogInfoFromContext.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(CatalogName),
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    wintrust.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        return False
    admin = ctypes.c_void_p()
    try:
        if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(admin), None, 0):
            return False
        try:
            size = wintypes.DWORD(0)
            wintrust.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size), None, 0)
            if not size.value or size.value > 256:
                return False
            digest = (ctypes.c_ubyte * size.value)()
            if not wintrust.CryptCATAdminCalcHashFromFileHandle(
                handle, ctypes.byref(size), digest, 0
            ):
                return False
            context = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, size, 0, None)
            if not context:
                return False
            try:
                name = CatalogName(size=ctypes.sizeof(CatalogName))
                if not wintrust.CryptCATCatalogInfoFromContext(context, ctypes.byref(name), 0):
                    return False
                tag = ''.join(f'{value:02X}' for value in digest)
                info = CatalogInfo(
                    size=ctypes.sizeof(CatalogInfo),
                    catalog=name.name,
                    tag=tag,
                    member=str(path),
                    hash=ctypes.addressof(digest),
                    hash_size=size.value,
                )
                return _verify(WTD_CHOICE_CATALOG, info)
            finally:
                wintrust.CryptCATAdminReleaseCatalogContext(admin, context, 0)
        finally:
            wintrust.CryptCATAdminReleaseContext(admin, 0)
    finally:
        kernel.CloseHandle(handle)


def signature_status(path):
    """Return 'trusted' or 'untrusted'; any API failure is 'unknown' rather than trust."""
    if os.name != 'nt':
        return 'unknown'
    try:
        if _verify(WTD_CHOICE_FILE, FileInfo(size=ctypes.sizeof(FileInfo), path=str(path))):
            return 'trusted'
        return 'trusted' if _catalog(path) else 'untrusted'
    except (OSError, ValueError, AttributeError):
        return 'unknown'

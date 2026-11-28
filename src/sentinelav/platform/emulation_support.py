# Purpose: Read-only compatibility check; never changes Windows mitigation policies.
# Works with: sibling modules in platform
# Used by: detection.emulation, detection.speakeasy_backend, detection.windows_emulation, lab.advanced_check

"""Read-only compatibility check; never changes Windows mitigation policies."""

import ctypes
from ctypes import wintypes
import os
import re
import hashlib
import json
from pathlib import Path
import sys


def validated_native_build():
    """Accept only the bundled native library described by its build receipt.

    Check the library actually loaded by ctypes, so LIBUNICORN_PATH cannot
    accidentally qualify a different DLL using the bundled receipt.
    """
    if not getattr(sys, 'frozen', False):
        return False
    try:
        from unicorn.unicorn_py3.unicorn import uclib

        root = Path(sys._MEIPASS).resolve()
        expected = root / 'unicorn/lib/unicorn.dll'
        loaded = Path(uclib._name).resolve()
        if loaded != expected.resolve():
            return False
        receipt = root / 'emulator-build.json'
        if receipt.stat().st_size > 4096:
            return False
        manifest = json.loads(receipt.read_text(encoding='utf-8'))
        return (
            manifest.get('schema') == 1
            and manifest.get('backend') == 'unicorn-windows-unwind-v1'
            and manifest.get('version') == '2.1.4'
            and manifest.get('upstream_revision') == '8028ec436f2d9376525352dd38ed9ed6b9f6be10'
            and manifest.get('dll_sha256') == hashlib.sha256(loaded.read_bytes()).hexdigest()
        )
    except (ImportError, OSError, ValueError, AttributeError, TypeError):
        return False


def control_flow_guard_enabled():
    """Tell whether Windows Control Flow Guard is enabled for this process (some emulator builds crash
    under it).
    """
    if os.name != 'nt':
        return False
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessMitigationPolicy.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    kernel.GetProcessMitigationPolicy.restype = wintypes.BOOL
    flags = wintypes.DWORD()
    if not kernel.GetProcessMitigationPolicy(
        kernel.GetCurrentProcess(), 7, ctypes.byref(flags), ctypes.sizeof(flags)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(flags.value & 1)


def compatibility(version):
    """Decide whether the Unicorn emulator can run safely in this process.

    If Control Flow Guard is on, only the validated, bundled build is allowed. Returns {'available':
    bool, 'reason': ..., 'cfg_enabled': bool}.
    """
    numbers = re.match(r'^(\d+)\.(\d+)\.(\d+)', version)
    if numbers is None:
        return dict(available=False, reason='Unrecognized emulator version')
    try:
        cfg = control_flow_guard_enabled()
    except OSError as error:
        return dict(
            available=False, reason='Cannot verify process mitigation compatibility: ' + str(error)
        )
    if cfg and not (version == '2.1.4' and validated_native_build()):
        return dict(
            available=False,
            reason='This Unicorn build has not been validated for this CFG-enabled process. Windows mitigations remain enabled; use the validated source runtime or the bundled Windows-unwind build.',
            cfg_enabled=True,
        )
    return dict(available=True, cfg_enabled=cfg)

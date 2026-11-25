# Purpose: Catch clipboard hijackers ("clippers") that swap a copied crypto address for the attacker's own.
# Works with: monitoring.deception.common
# Used by: monitoring.deception

"""Catch clipboard hijackers ("clippers") that swap a copied crypto address for the attacker's own.

The guard watches the clipboard's change counter. When a wallet address is
replaced by a different address of the same kind within a few seconds, with no
keyboard or mouse input in between, something other than the user made the
swap, and the window that owns the clipboard names the process.

Optional bait: while the user is away and the clipboard is empty, the guard puts
a decoy address there, which clippers take for a real one. It never replaces
anything the user copied.
"""
import os
import re
import secrets
import time

from sentinelav.monitoring.deception.common import describe, event, flag

# Address shapes clippers look for (Bitcoin legacy and SegWit, Ethereum and compatible chains, Litecoin, Tron, Monero).
WALLET = {
    'bitcoin': re.compile(r'^(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$'),
    'ethereum': re.compile(r'^0x[0-9a-fA-F]{40}$'),
    'litecoin': re.compile(r'^(?:ltc1[ac-hj-np-z02-9]{25,62}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33})$'),
    'tron': re.compile(r'^T[a-km-zA-HJ-NP-Z1-9]{33}$'),
    'monero': re.compile(r'^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$'),
}
BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def wallet_kind(text):
    text = (text or '').strip()
    return next((kind for kind, pattern in WALLET.items() if pattern.match(text)), None)


def decoy_address():
    return '1' + ''.join(secrets.choice(BASE58) for _ in range(33))


class WindowsClipboard:
    """Text, change counter, owner process and last-input time through the Windows API."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.user32, self.kernel32 = ctypes, ctypes.windll.user32, ctypes.windll.kernel32
        self.user32.GetClipboardData.restype = wintypes.HANDLE
        self.kernel32.GlobalLock.restype = ctypes.c_void_p
        self.kernel32.GlobalLock.argtypes = [wintypes.HANDLE]
        self.kernel32.GlobalUnlock.argtypes = [wintypes.HANDLE]
        self.user32.GetClipboardOwner.restype = wintypes.HWND

    def sequence(self):
        return self.user32.GetClipboardSequenceNumber()

    def text(self):
        if not self.user32.OpenClipboard(None):
            return None
        try:
            handle = self.user32.GetClipboardData(13)  # CF_UNICODETEXT
            if not handle:
                return ''
            pointer = self.kernel32.GlobalLock(handle)
            try:
                return self.ctypes.wstring_at(pointer)[:512] if pointer else ''
            finally:
                self.kernel32.GlobalUnlock(handle)
        finally:
            self.user32.CloseClipboard()

    def set_text(self, value):
        import win32clipboard
        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(value, win32clipboard.CF_UNICODETEXT)
        finally:
            win32clipboard.CloseClipboard()

    def owner(self):
        from ctypes import wintypes
        window = self.user32.GetClipboardOwner()
        if not window:
            return None
        pid = wintypes.DWORD()
        self.user32.GetWindowThreadProcessId(window, self.ctypes.byref(pid))
        try:
            import psutil
            process = psutil.Process(pid.value)
            return dict(pid=pid.value, name=process.name(), exe=process.exe(), create_time=process.create_time())
        except Exception:
            return dict(pid=pid.value, name='unknown', exe='', create_time=0) if pid.value else None

    def last_input(self):
        from ctypes import wintypes

        class Info(self.ctypes.Structure):
            _fields_ = [('cbSize', wintypes.UINT), ('dwTime', wintypes.DWORD)]
        info = Info(self.ctypes.sizeof(Info), 0)
        self.user32.GetLastInputInfo(self.ctypes.byref(info))
        return info.dwTime

    def idle_seconds(self):
        return (self.kernel32.GetTickCount() - self.last_input()) / 1000


class ClipboardGuard:
    def __init__(self, emit, behavior=None, clipboard=None, bait=False, window=4.0, idle_for=600, clock=time.monotonic):
        self.emit, self.behavior, self.bait, self.window, self.idle_for, self.clock = emit, behavior, bait, window, idle_for, clock
        self.clipboard = clipboard or (WindowsClipboard() if os.name == 'nt' else None)
        self.seen, self.last = None, None  # last: (address, kind, time, last input tick, was bait)
        self.baited = None
        import threading
        self.lock = threading.Lock()

    def poll(self):
        # The change listener and the monitor's poll both call this; one check at a time.
        with self.lock:
            return self._check()

    def _check(self):
        if not self.clipboard:
            return None
        number = self.clipboard.sequence()
        if number == self.seen:
            self._maybe_bait()
            return None
        self.seen = number
        text = (self.clipboard.text() or '').strip()
        kind = wallet_kind(text)
        found = None
        if kind and self.last and self.last[1] == kind and text != self.last[0]:
            swapped_bait = self.last[4]
            quick = self.clock() - self.last[2] <= self.window
            untouched = self.clipboard.last_input() == self.last[3]
            if swapped_bait or (quick and untouched):
                process = self.clipboard.owner()
                what = 'the decoy address SentinelAV left there' if swapped_bait else 'the address you copied'
                found = event('Clipboard hijack detected', f'A {kind} address on the clipboard was replaced, without any input, '
                    f'by another address ({text[:12]}…). It replaced {what}. Clipboard owner: {describe(process)}. '
                    'Do not paste it into a payment.', wallet=kind, replacement=text, process=process)
                self.emit(found)
                flag(self.behavior, process, 'Replaced a crypto address on the clipboard', 80)
        self.last = (text, kind, self.clock(), self.clipboard.last_input(), text == self.baited) if kind else None
        return found

    def start(self):
        """Hear every clipboard change as it happens; a 2-second poll alone can miss a swap made within milliseconds."""
        if os.name != 'nt' or not isinstance(self.clipboard, WindowsClipboard):
            return self
        import threading
        self.listener = threading.Thread(target=self._listen, daemon=True, name='clipboard-guard')
        self.listener.start()
        return self

    def _listen(self):
        import win32api
        import win32con
        import win32gui
        WM_CLIPBOARDUPDATE = 0x031D

        def handle(window, message, wparam, lparam):
            if message == WM_CLIPBOARDUPDATE:
                try:
                    self.poll()
                except Exception:
                    pass
                return 0
            return win32gui.DefWindowProc(window, message, wparam, lparam)
        klass = win32gui.WNDCLASS()
        klass.lpfnWndProc, klass.lpszClassName, klass.hInstance = handle, f'SentinelAVClipboardGuard{id(self)}', win32api.GetModuleHandle(None)
        try:
            win32gui.RegisterClass(klass)
        except win32gui.error:
            pass  # Registered by an earlier start in this process; the window can still be created.
        self.window = win32gui.CreateWindow(klass.lpszClassName, 'SentinelAV clipboard guard', 0, 0, 0, 0, 0, win32con.HWND_MESSAGE, 0, klass.hInstance, None)
        import ctypes
        ctypes.windll.user32.AddClipboardFormatListener(self.window)
        win32gui.PumpMessages()

    def stop(self):
        if getattr(self, 'window', None):
            import win32con
            import win32gui
            win32gui.PostMessage(self.window, win32con.WM_QUIT, 0, 0)

    def _maybe_bait(self):
        # Only when the user is away and the clipboard is empty, so nothing they copied is ever replaced.
        if not self.bait or self.baited or self.clipboard.idle_seconds() < self.idle_for or self.clipboard.text():
            return
        self.baited = decoy_address()
        self.clipboard.set_text(self.baited)
        self.seen = self.clipboard.sequence()
        self.last = (self.baited, 'bitcoin', self.clock(), self.clipboard.last_input(), True)

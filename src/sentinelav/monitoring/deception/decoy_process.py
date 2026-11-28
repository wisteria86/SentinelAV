# Purpose: The body of a decoy process: sit idle under a tempting name and report code injected into it.
# Works with: monitoring.deception.processes
# Used by: entrypoint (--decoy-role), monitoring.deception.processes

"""The body of a decoy process: sit idle under a tempting name and report code injected into it.

A bait process has nothing worth injecting into except its name, so a new
executable memory region or a thread that starts outside every loaded module is
code that another program put there. Findings are appended to a status file the
monitor reads; this process never acts on them itself. It exits when its parent
monitor goes away.
"""
import ctypes
import json
import os
import sys
import time
from ctypes import wintypes

MEM_COMMIT, MEM_PRIVATE = 0x1000, 0x20000
EXECUTE = 0x10 | 0x20 | 0x40 | 0x80


class Region(ctypes.Structure):
    """MEMORY_BASIC_INFORMATION structure filled in by VirtualQuery."""
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p), ('AllocationProtect', wintypes.DWORD),
                ('PartitionId', wintypes.WORD), ('RegionSize', ctypes.c_size_t), ('State', wintypes.DWORD),
                ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD)]


def executable_private_regions():
    """Base addresses of committed private memory that can run code (normal programs keep code in mapped images)."""
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(Region), ctypes.c_size_t]
    found, address, region = set(), 0, Region()
    while kernel32.VirtualQuery(ctypes.c_void_p(address), ctypes.byref(region), ctypes.sizeof(region)):
        if region.State == MEM_COMMIT and region.Type == MEM_PRIVATE and region.Protect & EXECUTE:
            found.add(region.BaseAddress or 0)
        address = (region.BaseAddress or 0) + region.RegionSize
        if address >= 1 << 47:
            break
    return found


def thread_ids():
    """Return the ids of every thread in this process."""
    import psutil
    return {thread.id for thread in psutil.Process().threads()}


def module_ranges():
    """Return the (start, end) address range of every module (EXE or DLL) loaded in this process."""
    psapi, kernel32 = ctypes.windll.psapi, ctypes.windll.kernel32
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    process = kernel32.GetCurrentProcess()
    handles, needed = (ctypes.c_void_p * 1024)(), wintypes.DWORD()
    psapi.EnumProcessModules(process, handles, ctypes.sizeof(handles), ctypes.byref(needed))

    class Info(ctypes.Structure):
        """MODULEINFO structure filled in by GetModuleInformation."""
        _fields_ = [('base', ctypes.c_void_p), ('size', wintypes.DWORD), ('entry', ctypes.c_void_p)]
    ranges = []
    for handle in handles[:needed.value // ctypes.sizeof(ctypes.c_void_p)]:
        info = Info()
        if psapi.GetModuleInformation(process, ctypes.c_void_p(handle), ctypes.byref(info), ctypes.sizeof(info)):
            ranges.append((info.base or 0, (info.base or 0) + info.size))
    return ranges


def thread_start(thread_id):
    """Start address of a thread, or None when Windows will not say."""
    kernel32, ntdll = ctypes.windll.kernel32, ctypes.windll.ntdll
    kernel32.OpenThread.restype = wintypes.HANDLE
    handle = kernel32.OpenThread(0x0040, False, thread_id)  # THREAD_QUERY_INFORMATION
    if not handle:
        return None
    try:
        address = ctypes.c_void_p()
        status = ntdll.NtQueryInformationThread(wintypes.HANDLE(handle), 9, ctypes.byref(address), ctypes.sizeof(address), None)
        return address.value if status == 0 else None
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def foreign_threads(thread_list):
    """Threads whose start address lies outside every loaded module: Windows' own worker threads start inside one."""
    ranges = module_ranges()
    result = []
    for thread_id in thread_list:
        start = thread_start(thread_id)
        if start and not any(low <= start < high for low, high in ranges):
            result.append(dict(thread=thread_id, start=hex(start)))
    return result


def run(role, status_path, parent_pid, interval=2.0):
    """Watch this decoy process for injected code until the parent monitor exits.

    Every `interval` seconds, any new executable private memory and any new thread starting outside
    a loaded module is written as a JSON line to the status file.
    """
    import psutil
    baseline_regions, baseline_threads = executable_private_regions(), thread_ids()
    reported = set()
    while psutil.pid_exists(parent_pid):
        time.sleep(interval)
        findings = []
        for base in executable_private_regions() - baseline_regions - reported:
            findings.append(dict(kind='executable_memory', address=hex(base)))
            reported.add(base)
        new_threads = thread_ids() - baseline_threads
        findings += [dict(kind='foreign_thread', **item) for item in foreign_threads(new_threads)]
        baseline_threads |= new_threads
        if findings:
            with open(status_path, 'a', encoding='utf-8') as stream:
                for item in findings:
                    stream.write(json.dumps(dict(item, role=role, pid=os.getpid(), time=time.time())) + '\n')


def main(argv=None):
    """Entry point when started as a decoy (`--decoy-role`): fake analysis tools just idle; bait
    processes watch for injected code.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    role, status, parent = argv[argv.index('--decoy-role') + 1], argv[argv.index('--decoy-status') + 1], int(argv[argv.index('--decoy-parent') + 1])
    if role == 'analysis':
        # A fake analysis tool only needs to exist under its name.
        import psutil
        while psutil.pid_exists(parent):
            time.sleep(5)
        return 0
    run(role, status, parent)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

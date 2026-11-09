# Purpose: Bounded, read-only same-account memory inspection. Never dumps raw bytes.
# Works with: detection.yara_rules, paths
# Used by: detection.inspection_worker, tests.unit.test_defense_layers

"""Bounded, read-only same-account memory inspection. Never dumps raw bytes."""
from sentinelav.paths import RESOURCE_ROOT
import ctypes
from ctypes import wintypes
import os
import time
import psutil


def inspect_memory(pid,creation,analyze,max_bytes=32*1024*1024,max_regions=128,seconds=5):
    if os.name!='nt': raise RuntimeError('Memory inspection requires Windows')
    if type(pid) is not int or pid<=4 or not isinstance(creation,(int,float)):
        raise ValueError('Invalid process identity')
    process=psutil.Process(pid)
    if process.create_time()!=creation: raise ValueError('PID was reused')
    if process.username().casefold()!=psutil.Process().username().casefold():
        raise ValueError('Only processes owned by the current Windows account may be inspected')
    from pathlib import Path
    from sentinelav.detection.yara_rules import compile_rules,evidence
    memory_rules,memory_summary,memory_metadata=compile_rules(RESOURCE_ROOT/'rules/memory')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.VirtualQueryEx.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t]
    kernel.VirtualQueryEx.restype=ctypes.c_size_t
    kernel.ReadProcessMemory.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    class Region(ctypes.Structure):
        _fields_=[('base',ctypes.c_ulonglong),('allocation_base',ctypes.c_ulonglong),('allocation_protect',wintypes.DWORD),
                  ('alignment',wintypes.DWORD),('size',ctypes.c_ulonglong),('state',wintypes.DWORD),
                  ('protect',wintypes.DWORD),('kind',wintypes.DWORD),('alignment2',wintypes.DWORD)]
    handle=kernel.OpenProcess(0x0400|0x0010,False,pid)
    if not handle: raise ctypes.WinError(ctypes.get_last_error())
    total=regions=queries=private_executable=0
    matches=[]
    omissions=[]
    started=time.monotonic()
    address=0
    try:
        while address<0x7ffffffeFFFF and queries<4096 and regions<max_regions and total<max_bytes:
            if time.monotonic()-started>seconds:
                omissions.append('Memory wall-clock limit reached')
                break
            region=Region()
            if not kernel.VirtualQueryEx(handle,ctypes.c_void_p(address),ctypes.byref(region),ctypes.sizeof(region)): break
            queries+=1
            next_address=region.base+region.size
            if next_address<=address: break
            address=next_address
            executable=bool(region.protect&0xf0)
            if region.state!=0x1000 or region.protect&0x101 or not executable: continue
            if region.kind==0x20000: private_executable+=1
            amount=min(region.size,1024*1024,max_bytes-total)
            buffer=ctypes.create_string_buffer(amount)
            read=ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle,ctypes.c_void_p(region.base),buffer,amount,ctypes.byref(read)):
                omissions.append('Executable region unavailable at '+hex(region.base))
                continue
            regions+=1
            total+=read.value
            names,evidence,errors=analyze(buffer.raw[:read.value])
            omissions.extend(errors)
            if memory_rules:
                try:
                    from sentinelav.detection.yara_rules import evidence as match_evidence
                    for match in memory_rules.match(data=buffer.raw[:read.value],timeout=1):
                        names.append('Memory candidate: '+match.rule)
                        evidence.append(match_evidence(match,memory_metadata))
                except Exception as error: omissions.append('Memory-rule inspection failed: '+str(error))
            if region.size>amount: omissions.append('Region truncated at '+hex(region.base))
            if names: matches.append(dict(address=hex(region.base),bytes=read.value,reasons=names,yara_matches=evidence,classification='Candidate requiring review, not proof of malicious execution'))
        if queries>=4096 or regions>=max_regions or total>=max_bytes: omissions.append('Memory traversal/byte limit reached')
        if psutil.Process(pid).create_time()!=creation: raise ValueError('Process identity changed during inspection')
        return dict(pid=pid,creation=creation,scope='Bounded executable regions of a same-account process',
                    regions=regions,bytes=total,private_executable_regions=private_executable,
                    findings_requiring_review=matches,omissions=omissions,raw_memory_saved=False,
                    memory_candidate_rules=memory_summary['research_rules'],
                    classification='Review only; executable private memory can be legitimate JIT code',
                    limitations='File-oriented YARA rules can miss memory-only patterns; regions outside these limits were not inspected')
    finally: kernel.CloseHandle(handle)

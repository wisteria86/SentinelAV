# Purpose: Validate offline guest identity and share case policy or fixed Windows calls.
# Works with: lab.corpus_evaluation
# Used by: lab.qualification.corpus_inputs, lab.qualification.guest, lab.qualification.guest_inventory,
#   lab.qualification.guest_lifecycle

"""Typed guest-only case executor. Never accepts arbitrary commands or binaries."""
import json
from pathlib import Path
import subprocess

BASE=Path('C:/SentinelAV-Test')
BASE=Path("C:/SentinelAV-Test")


def ps(code,timeout=20):
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],capture_output=True,timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
    if p.returncode:raise RuntimeError('Guest Windows operation failed')
    return p.stdout.decode('utf-8-sig',errors='replace').strip()


def guard(context):
    from sentinelav.lab.corpus_evaluation import verified_offline_guest
    if context['backend']=='sandbox':return verified_offline_guest()
    if context['backend']!='hyperv':return False
    expected=context.get('guest_uuid','')
    if len(expected)!=36:return False
    facts=json.loads(ps("[Console]::OutputEncoding=[Text.Encoding]::UTF8;@{model=(Get-CimInstance Win32_ComputerSystem).Model;uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;up=@(Get-NetAdapter|Where-Object Status -eq 'Up').Count}|ConvertTo-Json"))
    return facts['model']=='Virtual Machine' and facts['uuid'].lower()==expected.lower() and facts['up']==0


def options(mode):
    return dict(signature_free=mode=='signature_free',advanced=True,model=True,neural=True,emulation=True,emulation_profile='lab',amsi=False,reputation=False)

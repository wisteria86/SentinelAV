# Purpose: Validate owned cleanup resources and independently inspect their state.
# Works with: monitoring.app_changes, response.remediation
# Used by: lab.qualification.guest_inventory

"""Approved encrypted corpus and narrowly scoped remediation fixtures in guests."""
import hashlib
from pathlib import Path
import re


def resources(inv,root):
    """Turn an inventory's expected artifacts into concrete resources, allowing only owned lab files,
    Run values, tasks and services.
    """
    result=[]
    for artifact in inv.get('expected_artifacts',[]):
        if artifact.get('kind')=='file':
            relative=artifact.get('relative','')
            if not relative or Path(relative).is_absolute() or any(p in ('..','') for p in Path(relative).parts) or ':' in relative:raise ValueError('Fixture file escapes trial')
            result.append({**artifact,'path':str(root/relative)})
        elif artifact.get('kind')=='registry':
            if artifact.get('key')!=r'Software\Microsoft\Windows\CurrentVersion\Run' or not re.fullmatch('SentinelAV-Lab-[A-Za-z0-9_-]{1,60}',artifact.get('name','')):
                raise ValueError('Only owned HKCU lab autorun fixtures may be seeded')
            result.append(artifact)
        elif artifact.get('kind') in ('task','service'):
            if not re.fullmatch('SentinelAV-Lab-[A-Za-z0-9_-]{1,60}',artifact.get('name','')):raise ValueError('Task/service fixtures must have owned lab names')
            result.append(artifact)
        else:raise ValueError('Unsupported expected artifact; task/service ground truth requires separate approved workflow')
    return result


def inspect_resources(artifacts):
    """Check whether each expected artifact still exists (and what it contains) after a clean-up."""
    import winreg
    observed=[]
    for a in artifacts:
        exists=False;value=None
        if a['kind']=='file':
            p=Path(a['path']);exists=p.exists();value=hashlib.sha256(p.read_bytes()).hexdigest() if exists and p.is_file() else None
        elif a['kind']=='registry':
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,a['key']) as k:value=winreg.QueryValueEx(k,a['name'])[0];exists=True
            except FileNotFoundError:pass
        else:
            from sentinelav.monitoring.app_changes import WindowsInventory
            state=WindowsInventory().read(dict(kind=a['kind'],name='\\'+a['name'] if a['kind']=='task' else a['name']))
            exists=state.get('exists',False);value=state
            if a['kind']=='service' and state.get('start')=='Disabled':exists=False
            if a['kind']=='task' and exists:
                from sentinelav.response.remediation import task_disabled
                if task_disabled(state):exists=False
        observed.append(dict(resource=a,exists=exists,identity=value))
    return observed

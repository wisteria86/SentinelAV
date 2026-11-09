# Purpose: Parse persistence references and define conflict-verification rules.
# Works with: data.contracts
# Used by: response.remediation, response.remediation_backend

"""Stored, expiring, evidence-linked cleanup and conflict-checked manual recovery."""
import ctypes
import os
from pathlib import Path
import xml.etree.ElementTree as ET
from sentinelav.data.contracts import fingerprint

def command_paths(command):
    """Parse only; never invoke a shell or interpret expressions."""
    if not isinstance(command,str) or len(command)>32768:return []
    if os.name=='nt':
        count=ctypes.c_int();shell=ctypes.WinDLL('shell32',use_last_error=True)
        shell.CommandLineToArgvW.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)]
        shell.CommandLineToArgvW.restype=ctypes.POINTER(ctypes.c_wchar_p)
        argv=shell.CommandLineToArgvW(command,ctypes.byref(count))
        if not argv:return []
        try:parts=[argv[i] for i in range(min(count.value,128))]
        finally:
            kernel=ctypes.WinDLL('kernel32');kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree(argv)
    else:
        import shlex
        try:parts=shlex.split(command)
        except ValueError:return []
    result=[]
    for part in parts:
        path=Path(os.path.expandvars(part))
        if path.is_absolute():result.append(str(path.absolute()))
    return result

def referenced_paths(record):
    target=record['resource'];state=record.get('after') or {}
    if not state.get('exists'):return []
    if target['kind'] in ('startup_file','setting_file','file'):return [target['path']]
    if target['kind']=='process':return [state['path']] if state.get('exists') else []
    if target['kind']=='registry':return command_paths(state.get('value',''))
    if target['kind']=='service':return command_paths(state.get('image',''))
    if target['kind']=='task':
        xml=state.get('xml','')
        if len(xml)>131072 or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():raise ValueError('Unsafe task XML')
        root=ET.fromstring(xml);result=[]
        for element in root.iter():
            if element.tag.rsplit('}',1)[-1]=='Exec':
                values={e.tag.rsplit('}',1)[-1]:e.text or '' for e in element}
                result+=command_paths('"'+values.get('Command','')+'" '+values.get('Arguments',''))
        return result
    return []

def task_disabled(state):
    xml=state.get('xml','')
    if len(xml)>131072 or '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():raise ValueError('Unsafe task definition')
    root=ET.fromstring(xml)
    for settings in root:
        if settings.tag.rsplit('}',1)[-1]!='Settings':continue
        return any(e.tag.rsplit('}',1)[-1]=='Enabled' and (e.text or '').strip().casefold()=='false' for e in settings)
    return False

MUTATE_SCRIPT=r'''
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
if($data.resource.kind -eq 'task'){
 $name=[string]$data.resource.name
 if(!$name.StartsWith('\') -or $name.StartsWith('\Microsoft\Windows\',[StringComparison]::OrdinalIgnoreCase)){throw 'Protected task scope'}
 $s=New-Object -ComObject Schedule.Service;$s.Connect();$last=$name.LastIndexOf('\')
 $parent=if($last -eq 0){'\'}else{$name.Substring(0,$last)};$folder=$s.GetFolder($parent)
 $task=$null
 try{$task=$folder.GetTask($name.Substring($last+1))}catch{if($data.action -ne 'restore' -or $data.expected.exists){throw}}
 if($data.expected.exists -and (!$task -or [string]$task.Xml -cne [string]$data.expected.xml -or [string]$task.GetSecurityDescriptor(7) -cne [string]$data.expected.sddl)){throw 'Task changed immediately before mutation'}
 if(!$data.expected.exists -and $task){throw 'Task appeared before restoration'}
 if($data.action -eq 'disable'){$task.Enabled=$false}
 elseif($data.action -eq 'restore'){
  $definition=$s.NewTask(0);$definition.XmlText=[string]$data.state.xml
  if($definition.Principal.LogonType -notin @(3,4,5)){throw 'Task restoration requires credentials that are not stored'}
  $null=$folder.RegisterTaskDefinition($name.Substring($last+1),$definition,6,$definition.Principal.UserId,$null,$definition.Principal.LogonType,[string]$data.state.sddl)
 }else{throw 'Unsupported task action'}
}elseif($data.resource.kind -eq 'service'){
 $name=[string]$data.resource.name
 $items=@(Get-CimInstance Win32_Service | Where-Object Name -CEQ $name)
 if($items.Count -ne 1){throw 'Service identity unavailable'}
 if($data.expected -and ($items[0].PathName -cne $data.expected.image -or $items[0].StartName -cne $data.expected.account -or $items[0].StartMode -cne $data.expected.start)){throw 'Service changed immediately before mutation'}
 $mode=if($data.action -eq 'disable'){'Disabled'}else{[string]$data.state.start}
 if($mode -notin @('Auto','Automatic','Manual','Disabled')){throw 'Unsupported service mode'}
 if($mode -eq 'Auto'){$mode='Automatic'}
 if($data.action -eq 'restore'){
  if($items[0].StartName -cne $data.state.account){throw 'Service account restoration requires separate credentials/authorization'}
  $reply=Invoke-CimMethod -InputObject $items[0] -MethodName Change -Arguments @{StartMode=$mode;PathName=[string]$data.state.image}
 }else{$reply=Invoke-CimMethod -InputObject $items[0] -MethodName ChangeStartMode -Arguments @{StartMode=$mode}}
 if($reply.ReturnValue -ne 0){throw ('Service change rejected: '+$reply.ReturnValue)}
}else{throw 'Unsupported privileged resource'}
@{applied=$true} | ConvertTo-Json -Compress
'''

def effect_matches(target,actual,action,desired):
    if action=='restore':
        if target['kind'] in ('setting_file','startup_file'):
            return not actual.get('exists') if not desired.get('exists') else actual.get('sha256')==desired.get('sha256') and actual.get('exists')
        if target['kind']=='service':return all(actual.get(key)==desired.get(key) for key in ('start','image','account','display_name','service_type'))
        return fingerprint(actual)==fingerprint(desired)
    if target['kind']=='service':return actual.get('exists') and actual.get('start')=='Disabled'
    if target['kind']=='task':
        try:
            return task_disabled(actual)
        except (ValueError,ET.ParseError):return False
    return not actual.get('exists')

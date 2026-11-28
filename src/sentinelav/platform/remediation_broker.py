# Purpose: One-shot UAC broker: protected records, independent verdicts, fixed actions.
# Works with: data.contracts, detection.inspection, monitoring.app_changes, paths, platform.amsi_broker
# Used by: entrypoint, ui.app_changes_ui, tests.unit.test_remediation_broker

"""One-shot UAC broker: protected records, independent verdicts, fixed actions.

The protection service remains LocalService. No shell command, repair payload,
baseline or claimed verdict is accepted from the GUI. Protected machine repair
currently supports reviewed persistence disabling; it never restores persistence
or terminates processes. Per-user restoration stays in the per-user engine.
"""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid
from sentinelav.data.contracts import canonical
from sentinelav.platform.integrity import verify_installation,verify_windows_acl
from sentinelav.response.response import dpapi
from sentinelav.workspace import unlinked

UUID=re.compile(r'^[0-9a-f]{32}$')
MAX_BYTES=4*1024*1024


def identity(value):
    """Check that a value is a 32-character lower-case hex id and return it, raising ValueError
    otherwise.
    """
    if not isinstance(value,str) or not UUID.fullmatch(value):raise ValueError('Invalid broker identity')
    return value


def request_folder():
    """Return the per-user folder where the app leaves broker requests."""
    return unlinked(Path(os.environ['LOCALAPPDATA'])/'SentinelAV/broker-requests')


def protected_root(owner):
    """Return the admin-only folder that holds broker plans and results for one deployment owner (a
    user SID).
    """
    from sentinelav.platform.windows_service import service_paths
    if not re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+',owner):raise ValueError('Invalid deployment owner')
    return unlinked(service_paths()[0]/'response'/owner)


def secure_create(path,directory=False,owner=None):
    """Assign administrative ownership atomically, before any record exists."""
    from sentinelav.platform.amsi_broker import PipeAPI
    api=PipeAPI(__import__('threading').Event());descriptor=ctypes.c_void_p()
    sddl='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if owner:sddl+=f'(A;OICI;FR;;;{owner})'
    if not api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
    security=api.Security(ctypes.sizeof(api.Security),descriptor,False)
    try:
        if directory:
            function=api.kernel.CreateDirectoryW;function.argtypes=[wintypes.LPCWSTR,ctypes.POINTER(api.Security)];function.restype=wintypes.BOOL
            if not function(str(path),ctypes.byref(security)):
                if ctypes.get_last_error()!=183:raise ctypes.WinError(ctypes.get_last_error())
            verify_windows_acl(unlinked(path));return None
        function=api.kernel.CreateFileW
        function.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(api.Security),wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
        function.restype=wintypes.HANDLE
        handle=function(str(path),0x40000000,0,ctypes.byref(security),1,0x00200000,None)
        if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        import msvcrt
        try:return os.fdopen(msvcrt.open_osfhandle(handle,os.O_WRONLY|os.O_BINARY),'wb')
        except BaseException:api.kernel.CloseHandle(handle);raise
    finally:api.kernel.LocalFree(descriptor)


def write_protected(path,value,owner):
    """Encrypt a value and write it to an admin-owned file, replacing it atomically."""
    path=unlinked(path);pending=path.with_name(uuid.uuid4().hex+'.pending')
    raw=canonical(value)
    if len(raw)>MAX_BYTES:raise ValueError('Protected broker record exceeds budget')
    try:
        with secure_create(pending,owner=owner) as stream:
            stream.write(dpapi(raw));stream.flush();os.fsync(stream.fileno())
        if path.exists():verify_windows_acl(path)
        os.replace(pending,path)
    finally:pending.unlink(missing_ok=True)


def read_protected(path):
    """Check an admin-owned file's permissions, then decrypt and return its contents."""
    path=unlinked(path);verify_windows_acl(path)
    with path.open('rb') as stream:raw=stream.read(MAX_BYTES+65537)
    if len(raw)>MAX_BYTES+65536:raise ValueError('Protected broker record too large')
    return json.loads(dpapi(raw,True))


class BrokerJournal:
    """A journal (like ChangeJournal) whose plans live in admin-owned, encrypted files, used by the
    elevated broker.
    """
    def __init__(self,root,owner,rows=()):
        """root is the protected folder, owner the deployment owner's SID, and rows the change records
        read from the service.
        """
        self.root,self.owner,self.rows=root,owner,{r['id']:r for r in rows}
    def change(self,key):
        """Return one change record by id."""
        return self.rows[identity(key)]
    def operation(self,value):
        """Save a remediation plan or receipt."""
        write_protected(self.root/('plan-'+identity(value['id'])+'.bin'),value,self.owner)
    def get_operation(self,key):
        """Load a remediation plan or receipt by id."""
        return read_protected(self.root/('plan-'+identity(key)+'.bin'))
    def operations(self):
        """Return the 64 most recent plans and receipts."""
        paths=sorted(self.root.glob('plan-*.bin'),key=lambda p:p.stat().st_mtime,reverse=True)
        return [read_protected(p) for p in paths[:64]]

    def exclusive(self):
        """Return the lock that lets only one broker run act at a time."""
        from sentinelav.response.transaction import exclusive_file
        return exclusive_file(self.root/'execution.lock',create=lambda path:secure_create(path,owner=self.owner),verify=verify_windows_acl)

    def recovery_operations(self):
        """Yield every plan that was still executing when a broker run stopped."""
        for path in self.root.glob('plan-*.bin'):
            value=read_protected(path)
            if value.get('state')=='Executing':yield value


def validate_request(request):
    """Check a broker request is exactly a 'prepare' (with 1-16 change ids) or an 'execute' (with one
    plan id), and nothing more.
    """
    if not isinstance(request,dict) or request.get('schema')!=1:raise ValueError('Invalid broker request')
    if request.get('operation')=='prepare':
        if set(request)!={'schema','operation','change_ids'}:raise ValueError('Unsupported broker input')
        ids=request['change_ids']
        if not isinstance(ids,list) or not 1<=len(ids)<=16 or len(set(ids))!=len(ids):raise ValueError('Select 1..16 distinct changes')
        for key in ids:identity(key)
    elif request.get('operation')=='execute':
        if set(request)!={'schema','operation','plan_id'}:raise ValueError('Unsupported broker input')
        identity(request['plan_id'])
    else:raise ValueError('Unsupported broker operation')
    return request


def require_deployment():
    """Make sure the broker is running as an administrator from the protected installation, as the
    configured owner. Returns the owner's SID.
    """
    if os.name!='nt' or not getattr(sys,'frozen',False):raise RuntimeError('Broker requires a protected packaged installation')
    if not ctypes.WinDLL('shell32').IsUserAnAdmin():raise PermissionError('UAC administrator authorization required')
    executable=unlinked(Path(sys.executable))
    expected=unlinked(Path(os.environ['ProgramFiles'])/'SentinelAVProtection/SentinelAV.exe')
    if executable!=expected:raise ValueError('Use the protected protection-service installation')
    verify_installation(executable.parent,protected=True)
    from sentinelav.platform.windows_service import service_paths
    from sentinelav.platform.windows_identity import current_sid
    base,_=service_paths();policy=unlinked(base/'policy.json');verify_windows_acl(base);verify_windows_acl(policy)
    from sentinelav.updates.artifacts import bounded_json
    owner=current_sid()
    if bounded_json(policy,32768).get('owner_sid')!=owner:raise PermissionError('UAC account must match the configured deployment owner')
    return owner


def process_request(request,journal,engine,confirm=None):
    """Handle one validated request: 'prepare' builds a plan for machine-wide autostarts; 'execute'
    runs a plan once the administrator confirms it.
    """
    validate_request(request)
    if request['operation']=='prepare':
        for key in request['change_ids']:
            target=journal.change(key)['resource']
            if target['kind'] not in ('registry','task','service') or (target['kind']=='registry' and target.get('hive')!='HKLM'):
                raise ValueError('Protected cleanup supports machine Run entries, tasks and services only')
        plan=engine.plan(request['change_ids'],with_related=False)
        plan.update(authorization='Explicit UAC review; no automatic actions',owner_sid=journal.owner)
        journal.operation(plan);return plan
    plan=journal.get_operation(request['plan_id'])
    if plan.get('owner_sid')!=journal.owner:raise PermissionError('Plan owner mismatch')
    if confirm is None or not confirm(plan):raise PermissionError('Protected confirmation declined or unavailable')
    return engine.execute(request['plan_id'],approved=True)


def confirm_plan(plan):
    """Show the administrator exactly what the plan will do in a Windows message box and return True
    only if they choose Yes.
    """
    if plan.get('state')!='Planned' or time.time()>plan['expires']:raise ValueError('Plan expired; prepare a fresh review')
    lines=[]
    for action in plan['actions']:
        target=action['resource']
        lines.append(action['action'].capitalize()+': '+target['kind']+' '+target.get('name',target.get('path','')))
    text='Apply this exact machine cleanup plan?\n\n'+'\n'.join(lines)+'\n\nOnly listed persistence is disabled. Payloads may remain and will be reported. Conflicting state is skipped.'
    user=ctypes.WinDLL('user32',use_last_error=True)
    user.MessageBoxW.argtypes=[wintypes.HWND,wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.UINT]
    user.MessageBoxW.restype=ctypes.c_int
    return user.MessageBoxW(None,text,'SentinelAV — administrator confirmation',0x4|0x30|0x100|0x10000)==6


def production_detection(finding):
    """Tell whether a detection comes from real signatures (an exact hash or a pinned production YARA
    rule), not from test or demo markers.
    """
    if any(reason.startswith('SHA-256: ') and not re.search(r'\b(test|demo|eicar|harmless)\b',reason,re.I) for reason in finding.get('reasons',[])):return True
    return any(not row.get('demo',True) and isinstance(row.get('source_sha256'),str) and re.fullmatch(r'[0-9a-f]{64}',row['source_sha256'])
        for row in finding.get('yara_matches',[]))


def run(key):
    """Entry point of the elevated broker process (`--remediation-broker <id>`).

    It reads the request the app left behind, verifies the installation, re-scans with only the
    protected bundled signatures, handles the request, and writes the result to an admin-owned file
    for the app to read. Returns 0 on success.
    """
    key=identity(key);owner=require_deployment();root=protected_root(owner)
    secure_create(root.parent,directory=True,owner=owner);secure_create(root,directory=True,owner=owner)
    scanner=None
    try:
        from sentinelav.updates.artifacts import bounded_json
        request=validate_request(bounded_json(unlinked(request_folder()/(key+'.json')),65536))
        from sentinelav.platform.service_changes import load_view
        view=load_view(fresh=request['operation']=='prepare')
        journal=BrokerJournal(root,owner,view['rows'])
        from sentinelav.detection.inspection import IsolatedScanner
        from sentinelav.paths import RESOURCE_ROOT
        # Only protected packaged signatures/rules; no user-controlled model,
        # exclusions, rules, trusted hashes, options or scan verdicts.
        scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',persistent=True)
        def verify(path):
            """Re-scan one file and keep only production-grade detections."""
            return [row for row in scanner.scan([path],lambda:False,lambda *args:None)['detections'] if production_detection(row)]
        from sentinelav.monitoring.app_changes import WindowsInventory
        from sentinelav.response.remediation import Remediator,WindowsRemediationBackend
        engine=Remediator(journal,WindowsRemediationBackend(WindowsInventory(service_scope=True)),verify)
        engine.reconcile()
        result=process_request(request,journal,engine,confirm_plan)
        response=dict(schema=1,ok=True,result=result)
    except Exception as error:response=dict(schema=1,ok=False,error=str(error))
    finally:
        if scanner:scanner.close()
    write_protected(root/('result-'+key+'.bin'),response,owner)
    return 0 if response['ok'] else 1


def launch(request):
    """Called by a GUI worker; UAC is the final authorization for each step."""
    validate_request(request)
    from sentinelav.platform.windows_identity import current_sid
    executable=unlinked(Path(os.environ['ProgramFiles'])/'SentinelAVProtection/SentinelAV.exe')
    verify_installation(executable.parent,protected=True)
    key=uuid.uuid4().hex;folder=request_folder();folder.mkdir(parents=True,exist_ok=True)
    request_path=unlinked(folder/(key+'.json'))
    with request_path.open('x',encoding='utf-8') as stream:json.dump(request,stream)
    class Execute(ctypes.Structure):
        """SHELLEXECUTEINFOW structure for ShellExecuteExW."""
        _fields_=[('size',wintypes.DWORD),('mask',wintypes.ULONG),('window',wintypes.HWND),('verb',wintypes.LPCWSTR),
            ('file',wintypes.LPCWSTR),('parameters',wintypes.LPCWSTR),('directory',wintypes.LPCWSTR),('show',ctypes.c_int),
            ('instance',wintypes.HINSTANCE),('idlist',ctypes.c_void_p),('class_name',wintypes.LPCWSTR),('class_key',wintypes.HKEY),
            ('hotkey',wintypes.DWORD),('icon',wintypes.HANDLE),('process',wintypes.HANDLE)]
    shell=ctypes.WinDLL('shell32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    shell.ShellExecuteExW.argtypes=[ctypes.POINTER(Execute)];shell.ShellExecuteExW.restype=wintypes.BOOL
    kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    info=Execute();info.size=ctypes.sizeof(info);info.mask=0x40;info.verb='runas';info.file=str(executable)
    info.parameters='--remediation-broker '+key;info.show=0
    try:
        if not shell.ShellExecuteExW(ctypes.byref(info)):raise ctypes.WinError(ctypes.get_last_error())
        try:
            if kernel.WaitForSingleObject(info.process,180000)!=0:raise TimeoutError('Broker still running; inspect its receipt before retrying')
        finally:kernel.CloseHandle(info.process)
        response=read_protected(protected_root(current_sid())/('result-'+key+'.bin'))
        if not response.get('ok'):raise ValueError(response.get('error','Protected repair failed'))
        return response['result']
    finally:request_path.unlink(missing_ok=True)

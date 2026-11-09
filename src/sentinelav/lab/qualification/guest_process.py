# Purpose: Launch the fixed per-user engine with reduced rights in verified test guests.
# Works with: lab.qualification.guest_context, platform.runtime, workspace
# Used by: lab.qualification.guest_support, tests.unit.test_harness_lifecycle

"""Launch the fixed per-user engine with reduced rights in verified test guests."""
import ctypes
import os
from pathlib import Path
import subprocess


class OwnedProcess:
    def __init__(self,handle,pid,details):
        self.handle=handle;self.pid=pid;self.evaluation_launch=details

    def poll(self):
        import win32event,win32process
        return None if win32event.WaitForSingleObject(self.handle,0)==258 else win32process.GetExitCodeProcess(self.handle)

    def wait(self,timeout=None):
        import win32event,win32process
        if win32event.WaitForSingleObject(self.handle,0xFFFFFFFF if timeout is None else int(timeout*1000))==258:
            raise subprocess.TimeoutExpired('owned guest engine',timeout)
        return win32process.GetExitCodeProcess(self.handle)

    def kill(self):
        import win32process
        if self.poll() is None:win32process.TerminateProcess(self.handle,1)

    def __del__(self):
        if getattr(self,'handle',None):self.handle.Close()


def launch_engine(data,context):
    from .guest_context import guard,BASE
    from sentinelav.workspace import unlinked
    from sentinelav.platform.runtime import launch_command
    if not guard(context):raise ValueError('Restricted engine launch requires a verified offline guest')
    data=unlinked(Path(data))
    if not data.is_relative_to(BASE/'Qualification') or data.name!='engine':raise ValueError('Engine data must be in an owned qualification case')
    command=launch_command('--engine-host','--data-dir',str(data))
    if not ctypes.windll.shell32.IsUserAnAdmin():
        process=subprocess.Popen(command,creationflags=subprocess.CREATE_NO_WINDOW)
        process.evaluation_launch=dict(mode='existing-nonadmin',administrator=False)
        return process
    import win32api,win32con,win32security as security,win32process
    # Keep the account identity; remove administrative memberships/privileges.
    # No account password, borrowed process token, or UAC policy change is used.
    original=security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_ALL_ACCESS)
    restricted=None;impersonation=None
    try:
        administrative={'S-1-5-32-544','S-1-5-32-547','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551','S-1-5-114'}
        disabled=[(sid,0) for sid,attrs in security.GetTokenInformation(original,security.TokenGroups)
            if security.ConvertSidToStringSid(sid) in administrative or attrs&8
            or security.ConvertSidToStringSid(sid).startswith('S-1-5-21-') and sid.GetSubAuthority(sid.GetSubAuthorityCount()-1) in (512,518,519,520)]
        restricted=security.CreateRestrictedToken(original,1,disabled,[],[])
        medium=security.ConvertStringSidToSid('S-1-16-8192')
        security.SetTokenInformation(restricted,security.TokenIntegrityLevel,(medium,0x20))
        impersonation=security.DuplicateToken(restricted,security.SecurityImpersonation)
        if security.CheckTokenMembership(impersonation,security.ConvertStringSidToSid('S-1-5-32-544')):
            raise RuntimeError('Restricted token still has administrative membership')
        sid,attrs=security.GetTokenInformation(restricted,security.TokenIntegrityLevel)
        integrity=sid.GetSubAuthority(sid.GetSubAuthorityCount()-1)
        if integrity>8192:raise RuntimeError('Guest engine integrity was not reduced')
        if security.GetTokenInformation(original,security.TokenUser)[0]!=security.GetTokenInformation(restricted,security.TokenUser)[0]:
            raise RuntimeError('Restricted token changed account identity')
        # Only these fresh, owned fixture directories need medium-integrity writes.
        user=security.ConvertSidToStringSid(security.GetTokenInformation(original,security.TokenUser)[0])
        for path in (data,data.parent/'watched'):
            unlinked(path)
            access=subprocess.run(['icacls.exe',str(path),'/grant:r','*'+user+':(OI)(CI)M','/T'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
            if access.returncode:raise RuntimeError('Could not grant the same guest account access to its owned engine fixtures')
            result=subprocess.run(['icacls.exe',str(path),'/setintegritylevel','(OI)(CI)M','/T'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:raise RuntimeError('Could not label owned engine fixture data for medium integrity')
        startup=win32process.STARTUPINFO();startup.dwFlags=1;startup.wShowWindow=0
        process,thread,pid,tid=win32process.CreateProcessAsUser(restricted,command[0],subprocess.list2cmdline(command),None,None,False,
            subprocess.CREATE_NO_WINDOW|win32con.CREATE_UNICODE_ENVIRONMENT,dict(os.environ),str(data.parent),startup)
        thread.Close()
        return OwnedProcess(process,pid,dict(mode='restricted-primary',administrator=False,integrity_rid=integrity,
            same_account=True,maximum_privileges_disabled=True))
    finally:
        if impersonation is not None:impersonation.Close()
        if restricted is not None:restricted.Close()
        original.Close()

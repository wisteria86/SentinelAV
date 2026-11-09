# Purpose: SCM-hosted, least-privilege monitoring with protected, admin-owned policy.
# Works with: data.storage, monitoring.monitoring, paths, platform.amsi_broker, platform.engine_policy
# Used by: entrypoint, platform.remediation_broker, platform.service_changes, ui.defense_pages

"""SCM-hosted, least-privilege monitoring with protected, admin-owned policy.

No service RPC accepts GUI commands or arbitrary paths. GUI status is read-only;
service control/installation uses Windows SCM authorization.
"""
from sentinelav.paths import RESOURCE_ROOT
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
import threading
import time

SERVICE_NAME='SentinelAVProtection'


def service_paths():
    base=Path(os.environ.get('ProgramData','C:/ProgramData'))/'SentinelAVProtection'
    return base,base/'data'


def query_service():
    if os.name!='nt': return dict(state='Unavailable',detail='Windows service requires Windows')
    advapi=ctypes.WinDLL('advapi32',use_last_error=True)
    advapi.OpenSCManagerW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.DWORD]
    advapi.OpenSCManagerW.restype=wintypes.HANDLE
    advapi.OpenServiceW.argtypes=[wintypes.HANDLE,wintypes.LPCWSTR,wintypes.DWORD]
    advapi.OpenServiceW.restype=wintypes.HANDLE
    advapi.CloseServiceHandle.argtypes=[wintypes.HANDLE]
    class Status(ctypes.Structure):
        _fields_=[(n,wintypes.DWORD) for n in ('kind','state','accepts','exit','specific','checkpoint','hint','pid','flags')]
    advapi.QueryServiceStatusEx.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    manager=advapi.OpenSCManagerW(None,None,1)
    if not manager: return dict(state='Unknown',detail='SCM status access denied')
    handle=None
    try:
        handle=advapi.OpenServiceW(manager,SERVICE_NAME,4)
        if not handle:
            error=ctypes.get_last_error()
            return dict(state='Not installed' if error==1060 else 'Unknown',detail=f'SCM status code {error}')
        status=Status(); required=wintypes.DWORD()
        if not advapi.QueryServiceStatusEx(handle,0,ctypes.byref(status),ctypes.sizeof(status),ctypes.byref(required)):
            return dict(state='Unknown',detail='Cannot read service status')
        return dict(state={1:'Stopped',2:'Starting',3:'Stopping',4:'Running',7:'Paused'}.get(status.state,'Transitioning'),pid=status.pid,
                    detail='Windows SCM authenticated status; configuration changes require administrator access')
    finally:
        if handle: advapi.CloseServiceHandle(handle)
        advapi.CloseServiceHandle(manager)


def read_health():
    result=query_service()
    _,data=service_paths()
    status=data/'status.json'
    if result['state']=='Running':
        try:
            if status.is_symlink() or status.stat().st_size>65536: raise ValueError('Invalid service status file')
            health=json.loads(status.read_text(encoding='utf-8'))
            if health.get('pid')!=result['pid'] or time.time()-health.get('heartbeat',0)>15:
                raise ValueError('Service heartbeat missing or stale')
            result['health']=health
        except Exception as error:
            result['detail']='SCM running, engine health unverified: '+str(error)
    return result


def run_service():
    if os.name!='nt' or not getattr(sys,'frozen',False):
        raise RuntimeError('The Windows service requires the packaged executable in a protected installation')
    from sentinelav.platform.windows_identity import current_sid
    if current_sid()!='S-1-5-19':
        raise RuntimeError('Protection service must run as LocalService, never as LocalSystem or an interactive administrator')
    executable=Path(sys.executable).resolve()
    protected=Path(os.environ.get('ProgramFiles','C:/Program Files')).resolve()
    if not executable.is_relative_to(protected): raise ValueError('Service executable must be under protected Program Files')
    for part in [executable,*executable.parents]:
        if part.is_symlink() or part.is_junction(): raise ValueError('Linked service installation rejected')
    base,data=service_paths()
    for part in [base,data,*base.parents]:
        if part.is_symlink() or part.is_junction(): raise ValueError('Linked service data rejected')
    if not base.is_dir() or not data.is_dir(): raise ValueError('Run the protected service installer first')
    advapi=ctypes.WinDLL('advapi32',use_last_error=True)
    class Status(ctypes.Structure):
        _fields_=[(n,wintypes.DWORD) for n in ('kind','state','accepts','exit','specific','checkpoint','hint')]
    handler_type=ctypes.WINFUNCTYPE(wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,ctypes.c_void_p)
    main_type=ctypes.WINFUNCTYPE(None,wintypes.DWORD,ctypes.POINTER(wintypes.LPWSTR))
    class Entry(ctypes.Structure): _fields_=[('name',wintypes.LPWSTR),('main',main_type)]
    advapi.RegisterServiceCtrlHandlerExW.argtypes=[wintypes.LPCWSTR,handler_type,ctypes.c_void_p]
    advapi.RegisterServiceCtrlHandlerExW.restype=wintypes.HANDLE
    advapi.SetServiceStatus.argtypes=[wintypes.HANDLE,ctypes.POINTER(Status)]
    advapi.StartServiceCtrlDispatcherW.argtypes=[ctypes.POINTER(Entry)]
    stop=threading.Event()
    state={'handle':None,'monitor':None,'broker':None,'checkpoint':0,'current':2}
    status_lock=threading.RLock()
    startup_done=threading.Event()
    def publish_status(code,error=0):
        with status_lock:
            if code==2 and state['current']!=2: return
            state['current']=code
            state['checkpoint']+=1
            status=Status(0x10,code,5 if code==4 else 0,error,1 if error==1066 else 0,state['checkpoint'] if code in (2,3) else 0,15000 if code in (2,3) else 0)
            if state['handle']: advapi.SetServiceStatus(state['handle'],ctypes.byref(status))
    @handler_type
    def control(code,event_type,event_data,context):
        if code in (1,5):
            publish_status(3); stop.set()
            if state['monitor']: state['monitor'].stop.set()
            if state['broker']: state['broker'].stop.set()
        return 0
    @main_type
    def main(count,args):
        state['handle']=advapi.RegisterServiceCtrlHandlerExW(SERVICE_NAME,control,None)
        if not state['handle']: return
        publish_status(2)
        def startup_heartbeat():
            while not startup_done.wait(2): publish_status(2)
        heartbeat=threading.Thread(target=startup_heartbeat,name='service-startup',daemon=True)
        heartbeat.start()
        store=None
        try:
            from sentinelav.monitoring.monitoring import Monitor
            from sentinelav.data.storage import Store
            from sentinelav.platform.integrity import verify_installation,verify_windows_acl
            verify_installation(executable.parent,protected=True)
            verify_windows_acl(base)
            verify_windows_acl(data,service_writable=True)
            policy_path=base/'policy.json'
            if policy_path.is_symlink() or policy_path.stat().st_size>32768: raise ValueError('Invalid service policy')
            verify_windows_acl(policy_path)
            policy=json.loads(policy_path.read_text(encoding='utf-8-sig'))
            folders=policy.get('folders',[])
            if not isinstance(folders,list) or len(folders)>64 or any(not isinstance(p,str) or not Path(p).is_absolute() for p in folders):
                raise ValueError('Invalid service watch folders')
            resources=RESOURCE_ROOT
            if type(policy.get('amsi_broker',False)) is not bool: raise ValueError('Invalid AMSI service policy')
            if policy.get('amsi_broker',False):
                from sentinelav.platform.amsi_broker import AmsiBroker
                state['broker']=AmsiBroker(resources)
                state['broker'].start()
            for name in ('sysmon','behavior','network','event_processes','watch_app_changes'):
                if name in policy and type(policy[name]) is not bool: raise ValueError('Invalid source policy: '+name)
            from sentinelav.platform.engine_policy import inspection_options
            service_inspection=inspection_options(policy.get('inspection_options'))
            service_inspection['analysis_store']=str(data/'analysis-data')
            service_inspection['analysis_trust']=str(resources/'trusted-update-keys.json')
            config=dict(folders=folders,processes=True,sysmon=policy.get('sysmon',False),behavior=policy.get('behavior',True),
                network=policy.get('network',False),event_processes=policy.get('event_processes',True),
                signatures=resources/'signatures.json',rules=resources/'rules',max_mb=100,
                exclusions=[str(base),str(executable.parent)],trusted_hashes=[],inspection_options=service_inspection)
            if policy.get('watch_app_changes',False):
                import re
                if not re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+',policy.get('owner_sid','')):raise ValueError('A deployment owner SID is required for change tracking')
                config.update(watch_app_changes=True,service_owner=policy['owner_sid'],data_dir=str(data))
            if policy.get('artifact_updates',{}).get('enabled'):
                config.update(artifact_updates=policy['artifact_updates'],data_dir=str(data))
            if policy.get('kernel_collector'):
                if not isinstance(policy['kernel_collector'],str): raise ValueError('Invalid kernel collector path')
                config['kernel_collector']=policy['kernel_collector']
            inbox=__import__('queue').Queue(maxsize=1024)
            dropped=[0]
            def event(item):
                try: inbox.put_nowait(item)
                except __import__('queue').Full: dropped[0]+=1
            store=Store(data/'sentinelav.db')
            from collections import deque
            recent_alerts=deque(maxlen=10)
            def status(stats):
                while not inbox.empty():
                    item=inbox.get_nowait()
                    store.save_event(item)
                    if item.get('level') in ('Alert','Warning'):
                        recent_alerts.append(dict(time=str(item.get('time',''))[:32],kind=str(item.get('kind',''))[:128],
                            details=str(item.get('details',''))[:512],path=str(item.get('path',''))[:512],
                            sha256=str(item.get('sha256',''))[:64],level=item['level']))
                health=dict(pid=os.getpid(),heartbeat=time.time(),engine='Monitoring',stats=stats,
                            dropped_service_events=dropped[0],account='LocalService',automatic_response=False,
                            recent_alerts=list(recent_alerts))
                broker=state['broker']
                health['amsi_broker']=dict(enabled=broker is not None,
                    running=bool(broker and broker.thread.is_alive() and not broker.error and not broker.stop.is_set()),
                    completed=broker.completed if broker else 0,omissions=broker.omissions if broker else 0,
                    error=broker.error if broker else None,provider_registration='Not verified')
                temp=data/'status.pending'
                temp.write_text(json.dumps(health),encoding='utf-8')
                os.replace(temp,data/'status.json')
                startup_done.set()
                publish_status(3 if stop.is_set() else 4)
                if stop.is_set(): state['monitor'].stop.set()
            monitor=Monitor(config,event,status)
            state['monitor']=monitor
            if stop.is_set(): monitor.stop.set()
            monitor.run()
            while not inbox.empty(): store.save_event(inbox.get_nowait())
            publish_status(1)
        except Exception as error:
            try: (data/'last-error.txt').write_text(str(error),encoding='utf-8')
            except OSError: pass
            publish_status(1,1066)
        finally:
            startup_done.set()
            heartbeat.join(3)
            if state['broker']:
                try: state['broker'].close()
                except Exception as error:
                    try: (data/'last-error.txt').write_text(str(error),encoding='utf-8')
                    except OSError: pass
            if store: store.db.close()
    table=(Entry*2)(Entry(SERVICE_NAME,main),Entry(None,main_type()))
    if not advapi.StartServiceCtrlDispatcherW(table): raise ctypes.WinError(ctypes.get_last_error())
    return 0

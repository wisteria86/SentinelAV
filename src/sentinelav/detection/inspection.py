"""JSON-only scan worker with Windows job limits and bounded transport.

Fault/resource isolation, not a VM or an AppContainer security sandbox.
"""
from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
import ctypes
import base64
from ctypes import wintypes
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

MAX_LINE=4*1024*1024
MAX_REQUEST=2*1024*1024


class WindowsJob:
    def __init__(self,process,memory=768*1024*1024):
        self.handle=None
        if os.name!='nt': return
        class Basic(ctypes.Structure):
            _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',wintypes.DWORD),
                ('minimum_ws',ctypes.c_size_t),('maximum_ws',ctypes.c_size_t),('processes',wintypes.DWORD),
                ('affinity',ctypes.c_size_t),('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_=[(name,ctypes.c_ulonglong) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
        class Extended(ctypes.Structure):
            _fields_=[('basic',Basic),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),
                      ('peak_process_memory',ctypes.c_size_t),('peak_job_memory',ctypes.c_size_t)]
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype=wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        handle=self.kernel.CreateJobObjectW(None,None)
        if not handle: raise ctypes.WinError(ctypes.get_last_error())
        info=Extended()
        info.basic.flags=0x2000|0x100|0x200|0x8
        info.basic.processes=2  # Windows venv redirector plus its interpreter.
        info.process_memory=info.job_memory=memory
        if not self.kernel.SetInformationJobObject(handle,9,ctypes.byref(info),ctypes.sizeof(info)) or not self.kernel.AssignProcessToJobObject(handle,wintypes.HANDLE(int(process._handle))):
            self.kernel.CloseHandle(handle)
            raise RuntimeError('Cannot enforce scan-worker job limits')
        self.handle=handle

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle=None


class IndexInfo:
    def __init__(self,count,metadata): self.count,self.metadata=count,metadata
    def __len__(self): return self.count
    def close(self): pass


class IsolatedScanner:
    def __init__(self,signatures,rules_dir,max_mb=100,exclusions=(),trusted_hashes=(),options=None,persistent=False):
        self.config=dict(signatures=str(Path(signatures).resolve()),rules=str(Path(rules_dir).resolve()),
                         max_mb=max_mb,exclusions=list(map(str,exclusions)),trusted_hashes=list(trusted_hashes),options=options or {})
        self.process=None
        self.job=None
        self.max_bytes=max_mb*1024*1024
        self.keep_alive=persistent
        self.exclusions=[Path(p).resolve() for p in exclusions]
        self.start()

    def start(self):
        if getattr(sys,'frozen',False): command=[sys.executable,'--inspection-worker']
        else: command=[str(Path(sys.executable).with_name('python.exe') if os.name=='nt' else Path(sys.executable)),str((PROJECT_ROOT/'app.py')),'--inspection-worker']
        environment={k:v for k,v in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','PATH','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA','PROGRAMDATA','PROGRAMFILES','PROGRAMFILES(X86)','SYSTEMDRIVE')}
        environment['PYTHONIOENCODING']='utf-8'
        environment['QT_QPA_PLATFORM']='offscreen'
        self.messages=queue.Queue(maxsize=16)
        self.error=''
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                      cwd=str(RESOURCE_ROOT),env=environment,
                                      creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:
            self.job=WindowsJob(self.process)
            process=self.process
            messages=self.messages
            errors=[]
            self.transport_errors=errors
            def read():
                try:
                    while True:
                        line=process.stdout.readline(MAX_LINE+1)
                        if not line: break
                        if len(line)>MAX_LINE or not line.endswith(b'\n'): raise ValueError('Worker output exceeded framing limit')
                        messages.put(json.loads(line),timeout=1)
                except Exception as error:
                    errors.append(str(error))
                    if process.poll() is None: process.kill()
            self.reader=threading.Thread(target=read,name='inspection-results',daemon=True)
            self.reader.start()
            reply=self.exchange(dict(command='initialize',config=self.config),lambda:False,lambda *a:None,30)
            self.signatures=IndexInfo(reply['signature_count'],reply['signature_metadata'])
            self.rule_summary=reply['yara']
            self.warnings=reply['warnings']
        except BaseException:
            self.close()
            raise

    def excluded(self,path):
        resolved=Path(path).resolve()
        return any(resolved==p or p in resolved.parents for p in self.exclusions)

    def exchange(self,message,cancelled,progress,timeout):
        raw=json.dumps(dict(protocol=1,**message)).encode()+b'\n'
        if len(raw)>(MAX_REQUEST if message.get('command')=='buffer' else 128*1024): raise ValueError('Inspection request exceeds limit')
        if self.process is None or self.process.poll() is not None: raise RuntimeError('Inspection worker is not running')
        process=self.process
        write_errors=[]
        def write_request():
            try:
                process.stdin.write(raw)
                process.stdin.flush()
            except Exception as error: write_errors.append(str(error))
        writer=threading.Thread(target=write_request,name='inspection-request',daemon=True)
        writer.start()
        deadline=time.monotonic()+timeout
        began=time.monotonic()
        partial=[]
        partial_keys={}
        partial_bytes=0
        checked=0
        def incomplete(status,error):
            return dict(started=time.strftime('%Y-%m-%d %H:%M:%S'),scanned=max(checked,len({d.get('path','') for d in partial})),skipped=0,errors=[error] if error else [],
                detections=partial,status=status,elapsed=round(time.monotonic()-began,2),
                warnings=['Partial worker result; coverage is incomplete'],yara=getattr(self,'rule_summary',{}))
        while True:
            if cancelled():
                self.close()
                return incomplete('Cancelled','')
            if time.monotonic()>deadline:
                self.close()
                if message['command']=='scan': return incomplete('Complete with omissions','Inspection worker exceeded its wall-clock budget')
                raise TimeoutError('Inspection worker exceeded its wall-clock budget; coverage is incomplete')
            try: reply=self.messages.get(timeout=.05)
            except queue.Empty:
                if self.process.poll() is not None:
                    if message['command']=='scan': return incomplete('Complete with omissions','Inspection worker exited; '+'; '.join(self.transport_errors))
                    raise RuntimeError('Inspection worker exited; coverage is incomplete. '+'; '.join(self.transport_errors))
                continue
            if not isinstance(reply,dict) or reply.get('protocol')!=1: raise ValueError('Invalid inspection response')
            if reply.get('type')=='progress':
                checked=reply['scanned']
                progress(reply['path'],reply['scanned'],reply['threats'])
                continue
            if reply.get('type')=='finding':
                finding=reply.get('finding')
                if not isinstance(finding,dict): raise ValueError('Invalid partial finding')
                partial_bytes+=len(json.dumps(finding).encode())
                if partial_bytes>MAX_LINE or len(partial)>=1000:
                    self.close()
                    return incomplete('Complete with omissions','Partial finding budget exceeded')
                key=(finding.get('path'),finding.get('sha256'),tuple(finding.get('member_chain',[])))
                if key in partial_keys:
                    old=partial[partial_keys[key]]
                    reasons=list(dict.fromkeys(old.get('reasons',[])+finding.get('reasons',[])))
                    old.update(finding); old['reasons']=reasons
                else:
                    partial_keys[key]=len(partial)
                    partial.append(finding)
                continue
            if reply.get('type')=='error':
                if message['command']=='scan': return incomplete('Complete with omissions',reply['error'])
                raise RuntimeError(reply['error'])
            if reply.get('type')!='result' or not isinstance(reply.get('result'),dict): raise ValueError('Invalid inspection result')
            return reply['result']

    def scan(self,roots,cancelled,progress):
        timeout=30 if len(roots)==1 and Path(roots[0]).is_file() else 300
        try: return self.exchange(dict(command='scan',roots=list(map(str,roots))),cancelled,progress,timeout)
        finally:
            if not self.keep_alive: self.close()

    def scan_memory(self,pid,creation,cancelled=lambda:False):
        try: return self.exchange(dict(command='memory',pid=pid,creation=creation),cancelled,lambda *a:None,12)
        finally:
            if not self.keep_alive: self.close()

    def scan_buffer(self,content,cancelled=lambda:False):
        from sentinelav.detection.buffer_scan import MAX_BUFFER
        try:
            if not isinstance(content,bytes): raise TypeError('Buffer content must be bytes')
            if len(content)>MAX_BUFFER: raise ValueError('Buffer exceeds the 1 MiB inspection limit')
            result=self.exchange(dict(command='buffer',content=base64.b64encode(content).decode('ascii')),
                                 cancelled,lambda *a:None,8)
            if result.get('kind')!='buffer': raise RuntimeError('Buffer inspection did not complete')
            return result
        finally:
            if not self.keep_alive: self.close()

    def close(self):
        process=self.process
        self.process=None
        if self.job: self.job.close(); self.job=None
        if process:
            if process.poll() is None: process.kill()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: pass
            for stream in (process.stdin,process.stdout):
                if stream:
                    try: stream.close()
                    except OSError: pass

    def __del__(self):
        if getattr(self,'process',None) is not None: self.close()


def worker_main():
    from sentinelav.detection.engine import Scanner
    scanner=None
    input_stream=getattr(sys.stdin,'buffer',None)
    output_stream=getattr(sys.stdout,'buffer',None)
    if (input_stream is None or output_stream is None) and os.name=='nt':
        import msvcrt
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.GetStdHandle.argtypes=[wintypes.DWORD]
        kernel.GetStdHandle.restype=wintypes.HANDLE
        if input_stream is None:
            input_stream=os.fdopen(msvcrt.open_osfhandle(int(kernel.GetStdHandle(wintypes.DWORD(-10))),os.O_RDONLY|os.O_BINARY),'rb')
        if output_stream is None:
            output_stream=os.fdopen(msvcrt.open_osfhandle(int(kernel.GetStdHandle(wintypes.DWORD(-11))),os.O_WRONLY|os.O_BINARY),'wb')
    def send(kind,**fields):
        data=json.dumps(dict(protocol=1,type=kind,**fields)).encode()+b'\n'
        if len(data)>MAX_LINE: data=json.dumps(dict(protocol=1,type='error',error='Inspection result exceeded limit; coverage is incomplete')).encode()+b'\n'
        output_stream.write(data)
        output_stream.flush()
    try:
        while True:
            raw=input_stream.readline(MAX_REQUEST+1)
            if not raw: break
            try:
                if len(raw)>MAX_REQUEST or not raw.endswith(b'\n'): raise ValueError('Invalid request framing')
                request=json.loads(raw)
                if not isinstance(request,dict) or request.get('protocol')!=1: raise ValueError('Invalid inspection protocol')
                command=request.get('command')
                if command!='buffer' and len(raw)>128*1024: raise ValueError('Request exceeds command limit')
                if command=='initialize' and scanner is None:
                    config=request['config']
                    if (not isinstance(config,dict) or set(config)!={'signatures','rules','max_mb','exclusions','trusted_hashes','options'}
                            or type(config['max_mb']) is not int or not 1<=config['max_mb']<=1024
                            or not isinstance(config['exclusions'],list) or len(config['exclusions'])>1024
                            or not isinstance(config['trusted_hashes'],list) or len(config['trusted_hashes'])>10000):
                        raise ValueError('Invalid worker configuration')
                    scanner=Scanner(config['signatures'],config['rules'],config['max_mb'],config['exclusions'],config['trusted_hashes'],config['options'])
                    scanner.early_finding=lambda finding:send('finding',finding=finding)
                    result=dict(signature_count=len(scanner.signatures),signature_metadata=scanner.signatures.metadata,yara=scanner.rule_summary,warnings=scanner.warnings)
                elif command=='scan' and scanner is not None:
                    roots=request.get('roots')
                    if not isinstance(roots,list) or not 1<=len(roots)<=10000 or any(not isinstance(p,str) or len(p)>32768 or not Path(p).is_absolute() for p in roots):
                        raise ValueError('Invalid scan paths')
                    last=[0.]
                    sent=[0]
                    def progress(path,scanned,threats):
                        detections=scanner.current_scan_result['detections']
                        for finding in detections[sent[0]:]: send('finding',finding=finding)
                        sent[0]=len(detections)
                        if time.monotonic()-last[0]>.1:
                            send('progress',path=path,scanned=scanned,threats=threats)
                            last[0]=time.monotonic()
                    result=scanner.scan(roots,lambda:False,progress)
                elif command=='buffer' and scanner is not None:
                    from sentinelav.detection.buffer_scan import inspect_buffer,MAX_BUFFER
                    encoded=request.get('content')
                    if set(request)!={'protocol','command','content'} or not isinstance(encoded,str) or len(encoded)>4*((MAX_BUFFER+2)//3):
                        raise ValueError('Invalid buffer request')
                    result=inspect_buffer(scanner,base64.b64decode(encoded,validate=True))
                elif command=='memory' and scanner is not None:
                    from sentinelav.detection.memory_inspection import inspect_memory
                    result=inspect_memory(request['pid'],request['creation'],scanner.analyze_bytes)
                else: raise ValueError('Unsupported worker request')
                send('result',result=result)
            except Exception as error: send('error',error=str(error)[:2000])
    finally:
        if scanner is not None: scanner.signatures.close()
    return 0

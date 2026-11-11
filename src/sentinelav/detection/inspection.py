# Purpose: Manage isolated scan workers and their bounded JSON exchanges.
# Works with: detection.buffer_scan, detection.inspection_protocol, detection.inspection_worker,
#   detection.worker_limits, paths
# Used by: entrypoint, lab.advanced_check, lab.corpus_evaluation, lab.qualification.corpus_inputs

"""JSON-only scan worker with Windows job limits and bounded transport.

Fault/resource isolation, not a VM or an AppContainer security sandbox.
"""
from .inspection_protocol import MAX_LINE,MAX_REQUEST
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


from .worker_limits import WindowsJob
from .inspection_worker import worker_main


PER_FILE_SECONDS=180
MAX_WORKER_RESUMES=64


def merge_results(first,second):
    """Combine scan segments from before and after a worker restart."""
    merged=dict(second)
    for key in ('scanned','skipped'):merged[key]=first.get(key,0)+second.get(key,0)
    seen=set();detections=[]
    for row in first.get('detections',[])+second.get('detections',[]):
        key=(row.get('path'),row.get('sha256'),tuple(row.get('member_chain',[])),tuple(row.get('reasons',[])))
        if key not in seen:seen.add(key);detections.append(row)
    merged['detections']=detections
    merged['suspicious']=first.get('suspicious',[])+second.get('suspicious',[])
    merged['errors']=first.get('errors',[])+second.get('errors',[])
    merged['elapsed']=round(first.get('elapsed',0)+second.get('elapsed',0),2)
    merged['started']=first.get('started',second.get('started'))
    if merged.get('status')=='Complete':merged['status']='Complete with omissions'
    return merged


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
        environment={k:v for k,v in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','PATH','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA','PROGRAMDATA','PROGRAMFILES','PROGRAMFILES(X86)','SYSTEMDRIVE',
            'SENTINELAV_WORK_ROOT','SENTINELAV_CLAMAV_HOME','SENTINELAV_CLAMAV_DB','SENTINELAV_DEFINITIONS','SENTINELAV_CLAMAV_RUNTIME')}
        environment['PYTHONIOENCODING']='utf-8'
        environment['QT_QPA_PLATFORM']='offscreen'
        # Native model loaders can initialize OpenMP/BLAS pools before predict's
        # per-call limit takes effect. Bound those pools at process startup so
        # their thread stacks cannot consume the emulator's 1 GiB job budget.
        for variable in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS'):
            environment[variable]='2'
        self.messages=queue.Queue(maxsize=16)
        self.error=''
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                      cwd=str(RESOURCE_ROOT),env=environment,
                                      creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:
            from sentinelav.platform.engine_policy import inspection_options
            effective=inspection_options(self.config.get('options') or {})
            self.job=WindowsJob(self.process,memory=1536*1024*1024 if any(effective.get(k) for k in ('emulation','model','neural','neural_gray')) else 768*1024*1024)
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
        suspicious=[]
        position=dict(index=0,path='')
        def incomplete(status,error):
            return dict(started=time.strftime('%Y-%m-%d %H:%M:%S'),scanned=max(checked,len({d.get('path','') for d in partial})),skipped=0,errors=[error] if error else [],
                detections=partial,suspicious=suspicious,status=status,elapsed=round(time.monotonic()-began,2),resume_index=position['index'],stuck_path=position['path'],
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
                    if message['command']=='scan': return incomplete('Complete with omissions','Inspection worker exited (code '+str(getattr(self.process,'returncode','unknown'))+'); '+'; '.join(self.transport_errors))
                    raise RuntimeError('Inspection worker exited; coverage is incomplete. '+'; '.join(self.transport_errors))
                continue
            if not isinstance(reply,dict) or reply.get('protocol')!=1: raise ValueError('Invalid inspection response')
            # The budget limits silence, not total duration, so a long full-disk scan is never cut off while it advances.
            if reply.get('type') in ('begin','progress','finding','suspicious') and message['command']=='scan':
                deadline=time.monotonic()+timeout
            if reply.get('type')=='begin':
                position.update(index=reply['index'],path=reply['path'])
                continue
            if reply.get('type')=='suspicious':
                if isinstance(reply.get('finding'),dict) and len(suspicious)<2000:suspicious.append(reply['finding'])
                continue
            if reply.get('type')=='progress':
                checked=reply['scanned']
                progress(reply['path'],reply['scanned'],reply['threats'])
                continue
            if reply.get('type')=='finding':
                finding=reply.get('finding')
                if not isinstance(finding,dict): raise ValueError('Invalid partial finding')
                partial_bytes+=len(json.dumps(finding).encode())
                if partial_bytes>MAX_LINE or len(partial)>=2000:
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
        single=len(roots)==1 and Path(roots[0]).is_file()
        timeout=PER_FILE_SECONDS
        restarted=False
        try:
            if self.keep_alive and not cancelled() and (self.process is None or self.process.poll() is not None):
                self.close()
                self.start()
                restarted=True
            result=self.exchange(dict(command='scan',roots=list(map(str,roots))),cancelled,progress,timeout)
            # A hostile or hung file costs that file, not the rest of the scan.
            for _ in range(MAX_WORKER_RESUMES):
                position=result.get('resume_index',0)
                if single or not position or result.get('status')=='Cancelled' or cancelled():break
                result['errors'].append(f"Skipped after the inspection worker stopped: {result.get('stuck_path','')}")
                self.close();self.start()
                restarted=True
                following=self.exchange(dict(command='scan',roots=list(map(str,roots)),skip=position),cancelled,progress,timeout)
                result=merge_results(result,following)
            if restarted: result['worker_restarted']=True
            return result
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

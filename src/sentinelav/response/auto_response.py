"""Opt-in exact-hash quarantine policy. Never auto-terminates processes."""
from collections import deque
import os
from pathlib import Path
import queue
import re
import threading
import time
from sentinelav.data.storage import Store
from sentinelav.response.response import ResponseService


def eligibility(event,policy):
    if not isinstance(policy,dict) or policy.get('enabled') is not True: return False,'Policy disabled'
    digest=event.get('sha256','')
    approvals=policy.get('approved_hashes',[])
    if not isinstance(approvals,list) or len(approvals)>256 or digest not in approvals: return False,'Exact hash is not approved for automatic response'
    if not re.fullmatch(r'[0-9a-f]{64}',digest): return False,'Invalid detection hash'
    if event.get('member_chain'): return False,'Archive-member findings require manual review'
    if not any(reason.startswith('SHA-256: ') for reason in event.get('reasons',[])): return False,'An independent exact-hash signature match is required'
    raw_path=event.get('path','')
    if not isinstance(raw_path,str) or not raw_path or not Path(raw_path).is_absolute(): return False,'Invalid absolute file path'
    original=Path(raw_path)
    if any(p.is_symlink() or p.is_junction() for p in [original,*original.parents]): return False,'Linked paths require manual review'
    path=original.resolve()
    roots=policy.get('roots',[])
    if not isinstance(roots,list) or not roots or len(roots)>32 or any(not isinstance(r,str) for r in roots): return False,'No bounded response scope'
    if any(part.is_symlink() or part.is_junction() for root in roots for part in [Path(root),*Path(root).parents]):
        return False,'Linked response roots require manual review'
    if os.name=='nt' and (len(path.drive)!=2 or path.drive[1]!=':'): return False,'Automatic response supports local drives only'
    if not any(Path(root).is_absolute() and path.is_relative_to(Path(root).resolve()) for root in roots): return False,'Outside automatic-response scope'
    return True,'Approved exact hash within configured scope'


class AutoResponder:
    def __init__(self,data_dir,root,policy,emit):
        self.data_dir,self.root,self.policy,self.emit=Path(data_dir),Path(root),policy,emit
        self.queue=queue.Queue(maxsize=8)
        self.stopping=threading.Event()
        self.attempts=deque()
        self.seen={}
        self.ready=False
        self.enabled=False
        self.error=''
        self.thread=threading.Thread(target=self.run,name='approved-hash-quarantine')
        self.thread.start()

    def report(self,kind,details,level='Info'):
        self.emit(dict(time=time.strftime('%Y-%m-%d %H:%M:%S'),kind=kind,details=details,source='Response policy',level=level))

    def submit(self,detection):
        allowed,_=eligibility(detection,self.policy)
        if not allowed or self.stopping.is_set(): return
        try: self.queue.put_nowait(dict(detection))
        except queue.Full: self.report('Automatic response backlog','Queue full; finding left for manual review','Warning')

    def run(self):
        store=None
        try:
            store=Store(self.data_dir/'sentinelav.db')
            responder=ResponseService(store,self.root)
            self.ready=True
            while not self.stopping.is_set():
                latest=store.get('auto_response',{})
                self.enabled=isinstance(latest,dict) and latest.get('enabled') is True
                try: detection=self.queue.get(timeout=.5)
                except queue.Empty: continue
                allowed,reason=eligibility(detection,latest)
                if not allowed: continue
                now=time.monotonic()
                key=(detection['path'],detection['sha256'])
                self.attempts=deque(t for t in self.attempts if now-t<60)
                if len(self.attempts)>=3 or now-self.seen.get(key,-1000)<300:
                    self.report('Automatic response deferred','Rate limit/cooldown reached; review finding manually','Warning')
                    continue
                self.attempts.append(now); self.seen[key]=now
                if len(self.seen)>1024: self.seen.pop(next(iter(self.seen)))
                try:
                    record=responder.quarantine_file(detection)
                    self.report('Approved-hash quarantine completed',str(record['original']))
                except Exception as error:
                    self.report('Automatic response failed',str(error),'Warning')
        except Exception as error:
            self.error=str(error)
            self.report('Automatic response unavailable',self.error,'Warning')
        finally:
            self.ready=False
            self.enabled=False
            if store: store.db.close()

    def close(self):
        self.stopping.set()
        # Fresh verification/response is bounded by the isolated scan worker;
        # do not report monitoring stopped while an owned action is unfinished.
        self.thread.join()

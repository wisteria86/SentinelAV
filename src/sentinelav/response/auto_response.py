# Purpose: Opt-in exact-hash quarantine policy. Never auto-terminates processes.
# Works with: data.change_journal, data.contracts, data.storage, detection.fusion, detection.inspection
# Used by: lab.qualification.guest_inventory, monitoring.monitor_loop, tests.unit.test_defense_layers,
#   tests.unit.test_runtime_guards

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
    if event.get('automatic_response_eligible') is False: return False,'This finding requires manual response'
    digest=event.get('sha256','')
    approvals=policy.get('approved_hashes',[])
    calibrated=(policy.get('allow_calibrated_unknown') is True and event.get('automatic_response_eligible') is True
        and isinstance(event.get('fusion_policy_id'),str) and bool(re.fullmatch('[0-9a-f]{64}',event['fusion_policy_id'])))
    if not calibrated and (not isinstance(approvals,list) or len(approvals)>256 or digest not in approvals): return False,'Exact hash is not approved for automatic response'
    if not re.fullmatch(r'[0-9a-f]{64}',digest): return False,'Invalid detection hash'
    if event.get('member_chain'): return False,'Archive-member findings require manual review'
    if not calibrated and not any(reason.startswith('SHA-256: ') for reason in event.get('reasons',[])): return False,'An independent exact-hash signature match is required'
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
        self.failures=0;self.circuit_open=False;self.reset_id=None
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
                if isinstance(latest,dict) and latest.get('reset_id')!=self.reset_id:
                    self.reset_id=latest.get('reset_id');self.failures=0;self.circuit_open=False
                self.enabled=isinstance(latest,dict) and latest.get('enabled') is True and not self.circuit_open
                try: detection=self.queue.get(timeout=.5)
                except queue.Empty: continue
                allowed,reason=eligibility(detection,latest)
                if not allowed or self.circuit_open: continue
                now=time.monotonic()
                key=(detection['path'],detection['sha256'])
                self.attempts=deque(t for t in self.attempts if now-t<60)
                if len(self.attempts)>=3 or now-self.seen.get(key,-1000)<300:
                    self.report('Automatic response deferred','Rate limit/cooldown reached; review finding manually','Warning')
                    continue
                self.attempts.append(now); self.seen[key]=now
                if len(self.seen)>1024: self.seen.pop(next(iter(self.seen)))
                try:
                    self.persistence(detection,latest,store,responder)
                    record=responder.quarantine_file(detection)
                    self.failures=0
                    self.report('Automatic quarantine completed',str(record['original']))
                except Exception as error:
                    self.report('Automatic response failed',str(error),'Warning')
                    self.failures+=1
                    if self.failures>=3:
                        self.circuit_open=True;self.enabled=False
                        self.report('Automatic response paused','Three consecutive failures; review the cause and save the response policy to reset.','Warning')
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

    def persistence(self,detection,policy,store,responder):
        if not policy.get('auto_persistence') or not store.get('watch_app_changes',False):return
        from sentinelav.updates.artifacts import active
        from sentinelav.detection.fusion import gates
        from sentinelav.data.contracts import fingerprint
        from sentinelav.data.change_journal import ChangeJournal
        from sentinelav.response.remediation import Remediator,WindowsRemediationBackend,referenced_paths
        options=store.get('inspection_options',{})
        folder=options.get('analysis_store',str(store.path.parent/'analysis-data'))
        trust=options.get('analysis_trust',str(self.root/'trusted-update-keys.json'))
        signed,_=active(folder,trust,'policy')
        if not gates(signed)['automatic']:return
        if detection.get('fusion_policy_id') and detection['fusion_policy_id']!=fingerprint(signed):raise ValueError('Automatic persistence policy changed')
        journal=ChangeJournal(self.data_dir/'app-changes')
        try:
            selected=[]
            for record in journal.changes():
                resource=record['resource']
                if resource['kind']!='registry' or resource.get('hive')!='HKCU' or record['attribution']!='Verified':continue
                if not 0<=time.time()-record['observed_at']<=60:continue
                if any(os.path.normcase(str(Path(path).resolve()))==os.path.normcase(str(Path(detection['path']).resolve())) for path in referenced_paths(record)):selected.append(record['id'])
                if len(selected)>=16:break
            if not selected:return
            from sentinelav.detection.inspection import IsolatedScanner
            scanner=IsolatedScanner(self.root/'signatures.json',self.root/'rules',options=options,persistent=True)
            try:
                def verify(path):return scanner.scan([path],lambda:False,lambda *a:None)['detections']
                engine=Remediator(journal,WindowsRemediationBackend(),verify,responder)
                plan=engine.plan(selected,with_related=False)
                plan.update(automatic=True,authorized_policy=fingerprint(signed));journal.operation(plan)
                receipt=engine.execute(plan['id'],approved=True)
                self.report('Automatic persistence cleanup',receipt['state'],'Info' if all(r['state']=='Verified' for r in receipt['results']) else 'Warning')
            finally:scanner.close()
        finally:journal.close()

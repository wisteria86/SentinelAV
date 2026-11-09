# Purpose: Explicit, hash-authorized process-tree response. No score-only termination.
# Works with: response.response
# Used by: response.response, tests.unit.test_tree_containment, tools.evaluation.process_tree_response

"""Explicit, hash-authorized process-tree response. No score-only termination."""
import hashlib
import time
import re
import psutil
from sentinelav.response.response import checked_path


def plan_tree(pid,creation):
    parent=psutil.Process(pid)
    if parent.create_time()!=creation: raise ValueError('Process identity changed')
    owner=psutil.Process().username()
    result=[]
    omissions=[]; total=0; deadline=time.monotonic()+10
    for process in [*parent.children(recursive=True),parent][:128]:
        try:
            if time.monotonic()>deadline: omissions.append('Planning time budget reached'); break
            info=process.as_dict(attrs=['pid','ppid','create_time','exe','username'])
            if info['username']!=owner or not info['exe']: continue
            path=checked_path(info['exe'])
            if path.stat().st_size>100*1024*1024: continue
            digest=hashlib.sha256()
            with path.open('rb') as stream:
                while block:=stream.read(1024*1024):
                    total+=len(block)
                    if total>256*1024*1024 or time.monotonic()>deadline: raise ValueError('Process-plan I/O budget reached')
                    digest.update(block)
            result.append(dict(pid=info['pid'],parent=info['ppid'],creation=info['create_time'],path=str(path),sha256=digest.hexdigest()))
        except (OSError,ValueError,psutil.Error) as error:
            omissions.append(str(error)[:160])
            if total>256*1024*1024: break
            continue
    by_pid={item['pid']:item for item in result}
    def depth(item):
        count=0; seen=set(); parent=item['parent']
        while parent in by_pid and parent not in seen and count<128:
            seen.add(parent); count+=1; parent=by_pid[parent]['parent']
        return count
    result.sort(key=depth,reverse=True)
    return dict(root_pid=pid,root_creation=creation,processes=result,automatic=False,omissions=omissions[:32],created_at=time.time(),expires_at=time.time()+120,
        limitation='Snapshot only; new children require a new plan. Each process requires its own approved hash and fresh signature verification.')


def execute_plan(service,plan,approved_hashes):
    if not isinstance(approved_hashes,list) or len(approved_hashes)>256: raise ValueError('Explicit approved hash list required')
    if not isinstance(plan.get('processes'),list) or len(plan['processes'])>128: raise ValueError('Invalid response plan')
    if any(not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) for sha in approved_hashes): raise ValueError('Invalid approved hash')
    if not isinstance(plan.get('expires_at'),(int,float)) or not time.time()<=plan['expires_at']<=time.time()+120:
        raise ValueError('Response plan expired; collect a fresh plan')
    root=psutil.Process(plan['root_pid'])
    if root.create_time()!=plan['root_creation']: raise ValueError('Root process identity changed')
    observed=[root,*root.children(recursive=True)]
    current={p.pid:p.create_time() for p in observed}
    parents={p.pid:p.ppid() for p in observed}
    identities=set()
    def depth(item):
        result=0; seen=set(); parent=parents.get(item['pid'])
        while parent in parents and parent not in seen:
            seen.add(parent); result+=1; parent=parents.get(parent)
        return result
    ordered=sorted(plan['processes'],key=depth,reverse=True)
    for item in ordered:
        if item['pid'] in identities or current.get(item['pid'])!=item['creation']: raise ValueError('Process tree changed; collect a fresh plan')
        identities.add(item['pid'])
    result=[]
    # Children are acted on before their parents; each action uses the existing
    # critical-process, ownership, identity and fresh-signature safeguards.
    for item in ordered:
        if item['sha256'] not in approved_hashes:
            result.append(dict(pid=item['pid'],state='Not approved')); continue
        try:
            detection=dict(path=item['path'],sha256=item['sha256'])
            result.append(service.terminate(item['pid'],item['creation'],detection))
        except Exception as error:
            result.append(dict(pid=item['pid'],state='Not terminated',reason=str(error)[:300]))
    service.audit('Process-tree response',str(result)[:4000])
    return dict(results=result,complete=bool(result) and all(r['state']=='Terminated' for r in result))

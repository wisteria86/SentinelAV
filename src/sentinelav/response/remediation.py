# Purpose: Stored, expiring, evidence-linked cleanup and conflict-checked manual recovery.
# Works with: data.contracts, monitoring.app_changes, response.remediation_backend,
#   response.remediation_resources, response.response
# Used by: lab.qualification.cleanup_fixtures, lab.qualification.guest_inventory, monitoring.change_monitor,
#   platform.remediation_broker

"""Stored, expiring, evidence-linked cleanup and conflict-checked manual recovery."""
import base64
import ctypes
import hashlib
import os
from pathlib import Path
import time
import uuid
import xml.etree.ElementTree as ET
from sentinelav.data.contracts import fingerprint
from sentinelav.monitoring.app_changes import WindowsInventory,powershell,RUN_KEYS
from sentinelav.response.response import ResponseService,checked_path,locked_file,delete_locked
from .remediation_resources import command_paths,referenced_paths,task_disabled,effect_matches
from .remediation_backend import WindowsRemediationBackend

class Remediator:
    def __init__(self,journal,backend,verify,responder=None,verify_buffer=None):
        self.journal,self.backend,self.verify,self.responder=journal,backend,verify,responder
        self.verify_buffer=verify_buffer

    def verified_references(self,record):
        findings=[]
        for path in referenced_paths(record):
            identity=os.path.normcase(os.path.abspath(path))
            for finding in self.verify(path):
                # Directory arguments must not inherit detections from unrelated
                # descendants scanned by a recursive scanner entry point.
                if os.path.normcase(os.path.abspath(finding['path']))!=identity:continue
                digest=finding.get('sha256','')
                if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise ValueError('Invalid fresh detection identity')
                findings.append(finding)
        return findings

    def plan(self,change_ids,mode='cleanup',with_related=True):
        if mode not in ('cleanup','restore') or not change_ids or len(set(change_ids))!=len(change_ids) or len(change_ids)>64:raise ValueError('Invalid remediation request')
        actions=[]
        for identity in change_ids:
            record=self.journal.change(identity);target=record['resource']
            current=self.backend.read(target)
            if fingerprint(current)!=record['after_hash']:raise ValueError('Change conflicts with current state; refresh the inventory')
            if mode=='restore':
                if not record['baseline_available'] or record['before'] is None:raise ValueError('No recorded before-state is available')
                if target['kind'] in ('setting_file','startup_file') and record['before'].get('exists'):
                    if self.verify_buffer is None:raise ValueError('Fresh recovery snapshot inspection required')
                    content=base64.b64decode(record['before']['content'],validate=True)
                    if self.verify_buffer(content):raise ValueError('Recorded previous content matches a current threat signature; restore refused')
                if target['kind']=='service' and any(record['before'].get(key)!=current.get(key) for key in ('account','display_name','service_type')):
                    raise ValueError('Service identity/account changes require an administrator review; no partial restoration is called complete')
                prior={**record,'after':record['before']}
                if target['kind'] not in ('setting_file','startup_file') and any(self.verify(path) for path in referenced_paths(prior)):raise ValueError('Recorded previous state references a detected threat; restoration refused')
                findings=[];action='restore'
            else:
                findings=self.verified_references(record)
                if not findings:raise ValueError('No fresh malicious file reference verified for this change')
                action='quarantine' if target['kind']=='startup_file' else 'disable'
                if target['kind']=='setting_file':raise ValueError('Configuration cleanup requires a reviewed recorded baseline')
                if target['kind']=='service':
                    # Never disable a shared Windows host or protected installed app.
                    for path in referenced_paths(record):checked_path(path)
            actions.append(dict(change_id=identity,resource=target,action=action,expected=current,
                desired=record['before'] if mode=='restore' else None,evidence=findings))
        graph=dict(schema=1,nodes=[],edges=[])
        for item in actions:
            graph['nodes'].append(dict(id=item['change_id'],kind='change',resource=item['resource']))
            for finding in item['evidence']:
                if not any(node['id']==finding['sha256'] for node in graph['nodes']):
                    graph['nodes'].append(dict(id=finding['sha256'],kind='detected_file',path=finding['path']))
                graph['edges'].append(dict(source=item['change_id'],target=finding['sha256'],relationship='references freshly detected file',attribution='Reference verified; creator attribution not implied'))
        if mode=='cleanup' and with_related:
            files={os.path.normcase(d['path']):d for action in actions for d in action['evidence']}
            terminations=[];quarantines=[]
            for detection in files.values():
                target=dict(kind='file',id=detection['sha256'],path=str(checked_path(detection['path'])))
                current=self.backend.read(target)
                if current.get('sha256')!=detection['sha256']:raise ValueError('Related file identity changed')
                if not any(node['id']==detection['sha256'] for node in graph['nodes']):graph['nodes'].append(dict(id=detection['sha256'],kind='detected_file',path=target['path']))
                if not any(a['action']=='quarantine' and a['resource'].get('path')==target['path'] for a in actions):
                    quarantines.append(dict(change_id='file-'+detection['sha256'],resource=target,action='quarantine',expected=current,desired=None,evidence=[detection]))
                import psutil
                for proc in psutil.process_iter(['pid','create_time','exe','username']):
                    info=proc.info
                    if not info.get('exe') or info.get('username')!=psutil.Process().username() or proc.pid in (os.getpid(),os.getppid(),0,4):continue
                    if os.path.normcase(str(Path(info['exe']).resolve()))!=os.path.normcase(target['path']):continue
                    process=dict(kind='process',id=f"{proc.pid}:{info['create_time']}",pid=proc.pid,creation=info['create_time'])
                    terminations.append(dict(change_id='process-'+process['id'],resource=process,action='terminate',expected=self.backend.read(process),desired=None,evidence=[detection]))
            # Disable respawn points, then stop verified images, then quarantine payloads.
            startup=[a for a in actions if a['action']=='quarantine']
            actions=[a for a in actions if a['action']!='quarantine']+terminations+startup+quarantines
        plan=dict(schema=1,id=uuid.uuid4().hex,kind='RemediationPlan',created=time.time(),expires=time.time()+120,incident_graph=graph,
            mode=mode,actions=actions,state='Planned',automatic=False)
        self.journal.operation(plan);return plan

    def execute(self,identity,approved=False):
        with self.journal.exclusive():return self._execute(identity,approved)

    def _execute(self,identity,approved=False):
        plan=self.journal.get_operation(identity)
        if not approved or plan['state']!='Planned' or time.time()>plan['expires']:raise ValueError('Fresh explicit approval is required for this plan')
        plan['state']='Executing';plan['results']=[];self.journal.operation(plan)
        for item in plan['actions']:
            result=dict(change_id=item['change_id'],state='Pending',resource=item['resource'])
            plan['results'].append(result);self.journal.operation(plan)
            try:
                current=self.backend.read(item['resource'])
                if fingerprint(current)!=fingerprint(item['expected']):raise ValueError('Conflict: resource changed after approval')
                if plan['mode']=='cleanup':
                    fresh=self.verified_references(dict(resource=item['resource'],after=current))
                    if not fresh or {d['sha256'] for d in fresh}!={d['sha256'] for d in item['evidence']}:raise ValueError('Threat evidence changed')
                elif item['action']=='restore':
                    desired=item['desired']
                    if item['resource']['kind'] in ('setting_file','startup_file') and desired.get('exists'):
                        if self.verify_buffer is None:raise ValueError('Fresh recovery inspection unavailable')
                        if self.verify_buffer(base64.b64decode(desired['content'],validate=True)):
                            raise ValueError('Recovery content is now detected; restoration refused')
                    elif any(self.verify(path) for path in referenced_paths(dict(resource=item['resource'],after=desired))):
                        raise ValueError('Previous configuration now references a threat; restoration refused')
                result['state']='Applying';self.journal.operation(plan)
                if item['action']=='terminate':
                    if self.responder is None:raise ValueError('Process response unavailable')
                    result['process']=self.responder.terminate(item['resource']['pid'],item['resource']['creation'],fresh[0])
                elif item['action']=='quarantine':
                    if self.responder is None:raise ValueError('Quarantine service unavailable')
                    result['quarantine']=self.responder.quarantine_file(fresh[0])
                else:self.backend.apply(item['resource'],item['action'],item['desired'],expected=current)
                actual=self.backend.read(item['resource'])
                if not effect_matches(item['resource'],actual,'disable' if item['action'] in ('quarantine','terminate') else item['action'],item['desired']):raise ValueError('Post-action verification failed')
                result.update(state='Verified',after=actual)
            except Exception as error:result.update(state='Unresolved',reason=str(error))
            self.journal.operation(plan)
        verified=sum(r['state']=='Verified' for r in plan['results'])
        plan['state']=('Verified removal within supported scope' if plan['mode']=='cleanup' else 'Restoration verified') if verified==len(plan['results']) else ('Partially remediated—specific remnants remain' if verified else 'Action failed or requires additional authorization')
        if plan['mode']=='cleanup':
            try:plan['verification']=self.backend.verify_incident(plan)
            except Exception as error:plan['verification']=dict(complete=False,remnants=[],omissions=[str(error)])
            # Disabling persistence alone is not removal of its payload. This
            # also protects narrowly scoped elevated and automatic sub-plans.
            files={os.path.normcase(d['path']):d for item in plan['actions'] for d in item['evidence']}
            for detection in files.values():
                target=dict(kind='file',id=detection['sha256'],path=detection['path'])
                try:
                    current=self.backend.read(target)
                    if not current.get('exists'):continue
                    fresh=self.verified_references(dict(resource=target,after=current))
                    plan['verification']['complete']=False
                    if fresh:plan['verification']['remnants'].append(dict(resource=target,reason='Detected incident payload remains'))
                    else:plan['verification']['omissions'].append('Incident path still exists with changed or no-longer-matching evidence: '+target['path'])
                except Exception as error:
                    plan['verification']['complete']=False;plan['verification']['omissions'].append(str(error))
            if not plan['verification']['complete'] and verified:
                plan['state']='Partially remediated—specific remnants remain'
        plan['kind']='RemediationReceipt';self.journal.operation(plan);return plan

    def reconcile(self):
        with self.journal.exclusive():return self._reconcile()

    def _reconcile(self):
        results=[]
        # Finish enumeration before changing SQLite rows or protected files.
        for plan in list(self.journal.recovery_operations()):
            if plan.get('state')!='Executing':continue
            by_id={r['change_id']:r for r in plan.get('results',[])}
            recovered=[]
            for item in plan['actions']:
                result=by_id.get(item['change_id'])
                if result is None:
                    result=dict(change_id=item['change_id'],resource=item['resource'],state='Skipped',reason='Interrupted before this action was journalled; not replayed')
                elif result['state']=='Pending':
                    result.update(state='Skipped',reason='Interrupted before application; not replayed')
                if result and result['state']=='Applying':
                    try:
                        actual=self.backend.read(item['resource'])
                        action='disable' if item['action'] in ('quarantine','terminate') else item['action']
                        result.update(state='Verified' if effect_matches(item['resource'],actual,action,item['desired']) else 'Unresolved',after=actual,
                            reason='Observed after interruption; no side effect replayed')
                    except Exception as error:result.update(state='Unresolved',reason=str(error))
                recovered.append(result)
            plan['results']=recovered
            plan['verification']=dict(complete=False,remnants=[],omissions=['Interrupted execution requires a fresh incident review; no removal claim'])
            plan['state']='Interrupted—review required';plan['kind']='RemediationReceipt'
            self.journal.operation(plan);results.append(plan)
        return results

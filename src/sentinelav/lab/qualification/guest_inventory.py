# Purpose: Approved encrypted corpus and narrowly scoped remediation fixtures in guests.
# Works with: data.change_journal, data.storage, detection.inspection, lab.qualification.backends,
#   lab.qualification.cleanup_fixtures
# Used by: lab.qualification.guest, tests.unit.test_harness_lifecycle

"""Approved encrypted corpus and narrowly scoped remediation fixtures in guests."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from .contracts import identifier


from .corpus_inputs import unpack, scan_rows
from .cleanup_fixtures import resources, inspect_resources


def execute(context,root):
    from .guest_context import BASE,options
    from sentinelav.paths import RESOURCE_ROOT
    from sentinelav.data.storage import Store
    from sentinelav.response.response import ResponseService
    case=context['case'];inv=case['parameters']['inventory_data'];kind=case['parameters'].get('inventory',case['action'])
    if case['action']=='comparison':
        from sentinelav.lab.removal_benchmark import compare
        if 'cases' not in inv or 'trials' not in inv:raise FileNotFoundError('Matched Defender trial metadata and independent ground truth required')
        result=compare(dict(schema=1,cases=inv['cases']),inv['trials'])
        return dict(comparison=result,superiority_gate_passed=result['superiority_gate_passed'],qualification_evidence=False),True
    if context.get('phase')=='verify_reboot':
        trial=BASE/'Trials'/identifier(context['trial_id']);state=json.loads((trial/'state.json').read_text())
        current=inspect_resources(state['artifacts'])
        remaining=sum(r['exists'] for r in current if r['resource'].get('malicious'))
        damage=sum(old['identity']!=new['identity'] or old['exists']!=new['exists'] for old,new in zip(state['protected'],[r for r in current if not r['resource'].get('malicious')]))
        return dict(malicious_remnants=remaining,protected_controls_changed=damage,current=current,verification_only=True),True
    trial=BASE/'Trials'/identifier(context['trial_id']) if case['action']=='recurrence' else root/'inventory'
    trial.mkdir(parents=True,exist_ok=False);entries=unpack(context,trial)
    if kind in ('independent-raw-corpus','legitimate-app-workflows','automatic-action-controls'):
        samples,detections=scan_rows(context,root,entries)
        if kind=='independent-raw-corpus':return dict(samples=samples,qualification_evidence=bool(samples) and all(r.get('independently_selected') and r.get('declared_format')=='PE' for r in samples)),True
        # Inspection alone is never a substitute for exercising actual actions
        # or completing installation/update workflows.
        if kind=='automatic-action-controls':
            policy=inv.get('automatic_policy')
            if not isinstance(policy,dict) or policy.get('enabled') is not True:raise FileNotFoundError('Explicit frozen active automatic-response policy required')
            positive=inv.get('positive_control')
            if not isinstance(positive,dict) or positive.get('label')!='malware':raise FileNotFoundError('A separately approved positive action control is required; disabled policies cannot qualify')
            from sentinelav.response.auto_response import AutoResponder,eligibility
            from .guest_context import options
            import time
            data=root/'automatic';data.mkdir();store=Store(data/'sentinelav.db')
            policy={**policy,'roots':[str(trial)]}
            positive_finding=next((d for d in detections if d.get('sha256')==positive['sha256']),None)
            if not positive_finding or not eligibility(positive_finding,policy)[0]:raise FileNotFoundError('Positive control is not eligible under the frozen product policy')
            store.set('inspection_options',options(case['mode']));store.set('auto_response',policy)
            events=[];responder=AutoResponder(data,RESOURCE_ROOT,policy,events.append)
            try:
                deadline=time.monotonic()+10
                while not responder.ready and not responder.error and time.monotonic()<deadline:time.sleep(.1)
                if not responder.ready:raise RuntimeError('Automatic policy worker unavailable')
                responder.submit(positive_finding)
                for finding in detections:
                    if finding is not positive_finding:responder.submit(finding)
                # Wait for submitted eligible detections and response failures;
                # rate limits/cooldowns are product behavior, never overridden.
                deadline=time.monotonic()+60
                while time.monotonic()<deadline and (not responder.queue.empty() or responder.attempts):
                    if responder.queue.empty() and any(e['kind'] in ('Automatic quarantine completed','Automatic response failed','Automatic response deferred') for e in events):break
                    time.sleep(.2)
            finally:responder.close()
            records=store.quarantine();false_actions=0
            positive_verified=any(q['sha256']==positive['sha256'] and q['state']=='Quarantined' for q in records)
            complete=positive_verified and not any(e['kind']=='Automatic response backlog' for e in events)
            benign_samples=[]
            for r,e in zip(samples,entries):
                if e['label']!='benign':continue
                changed=not Path(e['path']).exists() or hashlib.sha256(Path(e['path']).read_bytes()).hexdigest()!=e['sha256']
                acted=changed or any(q['sha256']==e['sha256'] for q in records)
                r.update(automatic_action_exercised=complete,false_action=acted,automatic_policy_id=inv.get('automatic_policy_digest',__import__('hashlib').sha256(json.dumps(inv['automatic_policy'],sort_keys=True).encode()).hexdigest()))
                false_actions+=acted;benign_samples.append(r)
            store.db.close()
            return dict(samples=benign_samples,qualification_evidence=complete,positive_control_verified=positive_verified,false_actions=false_actions,response_events=events,action_records=records),complete
        workflows=inv.get('workflows',[])
        if not workflows:raise FileNotFoundError('Approved legitimate application installation/update workflows required')
        from sentinelav.lab.runtime_job import run_job,AUTHORIZATION
        from .guest_context import guard
        outcomes=[]
        for w in workflows:
            target=next((e for e in entries if e['sha256']==w['sha256'] and e['label']=='benign'),None)
            if not target:raise ValueError('Workflow must select reviewed benign specimen')
            result=run_job(dict(schema=1,authorization=AUTHORIZATION,sample=target['path'],sha256=target['sha256'],seconds=min(600,int(w.get('seconds',120))),process_limit=32,arguments=w.get('arguments',[])),_guest_check=lambda:guard(context))
            details=json.loads(Path(result['report']).read_text());assertions=[]
            for expected in w.get('expected_files',[]):
                path=Path(os.path.expandvars(expected['path']))
                permitted=(Path(os.environ['ProgramFiles']),trial,Path(os.environ['LOCALAPPDATA'])/'Programs')
                if not any(path.is_relative_to(p) for p in permitted):raise ValueError('Workflow assertions must use approved application/test locations')
                exists=path.is_file();matches=exists==expected.get('exists',True)
                if exists and expected.get('sha256'):matches=matches and hashlib.sha256(path.read_bytes()).hexdigest()==expected['sha256']
                assertions.append(matches)
            outcomes.append(dict(runtime=result,exit_code=details.get('root_exit_code'),assertions=assertions,
                passed=bool(assertions) and all(assertions) and details.get('root_exit_code')==w.get('expected_exit_code',0)))
        return dict(samples=samples,workflows=outcomes,qualification_evidence=all(r['passed'] for r in outcomes),failures=sum(not r['passed'] for r in outcomes)),True
    artifacts=resources(inv,trial)
    if not artifacts:raise FileNotFoundError('Independent expected-artifact ground truth required')
    from sentinelav.data.change_journal import ChangeJournal
    from sentinelav.monitoring.app_changes import ChangeTracker,WindowsInventory
    journal=ChangeJournal(root/'changes');tracker=ChangeTracker(journal,WindowsInventory())
    if case['parameters'].get('scenario')=='tracked':tracker.poll()
    import winreg
    malicious=next((e for e in entries if e['label']=='malware'),None)
    if not malicious:raise ValueError('Remediation fixture needs an approved malicious file')
    for a in artifacts:
        if a['kind']=='registry':
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,a['key']) as k:
                try:winreg.QueryValueEx(k,a['name'])
                except FileNotFoundError:pass
                else:raise ValueError('Fixture would overwrite existing autorun')
                winreg.SetValueEx(k,a['name'],0,winreg.REG_SZ,'"'+malicious['path']+'"')
        elif a['kind']=='file':
            p=Path(a['path']);p.parent.mkdir(parents=True,exist_ok=True)
            if p.exists():raise ValueError('Fixture would overwrite existing file')
            p.write_bytes(Path(malicious['path']).read_bytes() if a.get('malicious') else b'protected harmless control')
        else:
            from .guest_context import ps
            from .backends import quote
            if not a.get('malicious'):raise ValueError('Task/service protected controls must be supplied by harmless workflow fixtures')
            if a['kind']=='task':
                ps("$n="+quote(a['name'])+";if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue){throw 'Task fixture collision'};$a=New-ScheduledTaskAction -Execute "+quote(malicious['path'])+";$t=New-ScheduledTaskTrigger -AtLogOn;Register-ScheduledTask -TaskName $n -Action $a -Trigger $t -Force|Out-Null")
            else:
                ps("$n="+quote(a['name'])+";if(Get-Service -Name $n -ErrorAction SilentlyContinue){throw 'Service fixture collision'};& sc.exe create $n binPath= "+quote('"'+malicious['path']+'"')+" start= auto obj= 'NT AUTHORITY\\LocalService'|Out-Null;if($LASTEXITCODE){throw 'Service fixture creation failed'}")
    initial=inspect_resources(artifacts);protected=[r for r in initial if not r['resource'].get('malicious')]
    # Inventory before product cleanup is explicit pre-existing state, never a
    # fabricated historical before-value or an automatically trusted baseline.
    from sentinelav.response.remediation import Remediator,WindowsRemediationBackend
    tracker.poll()
    store=Store(root/'response/history.db');store.set('inspection_options',options(case['mode']))
    responder=ResponseService(store,RESOURCE_ROOT)
    from sentinelav.detection.inspection import IsolatedScanner
    def verify(path):
        scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',options=options(case['mode']))
        try:return scanner.scan([Path(path)],lambda:False,lambda *a:None).get('detections',[])
        finally:scanner.close()
    errors=[]
    try:
        remediator=Remediator(journal,WindowsRemediationBackend(),verify,responder)
        changes=[r['id'] for r in journal.changes() if any((('\\'+a['name']) if a['kind']=='task' else a.get('name'))==r.get('resource',{}).get('name') for a in artifacts if a['kind'] in ('registry','task','service'))]
        if changes:
            try:
                plan=remediator.plan(changes);remediator.execute(plan['id'],approved=True)
            except Exception as e:errors.append(type(e).__name__+': '+str(e)[:300])
        for entry in entries:
            for finding in verify(entry['path']):
                try:responder.quarantine_file(finding)
                except Exception as e:errors.append(type(e).__name__+': '+str(e)[:300])
        for a in artifacts:
            if a['kind']=='file' and a.get('malicious'):
                for finding in verify(a['path']):
                    try:responder.quarantine_file(finding)
                    except Exception as e:errors.append(type(e).__name__+': '+str(e)[:300])
    finally:store.db.close();journal.close()
    current=inspect_resources(artifacts);remaining=sum(r['exists'] for r in current if r['resource'].get('malicious'))
    damage=sum(old['identity']!=new['identity'] or old['exists']!=new['exists'] for old,new in zip(protected,[r for r in current if not r['resource'].get('malicious')]))
    (trial/'state.json').write_text(json.dumps(dict(artifacts=artifacts,protected=protected)))
    return dict(qualification_evidence=not errors and remaining==0 and damage==0,malicious_remnants=remaining,
        protected_controls_changed=damage,errors=errors,failures=len(errors),initial=initial,current=current,trial_id=context['trial_id']),True

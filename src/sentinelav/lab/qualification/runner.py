# Purpose: One-click evaluator. All product mutations remain in registered lab guests.
# Works with: lab.qualification.backends, lab.qualification.catalog, lab.qualification.comparison,
#   lab.qualification.contracts, lab.qualification.evaluation_environment
# Used by: tests.unit.test_harness_lifecycle, tools.evaluation.critical_harness

"""One-click evaluator. All product mutations remain in registered lab guests."""
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time
import uuid
from .contracts import CaseDefinition,CaseResult,Observation,digest
from .catalog import suite
from .store import RunStore,new_path,exclusive,write_json
from .reporting import render,redact
from .scoring import score_case
from .backends import Sandbox,HyperV,Blocked,reconcile,powershell,quote,run
from sentinelav.workspace import Workspace,unlinked


from .evaluation_environment import source_identity, package_identity, freeze_package, preflight, sandbox_storage_problem, configure_work_temporary, build, resource_identity, selfcheck, transfer


class Runner:
    """The one-click evaluation runner: freezes the code and package, builds the case list, runs each
    case in its backend, and writes the reports.
    """
    def __init__(self,project,profile='critical',cancelled=lambda:False,progress=print,resume=None,preflight_only=False,release_soak=False,host_only=False,queue_progress=lambda done,total:None):
        """Remember the project, the profile to run, callbacks, and options (resume an earlier run,
        preflight only, host only, 7-day soak).
        """
        self.project=unlinked(project);self.work=unlinked(Path(os.environ.get('SENTINELAV_WORK_ROOT','F:/SentinelAV-Work')))
        self.profile=profile;self.cancelled=cancelled;self.progress=progress;self.resume=resume
        self.preflight_only=preflight_only;self.release_soak=release_soak;self.path=None
        self.host_only=host_only
        self.queue_progress=queue_progress

    def run(self):
        """Run the evaluation while holding the evaluation lock, recording any interruption in the run
        folder.
        """
        logs=unlinked(self.project/'logs');logs.mkdir(exist_ok=True)
        with exclusive(logs/'.evaluation.lock'):
            try:return self._run()
            except BaseException as e:
                if self.path:
                    from .reporting import _text
                    write_json(self.path/'interruption.json',dict(schema=1,error=type(e).__name__,reason=redact(str(e))),True)
                    if not (self.path/'report.md').exists():
                        _text(self.path/'report.md','# SentinelAV evaluation — incomplete\n\nBootstrap/queue validation failed. No qualification pass is established.\n\n'+str(redact(str(e)))+'\n')
                raise

    def _run(self):
        """Do the actual run.

        A new run checks preflight problems, builds and freezes the package, records every version
        and inventory hash, and creates the case list. A resumed run refuses to continue if anything
        changed. Then each pending case is executed in a fresh, owned guest (or on the host),
        scored, and the guest is always disposed of afterwards. Returns (run folder, summary).
        """
        folder=unlinked(self.resume) if self.resume else new_path(self.project)
        if not folder.is_relative_to(self.project/'logs'):raise ValueError('Resume must be inside project logs')
        folder.mkdir(parents=True,exist_ok=bool(self.resume));self.path=folder
        self.progress('Checking workspace, disk reserves, dependencies and frozen source identity')
        problems=preflight(self.project,self.work);identity=source_identity(self.project)
        temporary=None
        try:temporary=configure_work_temporary(self.work)
        except (OSError,ValueError) as e:problems.append('F: temporary storage unavailable: '+str(e))
        if not self.resume:
            zoo_inventory=None
            if self.profile in ('zoo-static','zoo-quick','zoo-dev','zoo-holdout'):
                from .zoo_inventory import cases as zoo_cases,quick_cases,repository
                splits={'zoo-dev':'dev','zoo-holdout':'holdout'}
                zoo_inventory=quick_cases() if self.profile=='zoo-quick' else zoo_cases(splits.get(self.profile))
                if self.profile!='zoo-quick' and not (self.preflight_only or self.host_only):repository(self.work)
            from .bazaar_corpus import profile_cases
            zoo_inventory=profile_cases(self.profile,zoo_inventory)
            if not problems and not self.preflight_only:
                try:build(self.project,self.work,digest(dict(source=identity,resources=resource_identity(self.project))),self.cancelled,self.progress,folder)
                except Exception as e:problems.append('Build not verified: '+type(e).__name__+': '+str(e))
            exe=self.work/'builds/dist/SentinelAV/SentinelAV.exe'
            assets={}
            # The evaluator measures the frozen package, not mutable source assets.
            for p in (exe.parent/'_internal/analysis-data').glob('*'):
                if p.is_file() and p.suffix in ('.json','.npz'):assets[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
            versions=dict(source_sha256=identity,executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest() if exe.exists() else None,
                models=assets,os=platform.platform(),dependencies=digest(sorted((d.metadata['Name'],d.version) for d in importlib.metadata.distributions() if d.metadata['Name'])))
            versions.update(harness_protocol=1,scorer_sha256=hashlib.sha256(Path(__file__).with_name('scoring.py').read_bytes()).hexdigest())
            versions['execution_scope']='host-only' if self.host_only else 'full'
            receipt=self.work/'builds/qualification-build.json'
            built=json.loads(receipt.read_text()) if receipt.exists() else {}
            versions['build_source_verified']=bool(built.get('build_key')==digest(dict(source=identity,resources=resource_identity(self.project))) and built.get('executable_sha256')==versions['executable_sha256'])
            if not versions['build_source_verified']:problems.append('Packaged build is not attested to current source and resource identities')
            versions['package_manifest']=package_identity(exe.parent)
            versions['artifact_root']=str(freeze_package(self.work,exe.parent,versions['package_manifest'])) if not self.preflight_only else str(exe.parent)
            for name,path in [('hyperv_configuration',self.work/'lab/qualification/hyperv.json'),('collectors',self.work/'lab/qualification/support/manifest.json')]:
                versions[name]=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            from .inventories import frozen
            inventories=frozen(self.work)
            manifest=suite(uuid.uuid4().hex,self.profile,versions,inventories)
            if zoo_inventory is not None:manifest['cases']=zoo_inventory
            # Explicitly approved corpora expand to bounded, independently
            # accounted cases. The eight historical fixtures stay regression.
            expanded=[]
            for c in manifest['cases']:
                name=c['parameters'].get('inventory',c['action'])
                if name in inventories and c['action']=='inventory':
                    from .inventories import load_inventory
                    inv=load_inventory(self.work,name)
                    if inv.get('files'):
                        for offset in range(0,len(inv['files']),32):
                            n=json.loads(json.dumps(c));n['id']+='-'+str(offset//32);n['parameters'].update(offset=offset,count=32)
                            expanded.append(n)
                        continue
                expanded.append(c)
            manifest['cases']=expanded
            if self.profile=='soak':
                manifest['cases']=[c for c in manifest['cases'] if c['id'] in ('scorer-known-answers','vm-soak-24h')]
                if self.release_soak:manifest['cases'][-1].update(id='vm-soak-7d',seconds=604800)
                manifest['budgets']['total_seconds']=manifest['cases'][-1]['seconds']+7200
            store=RunStore(folder,manifest)
        else:
            store=RunStore(folder)
            if store.manifest['versions']['source_sha256']!=identity:raise ValueError('Source changed; start a new run instead of mixing versions')
            if store.manifest['versions'].get('execution_scope')!=('host-only' if self.host_only else 'full'):raise ValueError('Execution scope changed; start a new run')
            for name,path in [('hyperv_configuration',self.work/'lab/qualification/hyperv.json'),('collectors',self.work/'lab/qualification/support/manifest.json')]:
                current=hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                if store.manifest['versions'].get(name)!=current:raise ValueError('Lab configuration changed; start a new run instead of mixing environments')
            if store.manifest['versions'].get('package_manifest')!=package_identity(Path(store.manifest['versions']['artifact_root'])):raise ValueError('Frozen packaged files changed; resume refused')
            for p in folder.glob('attempts/*/*/owner.json'):reconcile(self.project,self.work,p.parent)
            store.recover()
        try:
            write_json(folder/'preflight.json',dict(schema=1,problems=problems,preflight_only=self.preflight_only,host_only=self.host_only,
                work_root=str(self.work),temporary_root=str(temporary) if temporary else None,sandbox_storage_problem=sandbox_storage_problem()),True)
            total=len(store.manifest['cases']);completed=len(store.results())
            self.queue_progress(completed,total)
            render(store);began=time.monotonic()
            for case in store.manifest['cases']:
                if case['id'] not in store.pending():continue
                if self.cancelled() or time.monotonic()-began>store.manifest['budgets']['total_seconds']:break
                if case['action']=='zoo_static' and (problems or self.preflight_only or self.host_only or sandbox_storage_problem()):
                    self.progress('Zoo batches paused by preflight; pending batches preserved')
                    break
                used=sum(p.stat().st_size for p in folder.rglob('*') if p.is_file())
                if used+32*1024**2>store.manifest['budgets']['log_limit_bytes']:
                    write_json(folder/'storage-budget.json',dict(reason='Run log budget reached; pending cases preserved',bytes=used),True);break
                attempt=store.start(case['id']);backend=None
                unit='Zoo batch' if case['action']=='zoo_static' else 'Case'
                self.progress(f'{unit} {completed+1} of {total} · {case["id"]}')
                try:
                    if time.monotonic()-began>store.manifest['budgets']['total_seconds']:raise Blocked('Run time budget exhausted; case not executed')
                    if case['backend']!='host' and problems:raise Blocked('; '.join(problems))
                    if self.host_only and case['backend']!='host':raise Blocked('Host-only validation requested; no guest or specimen execution')
                    if self.preflight_only and case['action']!='selfcheck':raise Blocked('Preflight-only run; no product/guest tests executed')
                    if case['backend']=='sandbox' and sandbox_storage_problem():raise Blocked(sandbox_storage_problem())
                    if case['backend']=='host':
                        if case['action']=='selfcheck':measurements=selfcheck()
                        elif case['action']=='feature_regression':
                            from .features import regression
                            measurements=regression(self.work,self.cancelled,self.progress,Path(store.manifest['versions']['artifact_root'])/'_internal')
                        elif case['action']=='feature_qualification':
                            from .inventories import feature_qualification
                            from .inventories import load_inventory
                            name='temporal-'+case['parameters']['format'];inv=load_inventory(self.work,name)
                            if store.manifest['inventories'].get(name,{}).get('sha256')!=digest(inv):raise ValueError('Qualification inventory changed during run')
                            measurements=feature_qualification(self.work,case['parameters']['format'],self.cancelled,self.progress,Path(store.manifest['versions']['artifact_root'])/'_internal')
                        elif case['action']=='family_qualification':
                            from .inventories import feature_qualification,load_inventory
                            records=[]
                            for fmt in ('Win32','Win64','Dot_Net'):
                                inv=load_inventory(self.work,'temporal-'+fmt)
                                if not inv.get('family_disjoint'):raise Blocked('Family-disjoint inventories and training-family exclusions required')
                                if store.manifest['inventories'].get('temporal-'+fmt,{}).get('sha256')!=digest(inv):raise ValueError('Family inventory changed during run')
                                records.append(feature_qualification(self.work,fmt,self.cancelled,self.progress,Path(store.manifest['versions']['artifact_root'])/'_internal'))
                            measurements=dict(qualification_evidence=all(r['family_disjoint'] for r in records),formats=records)
                        else:raise ValueError('Unknown host action')
                        write_json(attempt/'measurements.json',redact(measurements))
                        observation=asdict(Observation(case['id'],digest(store.manifest['versions']),measurements,[str((attempt/'measurements.json').relative_to(folder))],True))
                    else:
                        if case['action']=='soak' and self.profile!='soak':
                            from .comparison import import_soak
                            imported=import_soak(store.manifest,folder.parent,case)
                            if imported:
                                write_json(attempt/'imported-evidence.json',imported)
                                observation=imported['observation'];observation['evidence']=[str((attempt/'imported-evidence.json').relative_to(folder))]
                                result=asdict(score_case(case,observation,store.manifest['versions']));write_json(attempt/'result.json',result);store.finish(result)
                                completed+=1;self.queue_progress(completed,total);render(store);continue
                            raise Blocked('Run Soak --release-soak for compatible seven-day VM evidence; completed receipts are imported automatically')
                        if case['action'] in ('inventory','recurrence','comparison'):
                            from .inventories import load_inventory
                            inventory=load_inventory(self.work,case['parameters'].get('inventory',case['action']))
                            name=case['parameters'].get('inventory',case['action'])
                            if store.manifest['inventories'].get(name,{}).get('sha256')!=digest(inventory):raise ValueError('Approved inventory changed during run')
                            case={**case,'parameters':{**case['parameters'],'inventory_data':inventory}}
                        cls=Sandbox if case['backend']=='sandbox' else HyperV
                        backend=cls(self.project,self.work,attempt,self.cancelled,self.progress)
                        backend.case_action=case['action']
                        backend.package_manifest=store.manifest['versions'].get('package_manifest',{})
                        backend.package_root=Path(store.manifest['versions']['artifact_root'])
                        quick=case['id']=='zoo-quick'
                        if quick:backend.case_action='zoo_quick'
                        elif case['action']=='zoo_static':backend.zoo_parameters=case['parameters']
                        if case['parameters'].get('inventory_data',{}).get('files'):
                            backend.inventory_name=case['parameters'].get('inventory',case['action']);backend.batch_offset=case['parameters'].get('offset',0);backend.batch_count=case['parameters'].get('count',32)
                        self.progress('Preparing a fresh '+('Windows Sandbox' if case['backend']=='sandbox' else 'Hyper-V guest'))
                        context=backend.start()
                        if case['action'] in ('live','telemetry','recovery','soak'):backend.setup_telemetry()
                        context.update(case=case,nonce=uuid.uuid4().hex,versions_digest=digest(store.manifest['versions']),performance_budgets=store.manifest['budgets']['performance'])
                        if case['parameters'].get('inventory_data',{}).get('files'):
                            original=case['parameters']['inventory_data'];offset=case['parameters'].get('offset',0);count=case['parameters'].get('count',32)
                            context['case']={**case,'parameters':{**case['parameters'],'offset':0,'inventory_data':{**original,'files':original['files'][offset:offset+count]}}}
                        context['trial_id']=uuid.uuid4().hex
                        if backend.inventory_name:
                            import base64
                            from sentinelav.response.response import dpapi
                            key=unlinked(self.work/'lab/qualification/corpora'/backend.inventory_name/'transfer-key.dpapi')
                            context['inventory_key']=base64.b64encode(dpapi(key.read_bytes(),True)).decode()
                        if quick or case['action'] in ('live','inspect','benign'):context.update(transfer(self.work,case))
                        if case['action']=='zoo_static':self.progress(f'Scanning Zoo batch {completed+1} of {total} inside Sandbox')
                        observation=backend.execute(context)
                        if case['action']=='zoo_static':
                            from .zoo_reporting import validate_batch
                            validate_batch(case,observation['measurements'])
                        if case['action']=='recurrence':
                            checks=[]
                            for _ in range(2):
                                reboot=backend.reboot();context['phase']='verify_reboot';context['nonce']=uuid.uuid4().hex
                                checked=backend.execute(context);checks.append(dict(reboot=reboot,measurements=checked['measurements']))
                            observation['measurements']['reboot_checks']=checks
                            observation['measurements']['reboots_verified']=sum(c['reboot']['verified'] for c in checks)
                            observation['measurements']['malicious_remnants']=max([observation['measurements'].get('malicious_remnants',0)]+[c['measurements']['malicious_remnants'] for c in checks])
                            observation['measurements']['protected_controls_changed']=max([observation['measurements'].get('protected_controls_changed',0)]+[c['measurements']['protected_controls_changed'] for c in checks])
                        # References to guest-only journals must never be presented
                        # as host evidence. Preserve the returned projection first.
                        write_json(attempt/'observation.json',redact(observation))
                        observation['evidence']=[str((attempt/'observation.json').relative_to(folder))]
                    result=asdict(score_case(case,observation,store.manifest['versions']))
                except (Blocked,FileNotFoundError) as e:result=asdict(CaseResult(case['id'],'blocked',str(e)))
                except InterruptedError as e:result=asdict(CaseResult(case['id'],'inconclusive',str(e)))
                except Exception as e:result=asdict(CaseResult(case['id'],'failed',type(e).__name__+': '+str(e)))
                finally:
                    if backend:
                        self.progress('Closing the test guest and saving evidence')
                        try:backend.dispose()
                        except Exception as e:
                            result=asdict(CaseResult(case['id'],'failed','OWNED GUEST DISPOSAL UNVERIFIED: '+type(e).__name__+': '+str(e)))
                            self.cancelled=lambda:True
                result=redact(result);write_json(attempt/'result.json',result)
                if case['action']=='zoo_static' and self.cancelled() and result['status']=='inconclusive':
                    store.recover()
                    break
                store.finish(result)
                completed+=1;self.queue_progress(completed,total)
                summary=render(store);self.progress(case['id']+': '+result['status'])
            summary=render(store)
            write_json(folder/'disposal.json',dict(schema=1,receipts=[str(p.relative_to(folder)) for p in folder.glob('attempts/*/*/disposal.json')],
                pending=[str(p.relative_to(folder)) for p in folder.glob('attempts/*/*/owner.json') if not (p.parent/'disposal.json').exists()]),True)
            self.progress('Report: '+str(folder/'report.md'));return folder,summary
        finally:store.close()

# Purpose: Freeze build identities, check storage, and prepare evaluation prerequisites.
# Works with: lab.qualification.backends, lab.qualification.contracts, lab.qualification.scoring,
#   lab.qualification.store, response.response
# Used by: lab.qualification.runner

"""One-click evaluator. All product mutations remain in registered lab guests."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid
from .contracts import CaseDefinition, Observation, digest
from .store import write_json
from .scoring import score_case
from .backends import powershell, quote
from sentinelav.workspace import Workspace,unlinked


def source_identity(project):
    paths=[]
    for folder in ('src','resources','packaging','native','scripts','tests/unit'):
        root=project/folder
        for p in root.rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts and not any(x in p.parts for x in ('obj','bin','signature-data','analysis-data')):
                if p.suffix.lower() in ('.py','.ps1','.cmd','.cs','.csproj','.spec','.iss','.json','.yar','.txt'):
                    unlinked(p);paths.append(p)
    for name in ('pyproject.toml','build.ps1','app.py','Run-SentinelAV-Tests.cmd','tools/evaluation/launch_critical.py','tools/evaluation/critical_harness.py','tools/evaluation/setup_lab_telemetry.py'):paths.append(project/name)
    return digest({p.relative_to(project).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)})


def package_identity(root):
    files={}
    if not root.exists():return files
    for p in sorted(root.rglob('*')):
        unlinked(p)
        if p.is_file():
            h=hashlib.sha256()
            with p.open('rb') as f:
                while chunk:=f.read(1024*1024):h.update(chunk)
            files[p.relative_to(root).as_posix()]=h.hexdigest()
            if len(files)>8192:raise ValueError('Packaged file inventory limit exceeded')
    return files


def freeze_package(work,source,manifest):
    if not manifest:return source
    base=unlinked(work/'builds/evaluation-packages');base.mkdir(parents=True,exist_ok=True)
    target=base/digest(manifest)
    if not target.exists():
        staging=base/('staging-'+uuid.uuid4().hex);staging.mkdir()
        shutil.copytree(source,staging/'App')
        if package_identity(staging/'App')!=manifest:raise ValueError('Package changed while freezing reproducible build')
        write_json(staging/'package-manifest.json',manifest)
        staging.rename(target)
    if package_identity(target/'App')!=manifest:raise ValueError('Frozen build cache identity differs')
    return target/'App'


def preflight(project,work):
    problems=[]
    if os.name!='nt':problems.append('Windows required for guest backends')
    if shutil.disk_usage(Path(project.anchor)).free<2*1024**3:problems.append('Project report drive needs 2 GiB free for bounded logs and headroom; heavy work stays on the work drive')
    try:Workspace(work).check()
    except (OSError,ValueError) as e:problems.append(str(e))
    if not (project/'.venv/Scripts/python.exe').exists():problems.append('Project Python environment missing')
    return problems


def sandbox_storage_problem():
    system=Path(os.environ.get('SystemDrive','C:')+'/')
    if shutil.disk_usage(system).free<10*1024**3:
        return 'Windows Sandbox requires 10 GiB system-drive reserve; F: staging does not relocate its Windows-managed guest storage. Use an enrolled Hyper-V VM with its disks on F:.'
    return None


def configure_work_temporary(work):
    import tempfile
    temporary=Workspace(work).area('cache')/'qualification-temp'
    unlinked(temporary).mkdir(exist_ok=True)
    os.environ['TEMP']=os.environ['TMP']=str(temporary)
    os.environ['PYINSTALLER_CONFIG_DIR']=str(unlinked(work/'cache/PyInstaller'))
    tempfile.tempdir=str(temporary)
    return temporary


def build(project,work,identity,cancelled,progress,folder):
    receipt=work/'builds/qualification-build.json';exe=work/'builds/dist/SentinelAV/SentinelAV.exe'
    if receipt.exists() and exe.exists():
        old=json.loads(receipt.read_text())
        if old.get('build_key')==identity and old.get('executable_sha256')==hashlib.sha256(exe.read_bytes()).hexdigest():return
    progress('Building current source and installer; stale binaries are not evaluated')
    powershell('$env:PYTHONPATH='+quote(str(project/'src')+';'+str(project))+';& '+quote(project/'build.ps1')+' -Installer;if(!$?){exit 1}',1800,cancelled,folder/'build.log')
    write_json(receipt,dict(schema=1,build_key=identity,executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()),True)


def resource_identity(project):
    root=project/'resources';paths=list((root/'analysis-data').glob('*.json'))+list((root/'analysis-data').glob('*.npz'))
    from sentinelav.detection.definition_paths import signature_data_dir
    active=signature_data_dir(root)/'active.json'
    if active.exists():
        import re
        data=json.loads(active.read_text(encoding='utf-8-sig'));name=data.get('database','')
        if not re.fullmatch('hashes-[0-9a-f]{32}\\.sqlite',name):raise ValueError('Invalid signature database activation')
        paths.extend((active,active.parent/name))
    result={}
    for p in paths:
        unlinked(p);h=hashlib.sha256()
        with p.open('rb') as f:
            while chunk:=f.read(1024*1024):h.update(chunk)
        result[p.relative_to(root).as_posix()]=h.hexdigest()
    return result


def selfcheck():
    from .scoring import upper_bound
    versions=dict(engine='known-answer');case=asdict(CaseDefinition('known','harness','host','selfcheck',expected=dict(answer=True)))
    def obs(**kw):return asdict(Observation('known',digest(versions),dict(answer=True,**kw),['fixture'],True))
    if score_case(case,obs(),versions).status!='passed':raise AssertionError('Known good scorer case failed')
    if score_case(case,obs(false_actions=1),versions).status!='failed':raise AssertionError('False action accepted')
    incomplete=obs();incomplete['complete']=False
    if score_case(case,incomplete,versions).status!='inconclusive':raise AssertionError('Missing evidence accepted')
    bad=obs();bad['versions_digest']='0'*64
    try:score_case(case,bad,versions)
    except ValueError:pass
    else:raise AssertionError('Mixed build accepted')
    if upper_bound(0,30000)>.0001:raise AssertionError('Binomial safety gate incorrect')
    return dict(assertions_passed=True,known_answer_assertions=5)


def transfer(work,case):
    from sentinelav.response.response import dpapi
    import base64
    sample=case['parameters'].get('sample','')
    group=case['parameters'].get('group') or ('holdout' if sample in ('wannacryplus','gameover') else 'zeus' if sample in ('zeusbanking','gameoveralt') else 'base')
    folders={'base':'sealed-static-corpus','holdout':'sealed-static-holdout','zeus':'sealed-zeus-validation'}
    path=unlinked(work/'lab'/folders[group]/'transfer-key.dpapi')
    return dict(group=group,transfer_key=base64.b64encode(dpapi(path.read_bytes(),True)).decode())

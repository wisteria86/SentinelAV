# Purpose: Own Sandbox creation, connection, boundary checks, and disposal.
# Works with: lab.qualification.backend_control, lab.qualification.backend_transport, lab.qualification.store,
#   workspace
# Used by: lab.qualification.backend_hyperv, lab.qualification.backend_recovery, lab.qualification.backends

"""Owned guest lifecycle and bounded metadata transport. No writable host share."""
import base64
import json
from pathlib import Path
import time
import uuid
from .store import write_json
from sentinelav.workspace import unlinked
from .backend_control import run,powershell,quote,Blocked
from .backend_transport import GuestTransportMixin

class Sandbox(GuestTransportMixin):
    """Evaluation backend that runs each case in a fresh Windows Sandbox guest it owns and always
    disposes of.
    """
    def __init__(self,project,work,attempt,cancelled,progress):
        """Remember the project and work folders, the attempt folder for logs and receipts, and the
        cancel/progress callbacks.
        """
        self.project=Path(project);self.work=Path(work);self.attempt=Path(attempt);self.cancelled=cancelled;self.progress=progress
        self.owner=None
        self.inventory_name=None;self.batch_offset=0;self.batch_count=32
        self.package_manifest={}
        self.case_action=''
        self.zoo_parameters=None
        self.package_root=self.work/'builds/dist/SentinelAV'

    def verify_stage(self,state):
        """Check that the staged application files match the frozen package manifest."""
        manifest=json.loads((Path(state['input'])/'manifest.json').read_text(encoding='utf-8-sig'))
        staged={k.replace('\\','/')[4:]:v for k,v in manifest['files'].items() if k.replace('\\','/').startswith('App/')}
        if self.package_manifest and staged!=self.package_manifest:raise ValueError('Staged application differs from frozen package')

    def listed(self):
        """Return the Windows Sandbox environments that currently exist."""
        return json.loads(run(['wsb.exe','list','--raw'],30,self.cancelled))['WindowsSandboxEnvironments']

    def start(self):
        """Prepare the input kit, start a new Sandbox with a fresh id, wait until its bootstrap self-
        test passes offline, and check the boundary.

        Refuses to start if any Sandbox already exists, so an unrelated guest is never touched.
        """
        try:existing=self.listed()
        except (OSError,RuntimeError) as e:raise Blocked('Sandbox CLI unavailable or inaccessible: '+str(e)) from e
        if existing:raise Blocked('A Sandbox already exists; unrelated guests are never stopped')
        script=self.project/'scripts/lab/Prepare-TestEnvironment.ps1'
        extra=' -ApprovedInventory '+quote(self.inventory_name)+' -BatchOffset '+str(self.batch_offset)+' -BatchCount '+str(self.batch_count) if self.inventory_name else ''
        sealed=' -SealedStaticCorpus -SealedStaticHoldout -SealedZeusValidation' if self.case_action in ('live','inspect','benign') else ''
        if self.case_action=='zoo_quick':sealed=' -SealedStaticCorpus'
        command='& '+quote(script)+' -PackageRoot '+quote(self.package_root)+sealed+extra
        zoo=None
        if self.zoo_parameters is not None:
            from tempfile import TemporaryDirectory
            from .zoo_inventory import stage
            from .bazaar_corpus import stage as bazaar_stage
            definitions=self.zoo_parameters.get('definitions')
            if definitions:command+=' -DefinitionsRoot '+quote(definitions)
            with TemporaryDirectory(dir=unlinked(self.work/'cache')) as temporary:
                if self.zoo_parameters.get('corpus'):zoo=bazaar_stage(self.zoo_parameters,Path(temporary))
                else:zoo=stage(self.work,self.zoo_parameters,Path(temporary))
                powershell(command+' -ZooInput '+quote(temporary),300,self.cancelled,self.attempt/'prepare.log')
        else:
            powershell(command,300,self.cancelled,self.attempt/'prepare.log')
        # Stage optional reviewed support files before freezing configuration.
        latest=self.work/'lab/windows-sandbox/latest.json'
        state=json.loads(latest.read_text(encoding='utf-8-sig'))
        self.verify_stage(state)
        powershell('& '+quote(self.project/'scripts/lab/Start-TestEnvironment.ps1')+' -CheckOnly',120,self.cancelled,self.attempt/'configuration-check.log')
        config=Path(state['configuration']).read_text(encoding='utf-8-sig')
        guest=str(uuid.uuid4())
        self.owner=dict(schema=1,backend='sandbox',guest_id=guest,kit_id=state['kit_id'],created=time.time(),disposal_required=True)
        write_json(self.attempt/'owner.json',self.owner)
        # An explicit new ID removes the launch/list ownership race.
        run(['wsb.exe','start','--id',guest,'--config',config,'--raw'],90,self.cancelled,self.attempt/'start.log')
        self.connect()
        deadline=time.monotonic()+240
        while time.monotonic()<deadline:
            if self.cancelled():raise InterruptedError('Cancelled during guest boot')
            if any(r['Id']==guest for r in self.listed()):
                try:
                    code="$ErrorActionPreference='Stop';$p=Get-Content 'C:/SentinelAV-Test/preflight.json' -Raw|ConvertFrom-Json;$s=Get-Content 'C:/SentinelAV-Test/SelfTest/self-test.json' -Raw|ConvertFrom-Json;if($p.kit_id -eq "+quote(state['kit_id'])+" -and $s.status -eq 'PASS' -and $env:USERNAME -eq 'WDAGUtilityAccount' -and @(Get-NetAdapter|Where-Object Status -eq 'Up').Count -eq 0){exit 0};exit 80"
                    if self.exec(code)==0:break
                except RuntimeError:pass
            self.progress('Waiting for owned guest bootstrap');time.sleep(2)
        else:raise RuntimeError('Guest bootstrap deadline exceeded')
        powershell('& '+quote(self.project/'scripts/lab/Test-SandboxBoundary.ps1'),90,self.cancelled,self.attempt/'boundary.log')
        return dict(backend='sandbox',guest_uuid='',**({'zoo_input':zoo} if zoo is not None else {}))

    def connect(self):
        """Open a viewer window onto our own Sandbox."""
        if not self.owner or self.owner.get('backend')!='sandbox':raise ValueError('Sandbox ownership required for connection')
        guest=str(uuid.UUID(self.owner['guest_id']))
        if not any(r['Id']==guest for r in self.listed()):raise Blocked('Owned Sandbox no longer exists; connection refused')
        run(['wsb.exe','connect','--id',guest,'--raw'],30,self.cancelled,self.attempt/'connect.log')

    def exec(self,code,timeout=30,system=False):
        """Run a PowerShell script inside our Sandbox and return its exit code."""
        if not self.owner:raise ValueError('Guest ownership unavailable')
        raw=run(['wsb.exe','exec','--id',self.owner['guest_id'],'-r','System' if system else 'ExistingLogin','-c',
            'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(code.encode('utf-16le')).decode(),'--raw'],timeout,self.cancelled)
        value=json.loads(raw).get('ExitCode')
        if type(value) is not int:raise RuntimeError('Missing guest exit status')
        return value

    def dispose(self):
        """Stop our Sandbox, confirm it is gone, release the staging folder and write a disposal
        receipt.
        """
        if not self.owner:return
        guest=self.owner['guest_id']
        raw=json.loads(run(['wsb.exe','list','--raw'],30,lambda:False))['WindowsSandboxEnvironments']
        if any(r['Id']==guest for r in raw):
            run(['wsb.exe','stop','--id',guest,'--raw'],60,lambda:False)
            if any(r['Id']==guest for r in json.loads(run(['wsb.exe','list','--raw'],30,lambda:False))['WindowsSandboxEnvironments']):
                raise RuntimeError('Owned guest disposal not verified')
        receipt={**self.owner,'disposed':True,'checked':time.time(),'disposal_required':False}
        receipt['staging']=self.release_staging()
        write_json(self.attempt/'disposal.json',receipt)
        latest=self.work/'lab/windows-sandbox/latest.json'
        if latest.exists():
            state=json.loads(latest.read_text(encoding='utf-8-sig'))
            if state.get('guest_id')==guest:
                state.update(active_guest_verified=False,guest_executed=False,state='Disposed by critical evaluation harness')
                write_json(latest,state,True)

    def release_staging(self):
        """Remove only regenerable input copies after manifest/config capture."""
        kit=self.owner.get('kit_id','')
        import re
        if not re.fullmatch('[0-9a-f]{32}',kit):return dict(retained=True,reason='No owned staging identity recorded')
        parent=unlinked(self.work/'lab/windows-sandbox');root=unlinked(parent/('kit-'+kit))
        if not root.exists():return dict(already_absent=True)
        for name,source in [('input-manifest.json',root/'input/manifest.json'),('configuration.wsb',root/'SentinelAV-Test.wsb')]:
            target=self.attempt/name
            if source.exists():
                if target.exists() and target.read_bytes()!=source.read_bytes():raise ValueError('Captured staging evidence changed')
                if not target.exists():shutil_copy(source,target)
        code="$ErrorActionPreference='Stop';$p="+quote(root)+";$expected="+quote(parent)+";$item=Get-Item -LiteralPath $p;if($item.Parent.FullName -ne $expected -or $item.Name -notmatch '^kit-[0-9a-f]{32}$'){throw 'Staging target mismatch'};$walk=$item;while($walk){if($walk.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked staging ancestor'};$walk=$walk.Parent};if(Get-ChildItem -LiteralPath $p -Recurse -Force|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}){throw 'Linked staging member'};Remove-Item -LiteralPath $p -Recurse -Force"
        try:powershell(code,120,lambda:False,self.attempt/'staging-cleanup.log');return dict(temporary_kit_removed=True,manifest_preserved=True)
        except Exception as e:return dict(retained=True,reason=type(e).__name__+': '+str(e))

def shutil_copy(source,target):
    """Copy a file, refusing linked source or target paths."""
    import shutil
    shutil.copyfile(unlinked(source),unlinked(target))

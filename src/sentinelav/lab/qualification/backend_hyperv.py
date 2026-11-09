# Purpose: Reset an enrolled VM and perform owned PowerShell Direct operations.
# Works with: lab.qualification.backend_control, lab.qualification.backend_sandbox, lab.qualification.contracts,
#   lab.qualification.store, workspace
# Used by: lab.qualification.backend_recovery, lab.qualification.backends

"""Owned guest lifecycle and bounded metadata transport. No writable host share."""
import base64
import json
from pathlib import Path
import time
import uuid
from .contracts import identifier
from .store import write_json
from sentinelav.workspace import unlinked
from .backend_control import powershell, quote, Blocked
from .backend_sandbox import Sandbox

class HyperV(Sandbox):
    """PowerShell Direct to one explicitly enrolled, offline, licensed lab VM."""
    def __init__(self,*args,**kw):
        super().__init__(*args,**kw)
        path=self.work/'lab/qualification/hyperv.json'
        if not path.exists():raise Blocked('Dedicated Hyper-V VM not enrolled: F:\\SentinelAV-Work\\lab\\qualification\\hyperv.json')
        self.config=json.loads(unlinked(path).read_text())
        for key in ('vm_id','checkpoint_id','guest_uuid','ownership_id'):
            uuid.UUID(self.config[key])
        credential=unlinked(Path(self.config['credential_xml']))
        if not credential.is_relative_to(self.work/'lab/qualification') or not credential.is_file():raise ValueError('DPAPI credential must be under private F: lab configuration')
        if self.config.get('licensed_windows') is not True:raise Blocked('Legitimate Windows VM licensing not confirmed')
        self.ownership_common="$ErrorActionPreference='Stop';$id=[guid]"+quote(self.config['vm_id'])+";$vm=Get-VM -Id $id;if($vm.Notes -ne "+quote('SentinelAV-Lab:'+self.config['ownership_id'])+"){throw 'VM ownership mismatch'};"
        self.common=self.ownership_common+"if(@(Get-VMNetworkAdapter -VM $vm|Where-Object SwitchName).Count){throw 'VM must have disconnected networking'};"
        try:powershell(self.common+'$vm.Id.ToString()',30,self.cancelled)
        except (OSError,RuntimeError) as e:raise Blocked('Hyper-V enrollment, isolation or management permission check failed') from e

    def start(self):
        c=self.config
        self.owner=dict(schema=1,backend='hyperv',guest_id=c['vm_id'],checkpoint_id=c['checkpoint_id'],ownership_id=c['ownership_id'],disposal_required=True)
        write_json(self.attempt/'owner.json',self.owner)
        powershell(self.common+"$s=Get-VMSnapshot -VM $vm|Where-Object Id -eq ([guid]"+quote(c['checkpoint_id'])+");if(@($s).Count -ne 1){throw 'Missing baseline checkpoint'};if($vm.State -ne 'Off'){Stop-VM -VM $vm -TurnOff -Confirm:$false};Restore-VMSnapshot -VMSnapshot $s -Confirm:$false;Start-VM -VM $vm|Out-Null",180,self.cancelled,self.attempt/'reset.log')
        # Copy only the sealed, already hashed input kit; never host credentials.
        extra=' -ApprovedInventory '+quote(self.inventory_name)+' -BatchOffset '+str(self.batch_offset)+' -BatchCount '+str(self.batch_count) if self.inventory_name else ''
        powershell('& '+quote(self.project/'scripts/lab/Prepare-TestEnvironment.ps1')+' -PackageRoot '+quote(self.package_root)+' -SealedStaticCorpus -SealedStaticHoldout -SealedZeusValidation'+extra,300,self.cancelled,self.attempt/'prepare.log')
        state=json.loads((self.work/'lab/windows-sandbox/latest.json').read_text(encoding='utf-8-sig'))
        self.owner['kit_id']=state['kit_id'];write_json(self.attempt/'owner.json',self.owner,True)
        self.verify_stage(state)
        source=unlinked(Path(state['input']))
        powershell(self.common+"Enable-VMIntegrationService -VM $vm -Name 'Guest Service Interface';$src="+quote(source)+";Get-ChildItem -LiteralPath $src -File -Recurse|ForEach-Object{$relative=$_.FullName.Substring($src.Length+1);Copy-VMFile -VM $vm -SourcePath $_.FullName -DestinationPath ('C:/SentinelAV-Input/'+$relative) -FileSource Host -CreateFullPath -Force}",600,self.cancelled,self.attempt/'stage.log')
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            try:
                if self.exec("if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ne "+quote(c['guest_uuid'])+"){exit 81};exit 0")==0:break
            except RuntimeError:time.sleep(2)
        else:raise RuntimeError('PowerShell Direct did not become available')
        if self.exec("$ErrorActionPreference='Stop';New-Item 'C:/SentinelAV-Test' -ItemType Directory -Force|Out-Null;if(Test-Path 'C:/SentinelAV-Test/App'){exit 83};$m=Get-Content 'C:/SentinelAV-Input/manifest.json' -Raw|ConvertFrom-Json;foreach($f in $m.files.psobject.Properties){if((Get-FileHash -LiteralPath ('C:/SentinelAV-Input/'+$f.Name)).Hash -ne $f.Value){exit 82}};New-Item 'C:/SentinelAV-Test/App' -ItemType Directory|Out-Null;Get-ChildItem 'C:/SentinelAV-Input/App'|ForEach-Object{Copy-Item -LiteralPath $_.FullName -Destination 'C:/SentinelAV-Test/App' -Recurse};exit 0",300):raise RuntimeError('Guest package copy/identity failed; reset required')
        result=dict(backend='hyperv',guest_uuid=c['guest_uuid'])
        if self.case_action=='recovery':
            disk=self.work/'lab/qualification/volumes'/(uuid.uuid4().hex+'.vhdx');disk.parent.mkdir(parents=True,exist_ok=True)
            self.owner['test_disk']=str(disk);write_json(self.attempt/'owner.json',self.owner,True)
            identifier=powershell(self.common+"$d=New-VHD -Path "+quote(disk)+" -Dynamic -SizeBytes 67108864;Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path "+quote(disk)+";$d.DiskIdentifier.ToString()",60,self.cancelled).strip()
            uuid.UUID(identifier);result['owned_disk_identifier']=identifier
        return result

    def exec(self,code,timeout=30,system=False):
        c=self.config
        script=self.common+"$cred=Import-Clixml -LiteralPath "+quote(c['credential_xml'])+";$reply=Invoke-Command -VMId $id -Credential $cred -ScriptBlock {param($code);$p=Start-Process powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$code) -WindowStyle Hidden -Wait -PassThru;[int]$p.ExitCode} -ArgumentList "+quote(base64.b64encode(code.encode('utf-16le')).decode())+";$reply|ConvertTo-Json -Compress"
        value=json.loads(powershell(script,timeout,self.cancelled))
        if type(value) is not int:raise ValueError('Invalid PowerShell Direct status')
        return value

    def dispose(self):
        if not self.owner:return
        powershell(self.ownership_common+"if($vm.State -ne 'Off'){Stop-VM -VM $vm -TurnOff -Confirm:$false}",60,lambda:False,self.attempt/'stop.log')
        if self.owner.get('test_disk'):
            disk=unlinked(Path(self.owner['test_disk']))
            if not disk.is_relative_to(self.work/'lab/qualification/volumes') or disk.suffix!='.vhdx':raise ValueError('Invalid owned test-disk path')
            powershell(self.ownership_common+"Get-VMHardDiskDrive -VM $vm|Where-Object Path -eq "+quote(disk)+"|Remove-VMHardDiskDrive -Confirm:$false",60,lambda:False,self.attempt/'detach-test-disk.log')
        powershell(self.ownership_common+"$s=Get-VMSnapshot -VM $vm|Where-Object Id -eq ([guid]"+quote(self.config['checkpoint_id'])+");if(@($s).Count -ne 1){throw 'Baseline checkpoint missing'};Restore-VMSnapshot -VMSnapshot $s -Confirm:$false",180,lambda:False,self.attempt/'post-case-reset.log')
        write_json(self.attempt/'disposal.json',{**self.owner,'disposed':True,'powered_off':True,'baseline_restored':True,'reset_before_reuse':True,'disposal_required':False,'staging':self.release_staging()})

    def reboot(self):
        code="exit ([int]([DateTimeOffset](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUnixTimeSeconds())"
        before=self.exec(code)
        if self.exec('shutdown.exe /r /t 0;exit $LASTEXITCODE'):raise RuntimeError('Guest reboot request failed')
        deadline=time.monotonic()+240
        while time.monotonic()<deadline:
            if self.cancelled():raise InterruptedError('Cancelled during reboot')
            time.sleep(2)
            try:
                after=self.exec(code)
                if after>before:return dict(before=before,after=after,verified=True)
            except RuntimeError:pass
        raise RuntimeError('Guest reboot not independently observed')

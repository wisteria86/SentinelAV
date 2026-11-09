# Purpose: Enroll an explicitly owned, licensed VM baseline for resettable evaluation.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

param(
    [Parameter(Mandatory=$true)][string]$VMName,
    [Parameter(Mandatory=$true)][string]$BaselineCheckpoint,
    [Parameter(Mandatory=$true)][switch]$LicensedWindows,
    [Parameter(Mandatory=$true)][switch]$CleanBaselineAcknowledged
)
$ErrorActionPreference='Stop'
if(!$LicensedWindows -or !$CleanBaselineAcknowledged){throw 'Licensed Windows and independently prepared clean baseline acknowledgments are required'}
$project=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python=Join-Path $project '.venv/Scripts/python.exe'
$root=& $python -c "import tools;from sentinelav.workspace import Workspace;print(Workspace().area('lab')/'qualification')"
if($LASTEXITCODE){throw 'Managed work drive unavailable'}
$root=([string]$root).Trim();New-Item -ItemType Directory -Path $root -Force|Out-Null
$configuration=Join-Path $root 'hyperv.json'
if(Test-Path -LiteralPath $configuration){throw 'An enrollment already exists; existing VM ownership is never replaced automatically'}
$vm=Get-VM -Name $VMName
if(@($vm).Count -ne 1){throw 'Select exactly one dedicated test VM'}
if(@(Get-VMNetworkAdapter -VM $vm|Where-Object SwitchName).Count){throw 'Disconnect all VM network adapters before enrollment'}
if($vm.Notes){throw 'VM has existing notes/ownership; preserve it and select an unowned dedicated VM'}
$snapshot=@(Get-VMSnapshot -VM $vm|Where-Object Name -eq $BaselineCheckpoint)
if($snapshot.Count -ne 1){throw 'Select exactly one independently prepared clean checkpoint'}
$credential=Get-Credential -Message 'Administrator credentials for this dedicated, offline Windows test VM (PowerShell Direct)'
if(!$credential){throw 'Enrollment cancelled'}
$credentialPath=Join-Path $root 'hyperv-credential.xml'
if(Test-Path -LiteralPath $credentialPath){throw 'Existing protected credential preserved'}
$credential|Export-Clixml -LiteralPath $credentialPath
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $credentialPath /inheritance:r /grant:r ($sid+':(F)') '*S-1-5-18:(F)'|Out-Null
if($LASTEXITCODE){throw 'Could not restrict protected credential access'}
if($vm.State -eq 'Off'){Start-VM -VM $vm|Out-Null}
$facts=Invoke-Command -VMId $vm.Id -Credential $credential -ScriptBlock {
    if(@(Get-NetAdapter|Where-Object Status -eq 'Up').Count){throw 'Guest networking is active'}
    @{uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;os=(Get-CimInstance Win32_OperatingSystem).Version;model=(Get-CimInstance Win32_ComputerSystem).Model}
}
if($facts.model -ne 'Virtual Machine'){throw 'Unexpected guest hardware identity'}
$owner=[guid]::NewGuid().ToString()
Set-VM -VM $vm -Notes ('SentinelAV-Lab:'+$owner)
$record=@{schema=1;vm_id=[string]$vm.Id;checkpoint_id=[string]$snapshot[0].Id;guest_uuid=[string]$facts.uuid;ownership_id=$owner;
    credential_xml=$credentialPath;licensed_windows=$true;clean_baseline_acknowledged=$true;guest_os=[string]$facts.os;enrolled_utc=[DateTime]::UtcNow.ToString('o')}
$record|ConvertTo-Json|Set-Content -LiteralPath $configuration -Encoding utf8
Write-Output ('Enrolled dedicated test VM. Its configured checkpoint will be restored by evaluations. Configuration: '+$configuration)

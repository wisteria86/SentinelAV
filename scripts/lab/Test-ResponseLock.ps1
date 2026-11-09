# Purpose: Verify response serialization and interrupted-operation recovery.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Harmless lock contention against the already deployed broker in the owned guest.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$lab=Get-SentinelLabRoot
$state=Get-Content -LiteralPath (Join-Path $lab 'latest.json') -Raw | ConvertFrom-Json
$running=wsb.exe list --raw | ConvertFrom-Json
if(!$state.active_guest_verified -or $state.active_guest_id -notmatch '^[0-9a-f-]{36}$' -or @($running.WindowsSandboxEnvironments).Count -ne 1 -or $running.WindowsSandboxEnvironments[0].Id -ne $state.active_guest_id){throw 'Exactly the owned verified guest is required'}
$code=@'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or @(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 80}
if((Get-Content 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json).kit_id -ne '__KIT__'){exit 81}
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root='C:\ProgramData\SentinelAVProtection\response\'+$owner
$handle=[IO.FileStream]::new((Join-Path $root 'execution.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
$id=[guid]::NewGuid().ToString('N');$inputFile=Join-Path $env:LOCALAPPDATA ('SentinelAV\broker-requests\'+$id+'.json')
try {
 $handle.Lock(0,1)
 @{schema=1;operation='execute';plan_id=('0'*32)} | ConvertTo-Json | Set-Content -LiteralPath $inputFile -Encoding utf8
 $process=Start-Process -FilePath 'C:\Program Files\SentinelAVProtection\SentinelAV.exe' -ArgumentList @('--remediation-broker',$id) -WindowStyle Hidden -Wait -PassThru
 Add-Type -AssemblyName System.Security
 $raw=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $root ('result-'+$id+'.bin'))),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $result=[Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
 if($process.ExitCode -ne 1 -or $result.ok -or $result.error -notlike '*Another cleanup or recovery operation is active*'){exit 82}
 @{schema=1;status='PASS';protected_lock_contention_denied=$true;side_effects_requested=$false} | ConvertTo-Json | Set-Content 'C:\SentinelAV-Test\response-lock-check.json'
} finally {$handle.Unlock(0,1);$handle.Dispose();Remove-Item -LiteralPath $inputFile -ErrorAction SilentlyContinue}
exit 0
'@
$code=$code.Replace('__KIT__',$state.kit_id)
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
$result=wsb.exe exec --id $state.active_guest_id -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
if($null -eq $result.ExitCode -or $result.ExitCode -ne 0){throw ('Protected lock contention check failed: '+$result.ExitCode)}
@{schema=1;guest_id=$state.active_guest_id;kit_id=$state.kit_id;status='PASS';protected_lock_contention_denied=$true;malware_executed=$false;checked_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $lab 'response-lock-validation.json') -Encoding utf8
Write-Output 'PASS: competing Windows process prevented protected broker recovery; no repair action requested.'

# Purpose: Validate scoped response behavior inside the disposable guest.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Verify the packaged --self-test's real Qt response lifecycle in the guest.
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Test-SandboxBoundary.ps1')
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot=Get-SentinelLabRoot
$state=Get-Content -LiteralPath (Join-Path $labRoot 'latest.json') -Raw | ConvertFrom-Json
$code=@'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount'){exit 80}
if(@(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 81}
$p=Get-Content -LiteralPath 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json
if($p.kit_id -ne '__KIT__'){exit 82}
$r=(Get-Content -LiteralPath 'C:\SentinelAV-Test\SelfTest\self-test.json' -Raw | ConvertFrom-Json).response
if(!$r -or $r.status -ne 'PASS'){exit 83}
if($r.original_sha256 -ne 'f2582599e71ebdfa02240afdf573aae382c651efad345c34efa09ba23685a35a' -or $r.restored_sha256 -ne $r.original_sha256){exit 84}
foreach($key in @('original_removed','encrypted_blob_verified','overwrite_refused','restored_state_verified','restored_content_detected_again','trust_unchanged','audit_verified','fixture_cleanup')){
    if($r.$key -ne $true){exit 85}
}
foreach($file in @('response-quarantined.png','response-restored.png')){
    if(!(Test-Path -LiteralPath (Join-Path 'C:\SentinelAV-Test\SelfTest' $file))){exit 86}
}
exit 0
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code.Replace('__KIT__',$state.kit_id)))
$reply=wsb.exe exec --id $state.guest_id -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
if($null -eq $reply.ExitCode -or $reply.ExitCode -ne 0){throw ('Guest response evidence check failed: '+$reply.ExitCode)}
@{checked_utc=[DateTime]::UtcNow.ToString('o');guest_id=$state.guest_id;kit_id=$state.kit_id;status='PASS';mode='automated Qt controls with fixture dialog answers';quarantine_restore=$true;overwrite_refused=$true;restored_hash_verified=$true;trust_unchanged=$true;audit_verified=$true;fixture_cleanup=$true;screenshots='Guest-local C:\SentinelAV-Test\SelfTest';desktop_click_test=$false;live_malware_executed=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'response-validation.json') -Encoding utf8
Write-Output 'PASS: packaged guest scan/quarantine/restore controls, no-overwrite, exact bytes, audit, unchanged trust and fixture cleanup.'

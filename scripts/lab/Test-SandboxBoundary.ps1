# Purpose: Verify guest identity, offline state, denied input-share writes, and the harmless baseline.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Harmless runtime checks only. No samples, network connections or trust changes.
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Start-TestEnvironment.ps1') -CheckOnly
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot=Get-SentinelLabRoot
$statePath=Join-Path $labRoot 'latest.json'
$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$running=wsb.exe list --raw | ConvertFrom-Json
if (@($running.WindowsSandboxEnvironments).Count -ne 1) { throw 'Exactly one Sandbox must be running' }
$guest=[string]$running.WindowsSandboxEnvironments[0].Id
if ($guest -notmatch '^[0-9a-f-]{36}$') { throw 'Invalid guest identity' }
$code=@'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount'){exit 70}
if((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine'){exit 71}
if(@(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 72}
if(Test-Path -LiteralPath 'C:\SentinelAV-Test\SelfTest\last-error.txt'){exit 78}
if(!(Test-Path -LiteralPath 'C:\SentinelAV-Test\preflight.json') -or !(Test-Path -LiteralPath 'C:\SentinelAV-Test\SelfTest\self-test.json')){exit 79}
$p=Get-Content -LiteralPath 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json
if($p.kit_id -ne '__KIT__'){exit 73}
$inputManifest=Get-Content -LiteralPath 'C:\SentinelAV-Input\manifest.json' -Raw | ConvertFrom-Json
if($inputManifest.kit_id -ne $p.kit_id){exit 76}
$r=Get-Content -LiteralPath 'C:\SentinelAV-Test\SelfTest\self-test.json' -Raw | ConvertFrom-Json
if($r.status -ne 'PASS' -or !$r.buffer.complete -or !$r.buffer.detected -or $r.lab.status -ne 'Checks passed' -or !$r.lab.workspace_reset){exit 74}
$probe='C:\SentinelAV-Input\boundary-'+[guid]::NewGuid().ToString('N')+'.txt'
$denied=$false
try { [IO.File]::WriteAllText($probe,'Harmless read-only boundary fixture') }
catch [UnauthorizedAccessException] { $denied=$true }
catch [IO.IOException] { if(($_.Exception.HResult -band 0xffff) -in @(5,19)){$denied=$true}else{throw} }
if(!$denied -or (Test-Path -LiteralPath $probe)){exit 75}
$result=@{checked_utc=[DateTime]::UtcNow.ToString('o');kit_id=$p.kit_id;offline=$true;input_write_denied=$true;packaged_self_test=$true;safe_profiles=$true}
$result | ConvertTo-Json | Set-Content -LiteralPath 'C:\SentinelAV-Test\boundary-validation.json'
exit 0
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code.Replace('__KIT__',$state.kit_id)))
$deadline=(Get-Date).AddSeconds(120)
do {
    $reply=wsb.exe exec --id $guest -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
    if($reply.ExitCode -ne 79){break}
    if((Get-Date) -ge $deadline){throw 'Guest bootstrap did not finish within the readiness budget'}
    Write-Output 'Waiting for the guest bootstrap self-test to finish...'
    Start-Sleep -Seconds 2
} while($true)
if ($null -eq $reply.ExitCode -or $reply.ExitCode -ne 0) { throw ('Guest boundary/baseline check failed: '+$reply.ExitCode) }
$state.guest_executed=$true
$state.state='Runtime offline/read-only boundary and harmless packaged baseline verified'
foreach($pair in @{guest_id=$guest;active_guest_id=$guest;active_guest_kit_id=$state.kit_id;active_guest_verified=$true}.GetEnumerator()) {
    $state | Add-Member -NotePropertyName $pair.Key -NotePropertyValue $pair.Value -Force
}
$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
@{checked_utc=[DateTime]::UtcNow.ToString('o');guest_id=$guest;kit_id=$state.kit_id;offline=$true;input_write_denied=$true;packaged_self_test=$true;clipboard_runtime_tested=$false;live_malware_suitability_established=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'boundary-validation.json') -Encoding utf8
Write-Output 'PASS: guest identity, kit, offline state, denied input-share write, packaged detection and four harmless simulation profiles.'
Write-Output 'Clipboard is configuration-checked only. This does not establish live-malware containment.'

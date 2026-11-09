# Purpose: Reconcile the recorded disposable guest and its owned staging state.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Explicitly discard only the registered disposable guest, then verify a fresh one.
$ErrorActionPreference='Stop'
# A Windows PowerShell child can inherit a PowerShell 7 module path. Resolve
# modules for the executing shell before using Utility/Management cmdlets.
$env:PSModulePath=$PSHOME+'\Modules;'+$env:SystemRoot+'\System32\WindowsPowerShell\v1.0\Modules'
$projectRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot=Get-SentinelLabRoot
$statePath=Join-Path $labRoot 'latest.json'
$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$oldId=if($state.active_guest_verified){[string]$state.active_guest_id}else{[string]$state.guest_id}
$oldVerified=$state.guest_executed -or $state.active_guest_verified
$running=wsb.exe list --raw | ConvertFrom-Json
if (!$oldVerified -or $oldId -notmatch '^[0-9a-f-]{36}$' -or @($running.WindowsSandboxEnvironments).Count -ne 1 -or $running.WindowsSandboxEnvironments[0].Id -ne $oldId) { throw 'Exactly the registered test guest must be running' }
& (Join-Path $PSScriptRoot 'Start-TestEnvironment.ps1') -CheckOnly
$code="Set-Content -LiteralPath 'C:\SentinelAV-Test\reset-marker.txt' -Value 'SentinelAV inert reset fixture'; if(!(Test-Path -LiteralPath 'C:\SentinelAV-Test\reset-marker.txt')){exit 60}; exit 0"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
$reply=wsb.exe exec --id $oldId -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
if ($reply.ExitCode -ne 0 -or $null -eq $reply.ExitCode) { throw 'Could not create guest-only reset fixture' }
wsb.exe stop --id $oldId --raw | Out-Null
if ($LASTEXITCODE) { throw 'Owned guest stop failed' }
$stopDeadline=(Get-Date).AddSeconds(15)
do {
    $remaining=wsb.exe list --raw | ConvertFrom-Json
    if (!@($remaining.WindowsSandboxEnvironments | Where-Object Id -eq $oldId).Count) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $stopDeadline)
if (@($remaining.WindowsSandboxEnvironments | Where-Object Id -eq $oldId).Count) { throw 'Owned guest did not stop' }
$state.guest_executed=$false; $state.state='Resetting; unverified'
$state | Add-Member -NotePropertyName active_guest_verified -NotePropertyValue $false -Force
$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
& (Join-Path $PSScriptRoot 'Start-TestEnvironment.ps1')
$deadline=(Get-Date).AddSeconds(120); $newId=$null; $verified=$false
do {
    Start-Sleep -Seconds 2
    $running=wsb.exe list --raw | ConvertFrom-Json
    if (@($running.WindowsSandboxEnvironments).Count -eq 1) {
        $newId=[string]$running.WindowsSandboxEnvironments[0].Id
        if ($newId -eq $oldId) { throw 'Old guest still present; reset not proven' }
        $code=@'
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath 'C:\SentinelAV-Test\reset-marker.txt'){exit 61}
if(Test-Path -LiteralPath 'C:\SentinelAV-Update'){exit 66}
if(!(Test-Path -LiteralPath 'C:\SentinelAV-Test\SelfTest\self-test.json')){exit 62}
$p=Get-Content -LiteralPath 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json
if($p.kit_id -ne '__KIT__'){exit 63}
$r=Get-Content -LiteralPath 'C:\SentinelAV-Test\SelfTest\self-test.json' -Raw | ConvertFrom-Json
if($r.status -ne 'PASS' -or !$r.buffer.complete -or !$r.buffer.detected){exit 64}
if(@(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 65}
exit 0
'@
        $code=$code.Replace('__KIT__',$state.kit_id)
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        try { $reply=wsb.exe exec --id $newId -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json }
        catch { $reply=$null }
        if ($null -ne $reply.ExitCode -and $reply.ExitCode -eq 0) { $verified=$true; break }
    }
} while ((Get-Date) -lt $deadline)
if (!$verified) { throw 'New guest did not pass reset/baseline checks; state remains unverified' }
$state.guest_executed=$true; $state.state='Reset and fresh guest baseline verified'
$state | Add-Member -NotePropertyName guest_id -NotePropertyValue $newId -Force
$state | Add-Member -NotePropertyName active_guest_id -NotePropertyValue $newId -Force
$state | Add-Member -NotePropertyName active_guest_kit_id -NotePropertyValue $state.kit_id -Force
$state | Add-Member -NotePropertyName active_guest_verified -NotePropertyValue $true -Force
$state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
@{checked_utc=[DateTime]::UtcNow.ToString('o');old_guest=$oldId;new_guest=$newId;marker_disappeared=$true;baseline_passed=$true;offline=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'reset-validation.json') -Encoding utf8
Write-Output 'PASS: owned guest discarded, marker absent, fresh kit and harmless baseline verified.'

# Purpose: Exercise the authorized response broker with controlled fixtures.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Fixed harmless test in the registered disposable guest only.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$lab=Get-SentinelLabRoot
& (Join-Path $PSScriptRoot 'Test-SandboxBoundary.ps1')
$state=Get-Content -LiteralPath (Join-Path $lab 'latest.json') -Raw | ConvertFrom-Json
if($state.kit_id -notmatch '^[0-9a-f]{32}$' -or $state.guest_id -notmatch '^[0-9a-f-]{36}$' -or !$state.guest_executed){throw 'Verified owned guest required'}
$fixed=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guest/Check-ResponseBoundary.ps1') -Raw
$code='& {'+[Environment]::NewLine+$fixed+[Environment]::NewLine+'} -ExpectedKitId '''+$state.kit_id+'''; if(!$?){exit 91}'
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
if($encoded.Length -gt 29000){throw 'Fixed test command exceeds the transport budget'}
$result=wsb.exe exec --id $state.guest_id -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
if($null -eq $result.ExitCode -or $result.ExitCode -ne 0){throw ('Guest broker check failed: '+$result.ExitCode+'; inspect guest response-boundary logs')}
@{schema=1;guest_id=$state.guest_id;kit_id=$state.kit_id;checked_utc=[DateTime]::UtcNow.ToString('o');status='PASS';scenario='Harmless protected service/broker negative controls';malware_executed=$false;host_service_installed=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $lab 'response-boundary-validation.json') -Encoding utf8
Write-Output 'PASS: service-owned machine history, protected broker, benign/demo refusal, forged verdict refusal and untouched controls; guest only.'

# Purpose: Finalize ownership markers and verify the guest service and AMSI broker startup.
# Works with: Common.ps1; Install-Before.ps1; platform/windows_service.py
# Used by: the CLI, desktop launcher, or packaging workflow

Read-State
foreach ($path in @($install,$dataRoot)) { Mark-Owned $path }
$policyPath=Join-Path $dataRoot 'policy.json'
$policy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
$policy.amsi_broker=$true
$policy | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $policyPath -Encoding utf8
$state.phase='Service installed; starting'; Save-State
Start-Service SentinelAVProtection
$deadline=(Get-Date).AddSeconds(75)
do {
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath (Join-Path $dataRoot 'data\last-error.txt')) { throw (Get-Content -LiteralPath (Join-Path $dataRoot 'data\last-error.txt') -Raw) }
    $health=$null
    try { $health=Get-Content -LiteralPath (Join-Path $dataRoot 'data\status.json') -Raw | ConvertFrom-Json } catch {}
    if ($health.amsi_broker.running -and $health.account -eq 'LocalService') { break }
} while ((Get-Date) -lt $deadline)
if (!$health.amsi_broker.running) { throw 'LocalService broker did not become healthy' }
$state.phase='Service ready'; Save-State

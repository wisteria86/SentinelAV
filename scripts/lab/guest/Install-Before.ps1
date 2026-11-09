# Purpose: Reject existing resources and initialize owned guest deployment state.
# Works with: Common.ps1; scripts/lab/Invoke-GuestIntegration.ps1
# Used by: the CLI, desktop launcher, or packaging workflow

foreach ($path in @($install,$dataRoot,$providerRoot,$watch,$classKey,$providerKey)) {
    if (Test-Path -LiteralPath $path) { throw ('Pre-existing deployment object preserved: '+$path) }
}
if (Get-Service SentinelAVProtection -ErrorAction SilentlyContinue) { throw 'Existing service preserved' }
if (Test-Path -LiteralPath $statePath) {
    $old=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($old.phase -ne 'Removed' -or !$old.completed -or $old.id -notmatch '^[0-9a-f]{32}$') { throw 'Incomplete deployment must be removed first' }
    $archive=Join-Path $root ('deployment-'+$old.id+'.json')
    Move-Item -LiteralPath $statePath -Destination $archive
}
$state=[ordered]@{id=$expectedDeploymentId;machine=$env:COMPUTERNAME;other_providers=(Other-Providers);phase='Installing';variant='';completed=$false}
Save-State
New-Item -ItemType Directory -Path $watch | Out-Null
Mark-Owned $watch
& icacls.exe $watch '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE) { throw 'Watch-folder ACL failed' }
Set-Content -LiteralPath (Join-Path $root 'unrelated-fixture.txt') -Value 'Preserve this harmless sibling fixture' -Encoding ascii

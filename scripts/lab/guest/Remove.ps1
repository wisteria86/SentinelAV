# Purpose: Remove only the guest provider and service deployment recorded as owned.
# Works with: Common.ps1; Register.ps1; Install-After.ps1
# Used by: the CLI, desktop launcher, or packaging workflow

Read-State
Assert-OtherProviders
& $probe --unregister-owned $state.id
if ($LASTEXITCODE) { throw ('Owned-key removal refused: '+$LASTEXITCODE) }
$service=Get-CimInstance Win32_Service -Filter "Name='SentinelAVProtection'"
if ($service) {
    $expected='"'+(Join-Path $install 'SentinelAV.exe')+'" --windows-service'
    if ($service.PathName -ne $expected -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Service identity mismatch; preserved' }
    $engineProcess=$null
    if ($service.ProcessId) {
        $engineProcess=Get-Process -Id $service.ProcessId -ErrorAction SilentlyContinue
        if ($engineProcess) { $null=$engineProcess.Handle }
    }
    $controller=Get-Service SentinelAVProtection
    try {
        if ($controller.Status -ne 'Stopped') { $controller.Stop(); $controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(25)) }
    } finally { $controller.Dispose() }
    if ($engineProcess) {
        try { if (!$engineProcess.HasExited -and !$engineProcess.WaitForExit(15000)) { throw 'Owned service process has not exited; files preserved' } }
        finally { $engineProcess.Dispose() }
    }
    & sc.exe delete SentinelAVProtection | Out-Null
    if ($LASTEXITCODE) { throw 'Service removal failed' }
}
foreach ($target in @($install,$dataRoot,$providerRoot,$watch)) {
    if (!(Test-Path -LiteralPath $target)) { continue }
    # Exact target allowlist + no links + deployment ownership before recursive removal.
    $resolved=[IO.Path]::GetFullPath((Get-Item -LiteralPath $target).FullName)
    if ($resolved -ne [IO.Path]::GetFullPath($target)) { throw 'Cleanup target mismatch' }
    Assert-Unlinked $target
    if (@(Get-ChildItem -LiteralPath $target -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count) { throw 'Linked cleanup member refused' }
    $marker=Join-Path $target '.sentinelav-deployment'
    $markerValue=if (Test-Path -LiteralPath $marker) { [string](Get-Content -LiteralPath $marker -Raw) } else { '' }
    if ([string]::IsNullOrWhiteSpace($markerValue)) {
        if ($state.phase -notlike 'Installing*') { throw 'Unmarked directory preserved' }
        # Install preflight recorded all four exact targets as absent before creation.
        Mark-Owned $target
    }
    if (([string](Get-Content -LiteralPath $marker -Raw)).Trim() -ne $state.id) { throw 'Cleanup ownership mismatch' }
    Remove-Item -LiteralPath $target -Recurse -Force
}
$deadline=(Get-Date).AddSeconds(10)
do {
    $remaining=Get-Service SentinelAVProtection -ErrorAction SilentlyContinue
    if (!$remaining) { break }
    $remaining.Dispose()
    Start-Sleep -Milliseconds 200
} while ((Get-Date) -lt $deadline)
if ($remaining) { throw 'Service registration still present' }
if (Test-Path -LiteralPath (Join-Path $root 'unrelated-fixture.txt')) {
    if ((Get-Content -LiteralPath (Join-Path $root 'unrelated-fixture.txt') -Raw).Trim() -ne 'Preserve this harmless sibling fixture') { throw 'Unrelated fixture changed' }
} elseif ($state.phase -notlike 'Installing*') { throw 'Unrelated fixture is missing' }
Assert-OtherProviders
$state.phase='Removed'; $state.completed=$true; Save-State

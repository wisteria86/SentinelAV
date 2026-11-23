# Purpose: Validate the staged Sandbox configuration and optionally launch the guest.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot = Get-SentinelLabRoot
$statePath = Join-Path $labRoot 'latest.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { throw 'Prepare the kit first: .\scripts\lab\Prepare-TestEnvironment.ps1' }
if ((Get-Item -LiteralPath $statePath).Length -gt 16384) { throw 'Invalid lab state size' }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.schema -ne 1 -or $state.kit_id -notmatch '^[0-9a-f]{32}$') { throw 'Invalid lab state' }
$expectedRoot = Join-Path $labRoot ('kit-' + $state.kit_id)
if ($state.configuration -ne (Join-Path $expectedRoot 'SentinelAV-Test.wsb') -or $state.input -ne (Join-Path $expectedRoot 'input')) { throw 'Kit path mismatch' }
foreach ($path in @($state.configuration,(Join-Path $state.input 'manifest.json'))) {
    $entry = Get-Item -LiteralPath $path
    while ($null -ne $entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked kit path rejected' }
        $entry = $entry.Parent
    }
}
if ((Get-FileHash -LiteralPath $state.configuration -Algorithm SHA256).Hash -ne $state.configuration_sha256) { throw 'Sandbox configuration changed; prepare a new kit' }
if ((Get-FileHash -LiteralPath (Join-Path $state.input 'manifest.json') -Algorithm SHA256).Hash -ne $state.manifest_sha256) { throw 'Input manifest changed; prepare a new kit' }
$manifest = Get-Content -LiteralPath (Join-Path $state.input 'manifest.json') -Raw | ConvertFrom-Json
$entries = @($manifest.files.psobject.Properties)
$members = @(Get-ChildItem -LiteralPath $state.input -Recurse -Force)
if ($members | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Linked kit member rejected' }
if ($manifest.schema -ne 1 -or $manifest.kit_id -ne $state.kit_id -or $entries.Count -gt 8192 -or @($members | Where-Object { -not $_.PSIsContainer }).Count -ne ($entries.Count + 1)) { throw 'Unexpected input inventory' }
foreach ($entry in $entries) {
    $path = [IO.Path]::GetFullPath((Join-Path $state.input $entry.Name))
    if (-not $path.StartsWith($state.input + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or $entry.Value -notmatch '^[0-9a-f]{64}$') { throw 'Invalid manifest member' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Value) { throw ('Input changed: ' + $entry.Name) }
}
[xml]$config = Get-Content -LiteralPath $state.configuration -Raw
foreach ($name in @('Networking','vGPU','ClipboardRedirection','AudioInput','VideoInput','PrinterRedirection')) {
    if ($config.Configuration.$name -cne 'Disable') { throw ('Unsafe Sandbox setting: ' + $name) }
}
if ($config.Configuration.ProtectedClient -cne 'Enable' -or $config.Configuration.MemoryInMB -ne '4096') { throw 'Sandbox protection/resource settings changed' }
$folders = @($config.Configuration.MappedFolders.MappedFolder)
if ($folders[0].HostFolder -ne $state.input -or $folders[0].SandboxFolder -ne 'C:\SentinelAV-Input' -or $folders[0].ReadOnly -cne 'true') { throw 'Unexpected folder sharing' }
# The only other share allowed is the recorded, read-only definitions snapshot.
if ($folders.Count -eq 2) {
    if (-not $state.definitions -or $folders[1].HostFolder -ne $state.definitions -or $folders[1].SandboxFolder -ne 'C:\SentinelAV-Definitions' -or $folders[1].ReadOnly -cne 'true') { throw 'Unexpected folder sharing' }
    if ((Get-FileHash -LiteralPath (Join-Path $state.definitions 'snapshot.json') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $state.definitions_snapshot_sha256) { throw 'Definitions snapshot changed after staging' }
} elseif ($folders.Count -ne 1) { throw 'Unexpected folder sharing' }
Write-Output 'PASS: pinned configuration has no networking/clipboard/device sharing; one read-only test-input folder.'
Write-Output 'This validates requested configuration only; actual guest checks are still required.'
if ($CheckOnly) { return }
$feature = Get-CimInstance Win32_OptionalFeature -Filter "Name='Containers-DisposableClientVM'"
if ($feature.InstallState -ne 1) { throw 'Windows Sandbox is disabled or pending. Run scripts/lab/Enable-WindowsSandbox.ps1 as Administrator and restart if requested.' }
$sandbox = Join-Path $env:WINDIR 'System32/WindowsSandbox.exe'
if (-not (Test-Path -LiteralPath $sandbox)) { throw 'Windows Sandbox launcher is not available yet. Complete feature activation/restart first.' }
if (Get-Command wsb.exe -ErrorAction SilentlyContinue) {
    $running=wsb.exe list --raw | ConvertFrom-Json
    if (@($running.WindowsSandboxEnvironments).Count) { throw 'A Sandbox is already running. Use Reset-TestEnvironment.ps1 for the registered disposable guest instead of launching a second profile.' }
}
Start-Process -FilePath $sandbox -ArgumentList @(('"' + $state.configuration + '"')) -WindowStyle Hidden

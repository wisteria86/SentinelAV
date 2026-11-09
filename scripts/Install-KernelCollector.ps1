# Purpose: Verify and stage a reviewed collector under protected Program Files permissions.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

param(
    [Parameter(Mandatory=$true)][string]$PackageDirectory,
    [Parameter(Mandatory=$true)][string]$ExpectedManifestSha256
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrative deployment authorization is required.' }
if ($ExpectedManifestSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Reviewed manifest SHA-256 required.' }
$source = (Resolve-Path -LiteralPath $PackageDirectory).Path.TrimEnd('\')
$ancestor = Get-Item -LiteralPath $source -Force
while ($null -ne $ancestor) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked package path rejected.' }
    $ancestor = $ancestor.Parent
}
$manifest = Join-Path $source 'collector-manifest.json'
if ((Get-Item -LiteralPath $manifest).Length -gt 1MB -or (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ne $ExpectedManifestSha256) { throw 'Package manifest mismatch.' }
$data = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
if ($data.schema -ne 1 -or $data.product -ne 'SentinelAV.Telemetry' -or @($data.files).Count -lt 1 -or @($data.files).Count -gt 1024) { throw 'Invalid collector package.' }
$seen = @{}
foreach ($file in $data.files) {
    $name = [string]$file.path
    if (-not $name -or $name -match '[:\\]' -or $name.StartsWith('/') -or @($name.Split('/') | Where-Object { $_ -in @('','..','.') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count -gt 0 -or $seen.ContainsKey($name.ToLowerInvariant())) { throw 'Ambiguous/escaping package member.' }
    $seen[$name.ToLowerInvariant()] = $true
    $path = [IO.Path]::GetFullPath((Join-Path $source $name))
    if (-not $path.StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Package path escapes source.' }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $file.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.sha256) { throw 'Package member identity mismatch.' }
}
$destination = Join-Path $env:ProgramFiles ('SentinelAVTelemetry-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $destination | Out-Null
& icacls $destination /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Collector ACL staging failed.' }
foreach ($file in $data.files) {
    $target = Join-Path $destination $file.path
    $parent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Copy-Item -LiteralPath (Join-Path $source $file.path) -Destination $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $file.sha256) { throw 'Copied member integrity failure. Collector was not started.' }
}
& icacls $destination /setowner '*S-1-5-32-544' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Collector ownership staging failed.' }
Write-Output (Join-Path $destination 'SentinelAV.Telemetry.exe')
Write-Output 'Collector staged only. Kernel ETW authorization and service policy must be configured separately; no account privilege was changed.'

# Stage only known application/native build files. No certificate private keys or samples.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$labRoot = Join-Path $projectRoot 'artifacts/lab/windows-sandbox'
$packageRoot = Join-Path $projectRoot 'artifacts/dist/SentinelAV'
$nativeRoot = Join-Path $projectRoot 'artifacts/native/amsi'
function Assert-UnlinkedPath([string]$Path) {
    $entry = Get-Item -LiteralPath $Path -ErrorAction Stop
    while ($null -ne $entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Linked staging path rejected: ' + $entry.FullName) }
        $entry = $entry.Parent
    }
}
Assert-UnlinkedPath $projectRoot
if (-not (Test-Path -LiteralPath (Join-Path $packageRoot 'SentinelAV.exe') -PathType Leaf)) { throw 'Build the application first: .\build.ps1 -Installer' }
Assert-UnlinkedPath $packageRoot
$packageFiles = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force)
if ($packageFiles.Count -gt 8192) { throw 'Package file limit exceeded' }
if ($packageFiles | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Linked package member rejected' }
New-Item -ItemType Directory -Path $labRoot -Force | Out-Null
Assert-UnlinkedPath $labRoot
$kitId = [guid]::NewGuid().ToString('N')
$kitRoot = Join-Path $labRoot ('kit-' + $kitId)
$inputRoot = Join-Path $kitRoot 'input'
New-Item -ItemType Directory -Path $inputRoot | Out-Null
Copy-Item -LiteralPath $packageRoot -Destination (Join-Path $inputRoot 'App') -Recurse
$nativeOutput = Join-Path $inputRoot 'native'
New-Item -ItemType Directory -Path $nativeOutput | Out-Null
foreach ($name in @('SentinelAVAmsi.dll','SentinelAVAmsi.dev-signed.dll','AmsiHarness.exe')) {
    $source = Join-Path $nativeRoot $name
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Assert-UnlinkedPath $source
        Copy-Item -LiteralPath $source -Destination (Join-Path $nativeOutput $name)
    }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Start-Guest.cmd') -Destination (Join-Path $inputRoot 'Start-Guest.cmd')
$hashes = [ordered]@{}
Get-ChildItem -LiteralPath $inputRoot -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($inputRoot.Length + 1)
    $hashes[$relative] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifest = [ordered]@{schema=1;kit_id=$kitId;purpose='Harmless SentinelAV/AMSI development checks only';files=$hashes}
$manifestPath = Join-Path $inputRoot 'manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$escapedInput = [Security.SecurityElement]::Escape($inputRoot)
$configuration = @"
<Configuration>
  <Networking>Disable</Networking>
  <vGPU>Disable</vGPU>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$escapedInput</HostFolder>
      <SandboxFolder>C:\SentinelAV-Input</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\Windows\System32\cmd.exe /d /k C:\SentinelAV-Input\Start-Guest.cmd</Command>
  </LogonCommand>
</Configuration>
"@
$configPath = Join-Path $kitRoot 'SentinelAV-Test.wsb'
$configuration | Set-Content -LiteralPath $configPath -Encoding utf8
$status = [ordered]@{
    schema=1;kit_id=$kitId;created_utc=[DateTime]::UtcNow.ToString('o');configuration=$configPath;input=$inputRoot
    configuration_sha256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    manifest_sha256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    state='Prepared; guest isolation and checks not yet verified';guest_executed=$false
}
$status | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'latest.json') -Encoding utf8
Write-Output ('Prepared: ' + $configPath)
Write-Output 'No VM or guest has been started. No provider/service registration or Windows policy change was performed.'

# Purpose: Check installer deployment, uninstallation, and retained user data.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

# Isolated installer/reinstall check. Never uses the production AppId.
param([string]$WorkRoot='F:\SentinelAV-Work')
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$managedRoot = [IO.Path]::GetFullPath($WorkRoot)
if (-not (Test-Path -LiteralPath $managedRoot -PathType Container)) { throw 'Managed work root unavailable; no C: fallback' }
$packageRoot = Join-Path $managedRoot 'builds/dist/SentinelAV'
$fixtureId = [guid]::NewGuid().ToString()
$testRoot = Join-Path (Join-Path $managedRoot 'builds/installer-validation') ('installer-' + $fixtureId)
$installRoot = Join-Path $testRoot 'installed'
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{' + $fixtureId + '}_is1'
if (Test-Path -LiteralPath $uninstallKey) { throw 'Fixture registration already exists' }
New-Item -ItemType Directory -Path $testRoot | Out-Null
foreach ($target in @($testRoot,$workspace,$packageRoot)) {
    $entry = Get-Item -LiteralPath $target
    while ($null -ne $entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked fixture path rejected' }
        $entry = $entry.Parent
    }
}
if (-not ([IO.Path]::GetFullPath($installRoot)).StartsWith($managedRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Fixture escaped managed workspace' }
$script = Get-Content -LiteralPath (Join-Path $workspace 'packaging/installer.iss') -Raw
$script = $script -replace '(?m)^AppId=.*$',('AppId={{' + $fixtureId + '}')
$script = $script -replace '(?m)^OutputDir=.*$',('OutputDir=' + $testRoot)
$script = $script -replace '(?m)^OutputBaseFilename=.*$','OutputBaseFilename=InstallerFixture'
$script = [regex]::Replace($script,'(?m)^SourceDir=.*$',('SourceDir=' + $workspace))
$fixtureScript = Join-Path $testRoot 'fixture.iss'
$script | Set-Content -LiteralPath $fixtureScript -Encoding utf8
& (Join-Path $workspace 'tools/vendor/inno/ISCC.exe') ('/DPackageRoot='+$packageRoot) $fixtureScript *> (Join-Path $testRoot 'compile.log')
if ($LASTEXITCODE -ne 0) { Get-Content -LiteralPath (Join-Path $testRoot 'compile.log') -Tail 25; throw 'Fixture compiler failed' }
$definitionDir = Join-Path $installRoot '_internal\signature-data'
New-Item -ItemType Directory -Path $definitionDir -Force | Out-Null
$pointer = Join-Path $definitionDir 'active.json'
$trust = Join-Path $installRoot '_internal\trusted-update-keys.json'
$metadata = Get-Content -LiteralPath (Join-Path $packageRoot '_internal\signature-data\active.json') -Raw | ConvertFrom-Json
$metadata | Add-Member -NotePropertyName highest_signed_revision -NotePropertyValue 42 -Force
$metadata | Add-Member -NotePropertyName installer_fixture -NotePropertyValue 'preserve existing definitions' -Force
# Windows PowerShell's utf8 encoding adds a byte-order mark, which strict JSON readers reject.
$plainUtf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($pointer,($metadata | ConvertTo-Json -Depth 8),$plainUtf8)
[IO.File]::WriteAllText($trust,'{"schema":1,"keys":{},"installer_fixture":"preserve existing trust"}',$plainUtf8)
$pointerHash = (Get-FileHash -LiteralPath $pointer -Algorithm SHA256).Hash
$trustHash = (Get-FileHash -LiteralPath $trust -Algorithm SHA256).Hash
$installed = $false
try {
    foreach ($attempt in 1..2) {
        $process = Start-Process -FilePath (Join-Path $testRoot 'InstallerFixture.exe') -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER','/NOICONS','/TASKS=',('/DIR="' + $installRoot + '"')) -WindowStyle Hidden -PassThru -Wait
        if ($process.ExitCode -ne 0) { throw 'Fixture installation failed' }
        $installed = $true
        if ((Get-FileHash -LiteralPath $pointer -Algorithm SHA256).Hash -ne $pointerHash) { throw 'Installer overwrote definitions' }
        if ((Get-FileHash -LiteralPath $trust -Algorithm SHA256).Hash -ne $trustHash) { throw 'Installer overwrote publisher trust' }
        if (-not (Test-Path -LiteralPath $uninstallKey)) { throw 'Fixture registration missing' }
    }
    $smokeData = Join-Path $testRoot 'self-test-data'
    $process = Start-Process -FilePath (Join-Path $installRoot 'SentinelAV.exe') -ArgumentList @('--self-test','--data-dir',('"' + $smokeData + '"')) -WindowStyle Hidden -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw 'Installed self-test failed' }
    $smoke = Get-Content -LiteralPath (Join-Path $smokeData 'self-test.json') -Raw | ConvertFrom-Json
    if ($smoke.status -ne 'PASS' -or $smoke.scan.yara.research_rules -lt 1) { throw 'Installed rules or self-test did not pass' }
} finally {
    if ($installed) {
        $resolvedInstall = [IO.Path]::GetFullPath((Get-Item -LiteralPath $installRoot).FullName)
        if ($resolvedInstall -ne [IO.Path]::GetFullPath($installRoot) -or -not $resolvedInstall.StartsWith($testRoot + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Uninstall target escaped fixture directory' }
        if (((Get-Item -LiteralPath $resolvedInstall).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked uninstall target rejected' }
        $uninstaller = Join-Path $resolvedInstall 'unins000.exe'
        $process = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -WindowStyle Hidden -PassThru -Wait
        if ($process.ExitCode -ne 0) { throw 'Fixture uninstall failed' }
        if (Test-Path -LiteralPath $uninstallKey) { throw 'Fixture registration was not removed' }
        if (-not (Test-Path -LiteralPath (Join-Path $testRoot 'self-test-data/sentinelav.db'))) { throw 'User data was removed by uninstall' }
    }
}
Write-Output 'PASS: isolated install/reinstall preserves definitions and trust, installed YARA self-test, and uninstall'

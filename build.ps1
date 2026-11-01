param([switch]$Installer)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$sentinelPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
& $sentinelPython -m PyInstaller --noconfirm --distpath artifacts/dist --workpath artifacts/build packaging/SentinelAV.spec
if ($LASTEXITCODE -ne 0) { throw 'Executable build failed' }
if ($Installer) {
    $sentinelCompiler = Join-Path $PSScriptRoot 'tools/vendor/inno/ISCC.exe'
    if (-not (Test-Path -LiteralPath $sentinelCompiler)) { throw 'Portable Inno Setup compiler not found in build-tools/inno' }
    & $sentinelCompiler packaging/installer.iss
    if ($LASTEXITCODE -ne 0) { throw 'Installer build failed' }
}

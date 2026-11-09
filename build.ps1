# Purpose: Build the executable and optional installer using managed F: work storage.
# Works with: packaging/SentinelAV.spec; packaging/installer.iss; workspace.py
# Used by: the CLI, desktop launcher, or packaging workflow

param([switch]$Installer,[switch]$NativeEmulator,[switch]$PruneCache,[string]$WorkRoot='F:\SentinelAV-Work')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$sentinelPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
$env:PYTHONPATH = (Join-Path $PSScriptRoot 'src') + [IO.Path]::PathSeparator + $PSScriptRoot
$env:SENTINELAV_WORK_ROOT=$WorkRoot
if($PruneCache){
    & $sentinelPython -c "import tools;from sentinelav.workspace import Workspace;print(Workspace().prune_cache())"
    if($LASTEXITCODE -ne 0){throw 'Cache maintenance failed'}
}
$sentinelBuildRoot=& $sentinelPython -c "import tools;from sentinelav.workspace import Workspace;print(Workspace().area('builds'))"
if($LASTEXITCODE -ne 0){throw 'Managed work drive unavailable; no C: fallback is performed'}
$sentinelBuildRoot=([string]$sentinelBuildRoot).Trim()
$sentinelTemporary=Join-Path $WorkRoot 'cache/build-temp'
& $sentinelPython -c "import sys;from pathlib import Path;from sentinelav.workspace import unlinked;p=unlinked(Path(sys.argv[1]));p.mkdir(parents=True,exist_ok=True)" $sentinelTemporary
if($LASTEXITCODE -ne 0){throw 'Managed build temporary directory unavailable; no C: fallback is performed'}
$env:TEMP=$sentinelTemporary
$env:TMP=$sentinelTemporary
$env:PYINSTALLER_CONFIG_DIR=Join-Path $WorkRoot 'cache/PyInstaller'
& $sentinelPython -c "import tools,importlib.metadata,sys;from sentinelav.workspace import Workspace;p=Workspace().immutable_report({'python':sys.version,'dependencies':sorted([{'name':d.metadata['Name'],'version':d.version} for d in importlib.metadata.distributions()],key=lambda x:x['name'].lower())},'build-dependencies');print(p)"
if($LASTEXITCODE -ne 0){throw 'Cannot preserve dependency manifest'}
if ($NativeEmulator) {
    & $sentinelPython tools/build_emulator.py
    if ($LASTEXITCODE -ne 0) { throw 'Native emulator build failed' }
}
& $sentinelPython -m PyInstaller --noconfirm --distpath (Join-Path $sentinelBuildRoot 'dist') --workpath (Join-Path $sentinelBuildRoot 'pyinstaller') packaging/SentinelAV.spec
if ($LASTEXITCODE -ne 0) { throw 'Executable build failed' }
if ($Installer) {
    $sentinelCompiler = Join-Path $PSScriptRoot 'tools/vendor/inno/ISCC.exe'
    if (-not (Test-Path -LiteralPath $sentinelCompiler)) { throw 'Portable Inno Setup compiler not found in build-tools/inno' }
    & $sentinelCompiler ('/DPackageRoot='+ (Join-Path $sentinelBuildRoot 'dist/SentinelAV')) ('/DReleaseRoot='+ (Join-Path $sentinelBuildRoot 'release')) packaging/installer.iss
    if ($LASTEXITCODE -ne 0) { throw 'Installer build failed' }
}

# Purpose: Install declared analysis dependencies into the project Python environment.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

# Source dependencies only. No recursive submodule or specimen acquisition.
param([string]$WorkRoot='F:\SentinelAV-Work')
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
$python=Join-Path $project '.venv/Scripts/python.exe'
$env:SENTINELAV_WORK_ROOT=$WorkRoot
Push-Location -LiteralPath $project
try {
 $cache=& $python -c "import tools;from sentinelav.workspace import Workspace;print(Workspace().area('cache'))"
 if($LASTEXITCODE -ne 0){throw 'Managed work drive unavailable'}
 $env:PIP_CACHE_DIR=Join-Path $cache 'pip'
 $specs=@(
  @{name='speakeasy';url='https://github.com/mandiant/speakeasy.git';revision='57d22dd475be9897cc939e3a4f01608104b0f903'},
  @{name='EMBER2024';url='https://github.com/FutureComputing4AI/EMBER2024.git';revision='0ef753e81d98bf209f71b03cd331dfc190b5b54d'}
 )
 foreach($spec in $specs){
  $destination=Join-Path $cache $spec.name
  if(!(Test-Path -LiteralPath $destination)){
   & git -c submodule.recurse=false clone --no-recurse-submodules --no-checkout $spec.url $destination
   if($LASTEXITCODE -ne 0){throw 'Source clone failed'}
   & git -C $destination -c submodule.recurse=false checkout --detach $spec.revision
   if($LASTEXITCODE -ne 0){throw 'Pinned checkout failed'}
  }
  $actual=& git -C $destination rev-parse HEAD
  if($LASTEXITCODE -ne 0 -or $actual -ne $spec.revision){throw 'Existing dependency checkout does not match the reviewed revision'}
  if($spec.name -eq 'speakeasy'){
   & git -C $destination -c submodule.recurse=false submodule update --init -- deps/phnt deps/win32json
   if($LASTEXITCODE -ne 0){throw 'Required API metadata unavailable'}
  }
 }
 & $python -c "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('pip') else 1)"
 if($LASTEXITCODE -ne 0){
  & $python -m ensurepip
  if($LASTEXITCODE -ne 0){throw 'pip is unavailable; install pip in the project virtual environment first'}
 }
 & $python -m pip install -r requirements/requirements-analysis.txt
 if($LASTEXITCODE -ne 0){throw 'Analysis prerequisites installation failed'}
 foreach($spec in $specs){
  & $python -m pip install --no-deps (Join-Path $cache $spec.name)
  if($LASTEXITCODE -ne 0){throw 'Pinned analysis installation failed'}
 }
 Write-Output 'Analysis source installed. Build the reviewed Unicorn runtime before enabling emulation. No model or automatic policy was activated.'
} finally {Pop-Location}

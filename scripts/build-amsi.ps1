param([switch]$Test)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'A complete MSVC C++ installation was not found' }
$vcvars = Join-Path $installation 'VC/Auxiliary/Build/vcvars64.bat'
$outputRoot = Join-Path $projectRoot 'artifacts/native/amsi'
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$commands = @(
    '@echo off',
    ('call "' + $vcvars + '"'),
    'if errorlevel 1 exit /b 1',
    ('cd /d "' + $outputRoot + '"'),
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /O2 /MT /guard:cf /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 /LD "' + $projectRoot + '\native\amsi\provider.cpp" /Fe:SentinelAVAmsi.dll /link /DEF:"' + $projectRoot + '\native\amsi\provider.def" ole32.lib advapi32.lib /DYNAMICBASE /NXCOMPAT'),
    'if errorlevel 1 exit /b 1',
    ('cl /nologo /std:c++17 /EHsc /W4 /WX /O2 /MT /guard:cf /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 /DSENTINEL_AMSI_TESTING "' + $projectRoot + '\native\amsi\provider.cpp" "' + $projectRoot + '\native\amsi\harness.cpp" /Fe:AmsiHarness.exe /link ole32.lib advapi32.lib /DYNAMICBASE /NXCOMPAT'),
    'if errorlevel 1 exit /b 1'
)
if ($Test) {
    $commands += ('AmsiHarness.exe --dll "' + $outputRoot + '\SentinelAVAmsi.dll"')
    $commands += 'if errorlevel 1 exit /b 1'
}
$commandFile = Join-Path $outputRoot 'build.cmd'
$commands | Set-Content -LiteralPath $commandFile -Encoding ascii
& cmd.exe /d /c $commandFile
if ($LASTEXITCODE -ne 0) { throw 'Native AMSI build/check failed' }
Write-Output 'Built unsigned x64 prototype. No provider registration or signing-policy changes were made.'

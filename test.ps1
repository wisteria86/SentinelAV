# Purpose: Run structural checks, unit tests, and optional UI regression checks.
# Works with: tools/maintenance/check_structure.py; tests/unit; tests/ui
# Used by: the CLI, desktop launcher, or packaging workflow

param([switch]$UI,[string]$TempRoot='F:\SentinelAV-Work\cache\qualification-temp')
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$previousPythonPath = $env:PYTHONPATH
try {
    # Response intentionally refuses files inside its own installation/project.
    # Use the F: temporary workspace so harmless response fixtures exercise
    # the real guard without weakening it. Tests clean up their own directories.
    $fixtureTemp = $TempRoot
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetPathRoot($fixtureTemp)))) {
        throw 'Test work drive unavailable; specify an existing -TempRoot. No C: fallback is performed.'
    }
    New-Item -ItemType Directory -Path $fixtureTemp -Force | Out-Null
    $env:TEMP = $fixtureTemp
    $env:TMP = $fixtureTemp
    $env:PYTHONPATH = (Join-Path $PSScriptRoot 'src') + [IO.Path]::PathSeparator + $PSScriptRoot
    $python = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
    & $python tools/maintenance/check_structure.py
    if ($LASTEXITCODE -ne 0) { throw 'Module size/header checks failed' }
    & $python -m unittest discover -s tests/unit -t .
    if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed' }
    if ($UI) {
        Get-ChildItem -LiteralPath 'tests/ui' -Filter 'verify_*ui.py' | ForEach-Object {
            & $python -m ('tests.ui.' + $_.BaseName)
            if ($LASTEXITCODE -ne 0) { throw ('UI check failed: ' + $_.Name) }
        }
    }
} finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    $env:PYTHONPATH = $previousPythonPath
    Pop-Location
}

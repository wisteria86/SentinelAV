param([switch]$UI)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
try {
    # Response intentionally refuses files inside its own installation/project.
    # Use a sibling temporary workspace so harmless response fixtures exercise
    # the real guard without weakening it. Tests clean up their own directories.
    $fixtureTemp = Join-Path (Split-Path -Parent $PSScriptRoot) 'tmp/SentinelAVTests'
    New-Item -ItemType Directory -Path $fixtureTemp -Force | Out-Null
    $env:TEMP = $fixtureTemp
    $env:TMP = $fixtureTemp
    $python = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
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
    Pop-Location
}

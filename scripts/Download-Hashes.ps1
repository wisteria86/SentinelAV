$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$sentinelPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $sentinelPython)) {
    throw 'SentinelAV Python environment was not found.'
}
& $sentinelPython -m tools.feeds.download_hashes
if ($LASTEXITCODE -ne 0) { throw 'Hash import did not complete. Active signatures were not changed.' }

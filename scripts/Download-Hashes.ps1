# Purpose: Invoke the hash-feed downloader using the project Python environment.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$sentinelPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $sentinelPython)) {
    throw 'SentinelAV Python environment was not found.'
}
& $sentinelPython -m tools.feeds.download_hashes
if ($LASTEXITCODE -ne 0) { throw 'Hash import did not complete. Active signatures were not changed.' }

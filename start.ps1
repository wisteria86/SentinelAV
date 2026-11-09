# Purpose: Launch the desktop application using the project Python environment.
# Works with: app.py; src/sentinelav/entrypoint.py
# Used by: the CLI, desktop launcher, or packaging workflow

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& "$PSScriptRoot/.venv/Scripts/python.exe" app.py

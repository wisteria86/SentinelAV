# Purpose: Resolve managed F: lab storage without a system-drive fallback.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Shared F: lab storage. No automatic system-drive fallback.
function Get-SentinelLabRoot {
    $project=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $python=Join-Path $project '.venv/Scripts/python.exe'
    Push-Location -LiteralPath $project
    try {
        $managed=& $python -c "import tools;from sentinelav.workspace import Workspace;print(Workspace().area('lab'))"
        if($LASTEXITCODE -ne 0){throw 'Managed lab drive unavailable; C: fallback is disabled'}
        return Join-Path (([string]$managed).Trim()) 'windows-sandbox'
    } finally {Pop-Location}
}

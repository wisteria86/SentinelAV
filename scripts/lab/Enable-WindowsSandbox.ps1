# Purpose: Check and enable the Windows Sandbox optional feature with explicit restart handling.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Enable the built-in Windows feature only. Never restart automatically.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator, then run this script. Windows feature activation requires administrator access.'
}
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot = Get-SentinelLabRoot
New-Item -ItemType Directory -Path $labRoot -Force | Out-Null
$statusPath = Join-Path $labRoot 'feature-status.json'
Start-Transcript -LiteralPath (Join-Path $labRoot 'enable-feature.log') -Append | Out-Null
try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
    $restart = $false
    if ($feature.State -eq 'Enabled') {
        Write-Output 'Windows Sandbox is already enabled. No feature change was needed.'
    } elseif ($feature.State -eq 'EnablePending') {
        $restart = $true
        Write-Output 'Windows Sandbox activation is pending. Save your work and restart Windows when convenient.'
    } else {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
        $restart = [bool]$result.RestartNeeded
        if ($restart) { Write-Output 'Save your work and restart Windows when convenient. This script will not restart it.' }
    }
    $current = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
    @{state=[string]$current.State;restart_needed=$restart;checked_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
} catch {
    @{state='Failed';error=$_.Exception.Message;checked_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
    throw
} finally { Stop-Transcript | Out-Null }

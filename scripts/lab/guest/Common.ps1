# Purpose: Share owned deployment paths, state checks, and recovery helpers for guest integration.
# Works with: Install-Before.ps1; Install-After.ps1; Register.ps1; Remove.ps1
# Used by: the CLI, desktop launcher, or packaging workflow

# Fixed commands supplied to the guest through the official Sandbox exec API.
# No execution-policy changes, trust-store imports or arbitrary action endpoint.
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or ![Environment]::Is64BitProcess) { throw 'Guest administrator guard failed' }
if (!(Test-Path -LiteralPath 'C:\SentinelAV-Test\preflight.json')) { throw 'Verified guest baseline required' }
if ((Get-Content -LiteralPath 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json).kit_id -ne $expectedKitId) { throw 'Guest kit identity mismatch' }
if ((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine') { throw 'VM identity required' }
if (@(Get-NetAdapter | Where-Object Status -eq 'Up').Count) { throw 'Guest must remain offline' }
$root='C:\SentinelAV-Test'
$statePath=Join-Path $root 'deployment-state.json'
$install=Join-Path $env:ProgramFiles 'SentinelAVProtection'
$dataRoot=Join-Path $env:ProgramData 'SentinelAVProtection'
$providerRoot=Join-Path $env:ProgramFiles 'SentinelAVAmsiTest'
$watch=Join-Path $root 'Watch'
$clsid='{DE3BE5B6-4DB7-4F8F-A71C-0576CDAF4581}'
$classKey='HKLM:\SOFTWARE\Classes\CLSID\'+$clsid
$providerKey='HKLM:\SOFTWARE\Microsoft\AMSI\Providers\'+$clsid
$probe=Join-Path $root 'native\AmsiProbe.exe'
function Save-State { $script:state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $statePath -Encoding utf8 }
function Read-State {
    if ((Get-Item -LiteralPath $statePath).Length -gt 65536) { throw 'Invalid state size' }
    $script:state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($state.id -notmatch '^[0-9a-f]{32}$' -or $state.id -ne $expectedDeploymentId -or $state.machine -ne $env:COMPUTERNAME) { throw 'Invalid deployment ownership' }
}
function Assert-Unlinked([string]$path) {
    $entry=Get-Item -LiteralPath $path
    while ($entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked deployment path refused' }
        $entry=$entry.Parent
    }
}
function Mark-Owned([string]$path) {
    Assert-Unlinked $path
    Set-Content -LiteralPath (Join-Path $path '.sentinelav-deployment') -Value $state.id -Encoding ascii
}
function Other-Providers {
    @((Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue).PSChildName | Where-Object { $_ -ne $clsid } | Sort-Object) -join '|'
}
function Assert-OtherProviders {
    if ((Other-Providers) -ne $state.other_providers) { throw 'Other AMSI provider inventory changed' }
}

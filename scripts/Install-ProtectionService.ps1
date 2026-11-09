# Purpose: Install the least-privilege protection service with protected code and policy.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

param([Parameter(Mandatory=$true)][string[]]$WatchFolders,[string]$PackageRoot='F:\SentinelAV-Work\builds\dist\SentinelAV',[switch]$TrackAppChanges)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this reviewed installer from an administrator PowerShell window.' }
$serviceName='SentinelAVProtection'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Service already exists. Stop and review its deployment before replacing it.' }
$destination=Join-Path $env:ProgramFiles 'SentinelAVProtection'
$configuration=Join-Path $env:ProgramData 'SentinelAVProtection'
if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $configuration)) { throw 'Deployment directories already exist; refusing to overwrite them.' }
if (-not (Test-Path -LiteralPath (Join-Path $PackageRoot 'SentinelAV.exe'))) { throw 'Build the packaged application first or supply its trusted package directory.' }
if ($WatchFolders.Count -gt 64) { throw 'Too many folders' }
foreach ($folder in $WatchFolders) {
    if (-not [IO.Path]::IsPathRooted($folder) -or -not (Test-Path -LiteralPath $folder -PathType Container)) { throw 'Use existing absolute watch folders.' }
}
# Refuse linked deployment ancestors. No recursive deletion or replacement.
foreach ($parent in @($env:ProgramFiles,$env:ProgramData)) {
    $entry=Get-Item -LiteralPath $parent -Force
    while ($null -ne $entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked deployment path rejected' }
        $entry=$entry.Parent
    }
}
New-Item -ItemType Directory -Path $destination,$configuration | Out-Null
& icacls.exe $destination '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Code ACL configuration failed' }
& icacls.exe $configuration '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' ('*'+$identity.User.Value+':(OI)(CI)R') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Policy ACL configuration failed' }
Copy-Item -Path (Join-Path $PackageRoot '*') -Destination $destination -Recurse
& icacls.exe (Join-Path $destination '*') '/reset' '/T' '/C' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Inherited code ACL reset failed' }
$data=Join-Path $configuration 'data'
New-Item -ItemType Directory -Path $data | Out-Null
& icacls.exe $data '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' ('*'+$identity.User.Value+':(OI)(CI)R') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service data ACL configuration failed' }
@{folders=$WatchFolders;owner_sid=$identity.User.Value;amsi_broker=$false;watch_app_changes=[bool]$TrackAppChanges} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $configuration 'policy.json') -Encoding utf8
$hashes=[ordered]@{}
Get-ChildItem -LiteralPath $destination -File -Recurse | ForEach-Object {
    $relative=$_.FullName.Substring($destination.Length+1)
    $hashes[$relative]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$hashes | ConvertTo-Json -Depth 2 | Set-Content -LiteralPath (Join-Path $destination 'code-integrity.json') -Encoding utf8
& icacls.exe $destination '/setowner' '*S-1-5-32-544' '/T' '/C' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Code ownership configuration failed' }
& icacls.exe $configuration '/setowner' '*S-1-5-32-544' '/T' '/C' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Policy ownership configuration failed' }
$binary='"'+(Join-Path $destination 'SentinelAV.exe')+'" --windows-service'
$credential=[Management.Automation.PSCredential]::new('NT AUTHORITY\LocalService',[Security.SecureString]::new())
New-Service -Name $serviceName -BinaryPathName $binary -DisplayName 'SentinelAV Protection' -StartupType Manual -Credential $credential -Description 'Least-privilege SentinelAV monitoring; protected administrator policy.' | Out-Null
$serviceDacl='D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LC;;;AU)(A;;CCLCSWLOCRRC;;;'+$identity.User.Value+')'
& sc.exe sdset $serviceName $serviceDacl | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SCM access-control configuration failed; service remains manual and stopped.' }
& sc.exe failure $serviceName 'reset=' '86400' 'actions=' 'restart/5000/restart/15000/none/0' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service recovery configuration failed' }
Set-Service -Name $serviceName -StartupType Automatic
Write-Output 'Service installed, not started. Review folder permissions and policy, then use Start-Service SentinelAVProtection. Existing folder ACLs were not modified.'

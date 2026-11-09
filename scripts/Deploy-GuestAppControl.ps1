# Purpose: Deploy the explicitly selected application-control policy inside the test guest.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

param(
    [Parameter(Mandatory=$true)][string]$AuditXml,
    [ValidateSet('Audit','Enforced')][string]$Mode='Audit',
    [Parameter(Mandatory=$true)][switch]$DisposableOfflineGuest
)
# Explicit guest-only deployment code; not called by the application or installer.
$ErrorActionPreference = 'Stop'
if (-not $DisposableOfflineGuest -or $env:USERNAME -ne 'WDAGUtilityAccount' -or
    (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or
    @(Get-NetAdapter | Where-Object Status -eq 'Up').Count -gt 0) {
    throw 'App Control deployment is limited to the disposable offline test guest.'
}
$source = (Resolve-Path -LiteralPath $AuditXml).Path
$guestRoot = [IO.Path]::GetFullPath('C:\SentinelAV-Test\')
if (-not $source.StartsWith($guestRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Policy must already reside in the guest workspace.' }
Import-Module ConfigCI -ErrorAction Stop
$workspace = Join-Path $guestRoot ('AppControl-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace | Out-Null
$policy = Join-Path $workspace 'policy.xml'
Copy-Item -LiteralPath $source -Destination $policy
if ($Mode -eq 'Enforced') { Set-RuleOption -FilePath $policy -Option 3 -Delete }
else { Set-RuleOption -FilePath $policy -Option 3 }
$binary = Join-Path $workspace 'policy.cip'
ConvertFrom-CIPolicy -XmlFilePath $policy -BinaryFilePath $binary | Out-Null
$tool = Join-Path $env:windir 'System32\CiTool.exe'
if (-not (Test-Path -LiteralPath $tool)) { throw 'Windows CiTool is unavailable on this guest.' }
& $tool --update-policy $binary -json
if ($LASTEXITCODE -ne 0) { throw 'Windows rejected policy deployment. No security settings were weakened.' }
Write-Output 'Guest policy submitted to Windows. Verify activation; guest disposal is the rollback boundary.'

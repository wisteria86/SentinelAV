# Purpose: Export Windows application-control audit evidence for review.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

param(
    [Parameter(Mandatory=$true)][string]$Manifest,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
# Generates reviewable audit-mode policy files only; never deploys a policy.
# ConfigCI API reference: https://learn.microsoft.com/powershell/module/configci/new-cipolicy
$ErrorActionPreference = 'Stop'
Import-Module ConfigCI -ErrorAction Stop
$entries = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
if ($entries.schema -ne 1 -or @($entries.files).Count -lt 1 -or @($entries.files).Count -gt 256) {
    throw 'Expected schema 1 with 1..256 explicitly approved file paths and SHA-256 hashes.'
}
$destination = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'Output directory must be new.' }
$approved = @()
foreach ($entry in $entries.files) {
    $resolved = (Resolve-Path -LiteralPath $entry.path).Path
    $item = Get-Item -LiteralPath $resolved
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'Regular files only.' }
    if ($entry.sha256 -notmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) {
        throw 'Approved file identity does not match.'
    }
    $approved += $resolved
}
$template = Join-Path $env:windir 'schemas/CodeIntegrity/ExamplePolicies/AllowAll.xml'
if (-not (Test-Path -LiteralPath $template)) { throw 'Windows AllowAll policy template unavailable.' }
New-Item -ItemType Directory -Path $destination | Out-Null
$rules = @()
foreach ($path in $approved) { $rules += New-CIPolicyRule -DriverFilePath $path -Level Hash -Deny }
$deny = Join-Path $destination 'reviewed-deny-rules.xml'
$merged = Join-Path $destination 'SentinelAV-Audit.xml'
New-CIPolicy -FilePath $deny -Rules $rules -UserPEs -MultiplePolicyFormat | Out-Null
Merge-CIPolicy -PolicyPaths @($template,$deny) -OutputFilePath $merged | Out-Null
Set-RuleOption -FilePath $merged -Option 3
ConvertFrom-CIPolicy -XmlFilePath $merged -BinaryFilePath (Join-Path $destination 'SentinelAV-Audit.cip') | Out-Null
Write-Output "Audit files generated under $destination. No policy was installed or enforced."

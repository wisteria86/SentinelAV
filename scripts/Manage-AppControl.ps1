# Purpose: Inspect or manage the explicitly selected Windows application-control policy.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('DeployAudit','DeployEnforced','Status','RemoveManaged')][string]$Action,
    [string]$PolicyXml,
    [string]$ExpectedXmlSha256,
    [string]$Receipt
)
# Production lifecycle entry point. No code in SentinelAV invokes it implicitly.
# Audit is an explicit action; enforcement requires a separate explicit action.
$ErrorActionPreference = 'Stop'
$tool = Join-Path $env:windir 'System32\CiTool.exe'
if (-not (Test-Path -LiteralPath $tool)) { throw 'Windows CiTool unavailable.' }
if ($Action -eq 'Status') {
    & $tool --list-policies -json
    if ($LASTEXITCODE -ne 0) { throw 'Windows policy status query failed.' }
    return
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrative deployment authorization is required.' }
$base = Join-Path $env:ProgramData 'SentinelAVPolicyReceipts'
if (Test-Path -LiteralPath $base) {
    $entry = Get-Item -LiteralPath $base -Force
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Receipt store cannot be a link.' }
    $acl = Get-Acl -LiteralPath $base
    $owner = ([Security.Principal.NTAccount]::new($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Existing receipt store is not administratively owned.' }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $write = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and $sid -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Receipt store has an untrusted writer.' }
    }
} else { New-Item -ItemType Directory -Path $base | Out-Null }
& icacls $base /setowner '*S-1-5-32-544' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot set administrative receipt ownership.' }
& icacls $base /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect deployment receipts.' }
if ($Action -eq 'RemoveManaged') {
    $resolved = (Resolve-Path -LiteralPath $Receipt).Path
    if (-not $resolved.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Use a receipt inside the protected managed store.' }
    $receiptItem = Get-Item -LiteralPath $resolved -Force
    if (($receiptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $receiptItem.Length -gt 16384) { throw 'Invalid receipt file.' }
    $receiptOwner = ([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $resolved).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($receiptOwner -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Receipt is not administratively owned.' }
    $record = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ($record.schema -ne 1 -or $record.product -ne 'SentinelAV' -or $record.state -ne 'Submitted') { throw 'Invalid managed receipt.' }
    $id = [guid]::Parse($record.policy_id).ToString('B')
    & $tool --remove-policy $id -json
    if ($LASTEXITCODE -ne 0) { throw 'Windows rejected removal; signed-policy restrictions may apply. No bypass was attempted.' }
    $record.state = 'Removal submitted'
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resolved -Encoding UTF8
    Write-Output 'Removal submitted for the recorded SentinelAV policy only. Verify Windows policy status.'
    return
}
if ($ExpectedXmlSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Expected policy SHA-256 is required.' }
$source = (Resolve-Path -LiteralPath $PolicyXml).Path
$item = Get-Item -LiteralPath $source
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 16MB) { throw 'Invalid policy input.' }
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedXmlSha256) { throw 'Reviewed policy hash mismatch.' }
Import-Module ConfigCI -ErrorAction Stop
$workspace = Join-Path $base ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace | Out-Null
$staged = Join-Path $workspace 'submitted.xml'
Copy-Item -LiteralPath $source -Destination $staged
if ((Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash -ne $ExpectedXmlSha256) { throw 'Policy changed during staging.' }
# A fresh ID avoids modifying or replacing any existing OS or organization policy.
$id = [guid]::NewGuid().ToString('B')
$settings = [System.Xml.XmlReaderSettings]::new()
$settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
$settings.XmlResolver = $null
$reader = [System.Xml.XmlReader]::Create($staged,$settings)
try { $xml = [System.Xml.XmlDocument]::new(); $xml.XmlResolver=$null; $xml.Load($reader) } finally { $reader.Dispose() }
$ns = [System.Xml.XmlNamespaceManager]::new($xml.NameTable)
$ns.AddNamespace('p','urn:schemas-microsoft-com:sipolicy')
$policyId = $xml.SelectSingleNode('/p:SiPolicy/p:PolicyID',$ns)
$baseId = $xml.SelectSingleNode('/p:SiPolicy/p:BasePolicyID',$ns)
if ($null -eq $policyId -or $null -eq $baseId) { throw 'Expected multiple-policy base format.' }
if ($Action -eq 'DeployEnforced') {
    $denyRules=@($xml.SelectNodes('/p:SiPolicy/p:FileRules/p:Deny',$ns))
    if ($denyRules.Count -lt 1 -or @($denyRules | Where-Object { -not $_.HasAttribute('Hash') }).Count -gt 0) { throw 'Enforced iteration-one policies support explicit hash denies only.' }
    $allowIds=@($xml.SelectNodes('/p:SiPolicy/p:FileRules/p:Allow[@FileName="*"]',$ns) | ForEach-Object { $_.GetAttribute('ID') })
    if ($allowIds.Count -lt 1) { throw 'Enforcement requires the reviewed AllowAll-plus-hash-deny base.' }
    foreach ($scenario in @('12','131')) {
        $references=@($xml.SelectNodes("/p:SiPolicy/p:SigningScenarios/p:SigningScenario[@Value='$scenario']/p:ProductSigners/p:FileRulesRef/p:FileRuleRef",$ns))
        if (@($references | Where-Object { $_.GetAttribute('RuleID') -in $allowIds }).Count -lt 1) { throw 'A broad allow reference is missing; refusing an accidental default-deny policy.' }
    }
}
$policyId.InnerText=$id; $baseId.InnerText=$id
$xml.Save($staged)
if ($Action -eq 'DeployEnforced') { Set-RuleOption -FilePath $staged -Option 3 -Delete }
else { Set-RuleOption -FilePath $staged -Option 3 }
$binary = Join-Path $workspace 'submitted.cip'
ConvertFrom-CIPolicy -XmlFilePath $staged -BinaryFilePath $binary | Out-Null
$receiptPath = Join-Path $workspace 'receipt.json'
$mode=if ($Action -eq 'DeployEnforced') { 'Enforced' } else { 'Audit' }
$record = [ordered]@{schema=1;product='SentinelAV';policy_id=$id;mode=$mode;state='Prepared';
    reviewed_xml_sha256=$ExpectedXmlSha256;submitted_binary_sha256=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash;
    submitted_utc=[DateTime]::UtcNow.ToString('o');policy_file=$binary}
$record | ConvertTo-Json | Set-Content -LiteralPath $receiptPath -Encoding UTF8
& icacls $workspace /setowner '*S-1-5-32-544' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect staged policy ownership.' }
& $tool --update-policy $binary -json
if ($LASTEXITCODE -ne 0) { throw "Windows rejected deployment. Prepared receipt retained: $receiptPath" }
$record.state='Submitted'
$record | ConvertTo-Json | Set-Content -LiteralPath $receiptPath -Encoding UTF8
Write-Output "$mode policy submitted; activation is not yet verified. Managed receipt: $receiptPath"

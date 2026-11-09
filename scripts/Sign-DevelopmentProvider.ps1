# Purpose: Sign the native development provider and record its exact binary identity.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint)
# Sign a separate app-owned development copy; never export keys or add trust.
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$folder=Join-Path $projectRoot 'artifacts/native/amsi'
$source=Join-Path $folder 'SentinelAVAmsi.dll'
$target=Join-Path $folder 'SentinelAVAmsi.dev-signed.dll'
$entry=Get-Item -LiteralPath $source -Force
while ($entry) {
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked signing path rejected' }
    $entry=$entry.Parent
}
if (Test-Path -LiteralPath $target) {
    if (((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Linked signing target rejected' }
}
$certificate=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$Thumbprint)
if (!$certificate.HasPrivateKey -or $certificate.NotAfter -le (Get-Date) -or $certificate.Subject -ne $certificate.Issuer) { throw 'A current self-signed development certificate with a private key is required' }
$codeSigning=@($certificate.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'} | ForEach-Object {$_.EnhancedKeyUsages} | Where-Object Value -eq '1.3.6.1.5.5.7.3.3')
if (!$codeSigning.Count) { throw 'Certificate is not enabled for code signing' }
Copy-Item -LiteralPath $source -Destination $target -Force
$signature=Set-AuthenticodeSignature -FilePath $target -Certificate $certificate -HashAlgorithm SHA256
if (!$signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $certificate.Thumbprint -or $signature.Status -in @('HashMismatch','NotSigned')) { throw 'Development signing failed' }
@{source_sha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash;signed_sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash;thumbprint=$certificate.Thumbprint;trust_status=[string]$signature.Status;created_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'signing-record.json') -Encoding utf8
Write-Output ('Development copy signed; trust status: '+$signature.Status+'. No trust store or policy was changed.')

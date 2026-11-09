# Purpose: Validate the guest runtime-job contract using controlled test inputs.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Executes only a copied, Microsoft-signed Windows whoami utility in the guest.
# Exercises the public controller, bounded summary, and disposal/reset path.
$ErrorActionPreference='Stop'
$project=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
& (Join-Path $PSScriptRoot 'Test-SandboxBoundary.ps1')
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$state=Get-Content -LiteralPath (Join-Path (Get-SentinelLabRoot) 'latest.json') -Raw | ConvertFrom-Json
$guest=[string]$state.guest_id
function Invoke-SafeGuest([string]$code) {
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $reply=wsb.exe exec --id $guest -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
    if($null -eq $reply.ExitCode){throw 'No safe guest status returned'}
    return [long]$reply.ExitCode
}
$prepare=@'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or @(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 50}
$source=Join-Path $env:windir 'System32\whoami.exe'
$signature=Get-AuthenticodeSignature -LiteralPath $source
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike '*Microsoft*'){exit 51}
$hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$root='C:\SentinelAV-Test\RuntimeSafeCorpus'
New-Item -ItemType Directory -Path (Join-Path $root 'corpus') | Out-Null
Copy-Item -LiteralPath $source -Destination (Join-Path $root 'corpus/whoami.bin')
if((Get-FileHash -LiteralPath (Join-Path $root 'corpus/whoami.bin') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash){exit 52}
@{schema=1;files=@(@{path='whoami.bin';sha256=$hash;label='benign';provenance='Guest Windows image; valid Microsoft Authenticode signature verified before copying'})} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'corpus/manifest.json') -Encoding utf8
@{schema=1;purpose='Safe runtime fixture setup, not a malware evaluation'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'report.json') -Encoding utf8
@{report=(Join-Path $root 'report.json')} | ConvertTo-Json | Set-Content -LiteralPath 'C:\SentinelAV-Test\static-corpus-latest.json' -Encoding utf8
exit 0
'@
if((Invoke-SafeGuest $prepare) -ne 0){throw 'Safe guest fixture preparation failed'}
$sha=(Get-FileHash -LiteralPath (Join-Path $env:windir 'System32/whoami.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
$compare="`$m=Get-Content -LiteralPath 'C:\SentinelAV-Test\RuntimeSafeCorpus\corpus\manifest.json' -Raw | ConvertFrom-Json;if(`$m.files[0].sha256 -eq '$sha'){exit 0}else{exit 55}"
if((Invoke-SafeGuest $compare) -ne 0){
    $sha=''
    for($i=0;$i -lt 16;$i++){
        $query="`$m=Get-Content -LiteralPath 'C:\SentinelAV-Test\RuntimeSafeCorpus\corpus\manifest.json' -Raw | ConvertFrom-Json;exit (1073741824+[Convert]::ToInt32(`$m.files[0].sha256.Substring($($i*4),4),16))"
        $value=Invoke-SafeGuest $query
        if($value -lt 1073741824 -or $value -gt 1073807359){throw 'Invalid safe-fixture hash metadata'}
        $sha+=('{0:x4}' -f ($value-1073741824))
    }
}
$folder=Join-Path $project ('artifacts/lab/runtime-validation/'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$request=Join-Path $folder 'request.json'
@{schema=1;authorization='RUN_ONLY_IN_DISPOSABLE_OFFLINE_GUEST';sha256=$sha;seconds=3} | ConvertTo-Json | Set-Content -LiteralPath $request -Encoding utf8
$output=@(& (Join-Path $PSScriptRoot 'Invoke-RuntimeJob.ps1') -JobManifest $request)
$output | ForEach-Object {Write-Output $_}
$summary=$output | Where-Object {$_ -is [string] -and $_.StartsWith('{')} | Select-Object -Last 1 | ConvertFrom-Json
if(!$summary.execution_attempted -or !$summary.guest_disposal_verified -or $summary.status -eq 'Incomplete' -or $summary.status -eq 'Guest disposal failed'){throw 'Safe runtime controller lifecycle failed'}
@{status='PASS';safe_program='Microsoft-signed whoami.exe from guest Windows';sample_sha256=$sha;real_malware_executed=$false;
    runtime_controller=$summary;guest_disposal_verified=$true} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $folder 'validation.json') -Encoding utf8
Write-Output ('PASS: harmless guest execution, bounded host summary, and registered guest disposal. Evidence: '+$folder)

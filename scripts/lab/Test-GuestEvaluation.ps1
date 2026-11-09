# Purpose: Validate evaluation output and required guest evidence.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Test-SandboxBoundary.ps1')
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot=Get-SentinelLabRoot
$state=Get-Content -LiteralPath (Join-Path $labRoot 'latest.json') -Raw | ConvertFrom-Json
$code=@'
$ErrorActionPreference='Stop'
$r=Get-Content -LiteralPath 'C:\SentinelAV-Test\SelfTest\corpus-evaluation.json' -Raw | ConvertFrom-Json
if($r.sample_execution -ne $false -or $r.sample_extraction -ne $false -or $r.response_actions -ne $false){exit 90}
$expected=@{'ordinary.txt'='not_detected';'renamed.bin'='detected';'utf16.txt'='detected';'nested.zip'='detected';'unsupported.7z'='unavailable'}
if(@($r.rows).Count -ne 5){exit 91}
foreach($entry in $r.rows){if($entry.label -ne 'test' -or $expected[$entry.path] -ne $entry.outcome){exit 92}; $expected.Remove($entry.path)}
if($expected.Count -or $r.status -ne 'Incomplete / review omissions'){exit 93}
$report='C:\SentinelAV-Test\Evaluation-'+[guid]::NewGuid().ToString('N')
$process=Start-Process -FilePath 'C:\SentinelAV-Test\App\SentinelAV.exe' -ArgumentList @('--evaluate-corpus','C:\SentinelAV-Test\SelfTest\evaluation-fixtures\manifest.json','--evaluation-output',$report) -WindowStyle Hidden -PassThru
try {
    if(!$process.WaitForExit(120000)){ $process.Kill(); throw 'Harmless evaluation CLI timed out' }
    if($process.ExitCode -ne 2){exit 94}
} finally {$process.Dispose()}
$cli=Get-Content -LiteralPath (Join-Path $report 'report.json') -Raw | ConvertFrom-Json
if($cli.manifest_sha256 -ne $r.manifest_sha256 -or $cli.status -ne $r.status -or $cli.sample_execution -ne $false){exit 95}
if($cli.summary.test.detected -ne 3 -or $cli.summary.test.not_detected -ne 1 -or $cli.summary.test.unavailable -ne 1){exit 96}
if(!(Test-Path -LiteralPath (Join-Path $report 'report.html'))){exit 97}
exit 0
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
$reply=wsb.exe exec --id $state.guest_id -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
if($null -eq $reply.ExitCode -or $reply.ExitCode -ne 0){throw ('Guest static evaluation check failed: '+$reply.ExitCode)}
@{checked_utc=[DateTime]::UtcNow.ToString('o');guest_id=$state.guest_id;kit_id=$state.kit_id;status='PASS';generated_fixtures=5;expected_detections=3;expected_not_detected=1;expected_unavailable=1;standalone_cli_verified=$true;json_html_reports_verified=$true;real_malware_tested=$false;sample_execution=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'static-evaluation-validation.json') -Encoding utf8
Write-Output 'PASS: five packaged static-evaluation fixtures; incomplete coverage correctly reported, no sample execution.'

# Purpose: Invoke the pinned, guest-only static pilot evaluation.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# One pinned static scan. Never launch a sample or alter antivirus settings.
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Test-SandboxBoundary.ps1')
$project=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$lab=Get-SentinelLabRoot
$state=Get-Content -LiteralPath (Join-Path $lab 'latest.json') -Raw | ConvertFrom-Json
$inventory=Get-Content -LiteralPath (Join-Path $state.input 'manifest.json') -Raw | ConvertFrom-Json
if(!$inventory.files.'pilot.sealed'){throw 'Prepare a kit with -SealedStaticPilot first'}
$python=Join-Path $project '.venv/Scripts/python.exe'
Push-Location -LiteralPath $project
try {
    # Capture the transfer key in memory only. Do not log or persist it in the kit.
    $key=& $python -c "import tools,base64; from pathlib import Path; from sentinelav.response.response import dpapi; print(base64.b64encode(dpapi(Path('artifacts/lab/sealed-static-pilot/transfer-key.dpapi').read_bytes(),True)).decode())"
    if($LASTEXITCODE -ne 0 -or $key -notmatch '^[A-Za-z0-9+/]{43}=$'){throw 'Cannot unlock transfer key'}
    $code=@'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount'){exit 20}
if(@(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 21}
$p=Get-Content -LiteralPath 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json
if($p.kit_id -ne '__KIT__'){exit 22}
$process=Start-Process -FilePath 'C:\SentinelAV-Test\App\SentinelAV.exe' -ArgumentList @('--static-pilot-key','__KEY__') -WindowStyle Hidden -PassThru
try {
    if(!$process.WaitForExit(120000)){$process.Kill();exit 23}
    if($process.ExitCode -ne 0){exit $process.ExitCode}
} finally {$process.Dispose()}
$latest=Get-Content -LiteralPath 'C:\SentinelAV-Test\static-pilot-latest.json' -Raw | ConvertFrom-Json
$reportPath=[IO.Path]::GetFullPath($latest.report)
if($reportPath -notmatch '^C:\\SentinelAV-Test\\StaticPilot-[0-9a-f]{32}\\report\.json$'){exit 24}
$r=Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
if($r.sample_execution -ne $false -or $r.response_actions -ne $false -or !$r.pilot.guest_only_sample_unpacking){exit 25}
if($r.pilot.sample_sha256 -ne 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa' -or @($r.rows).Count -ne 1){exit 26}
$row=$r.rows[0]
$outcomes=@('detected','not_detected','detected_incomplete','unavailable')
$index=[Array]::IndexOf($outcomes,$row.outcome)
if($index -lt 0){exit 27}
$status=64 -bor $index
$reasons=@($row.scan.detections | ForEach-Object {$_.reasons})
if(@($reasons | Where-Object {$_ -like 'SHA-256:*'}).Count){$status=$status -bor 4}
if(@($reasons | Where-Object {$_ -like 'YARA:*'}).Count){$status=$status -bor 8}
if($row.coverage_complete){$status=$status -bor 16}
if($row.postcheck_unchanged){$status=$status -bor 32}
exit $status
'@
    $code=$code.Replace('__KIT__',$state.kit_id).Replace('__KEY__',$key)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $reply=wsb.exe exec --id $state.guest_id -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
    $status=$reply.ExitCode
    if($null -eq $status -or $status -lt 64 -or $status -gt 127){throw ('Static pilot failed with guest status '+$status+'; inspect guest-local static-pilot-error.txt')}
    $outcome=@('detected','not_detected','detected_incomplete','unavailable')[$status -band 3]
    $record=[ordered]@{checked_utc=[DateTime]::UtcNow.ToString('o');guest_id=$state.guest_id;kit_id=$state.kit_id;
        source_revision='48515e492013bc5bb2769249ea539436bb3e733f';family='Ransomware.WannaCry';
        sample_sha256='ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa';
        outcome=$outcome;hash_detection=[bool]($status -band 4);yara_detection=[bool]($status -band 8);
        coverage_complete=[bool]($status -band 16);postcheck_unchanged=[bool]($status -band 32);
        real_malware_statically_scanned=$true;sample_executed=$false;host_raw_archive_stored=$false;host_sample_unpacked=$false;
        full_report='Guest-local C:\SentinelAV-Test\StaticPilot-<run>\report.json';
        interpretation='One historical sample; no behavioral or representative protection-rate claim'}
    $record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $lab 'static-pilot-result.json') -Encoding utf8
    $record | ConvertTo-Json
} finally {
    $key=$null; $code=$null; $encoded=$null
    Pop-Location
}

# Purpose: Invoke a declared static corpus inside the owned offline guest.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Fixed static-only samples and Microsoft-signed guest-image controls.
param([switch]$Holdout,[switch]$ZeusValidation)
$ErrorActionPreference='Stop'
if($Holdout -and $ZeusValidation){throw 'Choose one fixed corpus profile'}
& (Join-Path $PSScriptRoot 'Test-SandboxBoundary.ps1')
$project=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$lab=Get-SentinelLabRoot
$state=Get-Content -LiteralPath (Join-Path $lab 'latest.json') -Raw | ConvertFrom-Json
$inventory=Get-Content -LiteralPath (Join-Path $state.input 'manifest.json') -Raw | ConvertFrom-Json
$ids=if($ZeusValidation){@('zeusbanking','gameoveralt')}elseif($Holdout){@('wannacryplus','gameover')}else{@('wannacry','emotet','zeusvm','mirai')}
foreach($id in $ids){if(!$inventory.files.('corpus-'+$id+'.sealed')){throw 'Prepare the selected sealed corpus kit first'}}
function Invoke-FixedGuest([string]$code) {
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $reply=wsb.exe exec --id $state.guest_id -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
    if($null -eq $reply.ExitCode){throw 'Missing guest result'}
    return [int]$reply.ExitCode
}
$benignNames=@('cmd.exe','whoami.exe','notepad.exe','kernel32.dll','user32.dll','advapi32.dll','crypt32.dll','ntdll.dll','gdi32.dll','WindowsPowerShell/v1.0/powershell.exe')
$launch=@'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -or @(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 20}
$p=Get-Content -LiteralPath 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json
if($p.kit_id -ne '__KIT__'){exit 21}
$names=@('cmd.exe','whoami.exe','notepad.exe','kernel32.dll','user32.dll','advapi32.dll','crypt32.dll','ntdll.dll','gdi32.dll','WindowsPowerShell/v1.0/powershell.exe')
$provenance=@()
foreach($name in $names){
    $path=Join-Path (Join-Path $env:WINDIR 'System32') $name
    try{
        $before=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature=Get-AuthenticodeSignature -LiteralPath $path
        $after=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if($before -ne $after){throw 'Control changed during signature check'}
        $provenance+=[pscustomobject]@{name=$name;sha256=$after;signature_status=[string]$signature.Status;signer=[string]$signature.SignerCertificate.Subject;thumbprint=[string]$signature.SignerCertificate.Thumbprint}
    }catch{$provenance+=[pscustomobject]@{name=$name;signature_status='Unavailable';error=[string]$_}}
}
$provenance | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath 'C:\SentinelAV-Test\benign-provenance.json' -Encoding utf8
$process=Start-Process -FilePath 'C:\SentinelAV-Test\App\SentinelAV.exe' -ArgumentList @('--static-corpus-key','__KEY__') -WindowStyle Hidden -PassThru
try{if(!$process.WaitForExit(240000)){$process.Kill();exit 23}; exit $process.ExitCode}finally{$process.Dispose()}
'@
Push-Location -LiteralPath $project
try{
    $keyCode="import tools,base64; from pathlib import Path; from sentinelav.response.response import dpapi; print(base64.b64encode(dpapi(Path('artifacts/lab/sealed-static-corpus/transfer-key.dpapi').read_bytes(),True)).decode())"
    if($Holdout){$keyCode=$keyCode.Replace('sealed-static-corpus','sealed-static-holdout');$launch=$launch.Replace('--static-corpus-key','--static-holdout-key')}
    if($ZeusValidation){$keyCode=$keyCode.Replace('sealed-static-corpus','sealed-zeus-validation');$launch=$launch.Replace('--static-corpus-key','--zeus-validation-key')}
    $key=& (Join-Path $project '.venv/Scripts/python.exe') -c $keyCode
    if($LASTEXITCODE -ne 0 -or $key -notmatch '^[A-Za-z0-9+/]{43}=$'){throw 'Cannot unlock transfer key'}
    $status=Invoke-FixedGuest ($launch.Replace('__KIT__',$state.kit_id).Replace('__KEY__',$key))
    if($status -ne 0){throw ('Static corpus guest preparation failed: '+$status)}
}finally{$key=$null;$launch=$null;Pop-Location}
$reportPrefix=@'
$ErrorActionPreference='Stop'
$latest=Get-Content -LiteralPath 'C:\SentinelAV-Test\static-corpus-latest.json' -Raw | ConvertFrom-Json
if($latest.report -notmatch '^C:\\SentinelAV-Test\\StaticCorpus-[0-9a-f]{32}\\report\.json$'){exit 250}
$r=Get-Content -LiteralPath $latest.report -Raw | ConvertFrom-Json
if($r.sample_execution -ne $false -or $r.response_actions -ne $false -or !$r.corpus_plan.guest_only_unpacking){exit 251}
'@
$names=@($ids | ForEach-Object {$_+'.bin'})+@($benignNames | ForEach-Object {'benign-'+$_.Replace('/','-')+'.bin'})
$baseReportPrefix=$reportPrefix
$comparisonRows=@{}
foreach($comparison in @('normal','hash_disabled','hash_disabled_emulation')){
$reportPrefix=$baseReportPrefix
if($comparison -eq 'hash_disabled'){
    $reportPrefix+=[Environment]::NewLine+'if($r.hash_ablation.hash_signatures_disabled -ne $true){exit 249}; $r=$r.hash_ablation; if(@($r.rows | Where-Object {$_.scan -and $_.definitions.count -ne 0}).Count){exit 248}'
}
if($comparison -eq 'hash_disabled_emulation'){
    $reportPrefix+=[Environment]::NewLine+'if($r.hash_disabled_emulation.hash_signatures_disabled -ne $true -or $r.hash_disabled_emulation.inspection_options.emulation -ne $true){exit 249}; $r=$r.hash_disabled_emulation; if(@($r.rows | Where-Object {$_.scan -and $_.definitions.count -ne 0}).Count){exit 248}'
}
$rows=@()
for($offset=0;$offset -lt $names.Count;$offset+=2){
    $pair=@($names[$offset],$names[$offset+1])
    $query=@'
$names=@('__FIRST__','__SECOND__')
$packed=16384
for($i=0;$i -lt 2;$i++){
 $matches=@($r.rows | Where-Object path -eq $names[$i])
 if($matches.Count -gt 1){exit 252}
 $flags=0
 if($matches.Count){
  $row=$matches[0]
  $outcomes=@('detected','not_detected','detected_incomplete','unavailable')
  $index=[Array]::IndexOf($outcomes,$row.outcome)
  if($index -lt 0){exit 253}
  $flags=64 -bor $index
  $reasons=@($row.scan.detections | ForEach-Object {$_.reasons})
  if(@($reasons | Where-Object {$_ -like 'SHA-256:*'}).Count){$flags=$flags -bor 4}
  if(@($reasons | Where-Object {$_ -like 'YARA:*'}).Count){$flags=$flags -bor 8}
  if($row.coverage_complete){$flags=$flags -bor 16}
  if($row.postcheck_unchanged){$flags=$flags -bor 32}
 }
 $packed=$packed -bor ($flags -shl ($i*7))
}
exit $packed
'@
    $status=Invoke-FixedGuest ($reportPrefix+[Environment]::NewLine+$query.Replace('__FIRST__',$pair[0]).Replace('__SECOND__',$pair[1]))
    if($status -lt 16384 -or $status -gt 32767){throw ('Invalid corpus row evidence: '+$status)}
    for($i=0;$i -lt 2;$i++){
        $flags=($status -shr ($i*7)) -band 127
        $included=[bool]($flags -band 64)
        $rows+=[pscustomobject]@{path=$pair[$i];label=if($offset -lt $ids.Count){'malware'}else{'benign'};included=$included;
            outcome=if($included){@('detected','not_detected','detected_incomplete','unavailable')[$flags -band 3]}else{'unavailable'};
            hash_detection=[bool]($flags -band 4);yara_detection=[bool]($flags -band 8);coverage_complete=[bool]($flags -band 16);postcheck_unchanged=[bool]($flags -band 32)}
    }
}
$comparisonRows[$comparison]=$rows
}
$rows=$comparisonRows['normal']
$reportPrefix=$baseReportPrefix
# Numeric-only emulator diagnostics: no guest strings, memory or virtual files.
$emulatorPrefix=$baseReportPrefix+[Environment]::NewLine+'$r=$r.hash_disabled_emulation'
foreach($id in $ids){
    $metricPrefix=$emulatorPrefix+[Environment]::NewLine+('$row=@($r.rows | Where-Object path -eq '''+$id+'.bin''); if($row.Count -ne 1 -or !$row[0].emulation_metrics){exit 247}; $m=$row[0].emulation_metrics')
    $query=@'
$states=@('Not run','Not applicable','Unavailable','Partial','Complete')
$status=[Array]::IndexOf($states,[string]$m.status); if($status -lt 0){exit 246}
$categories=@('api_model_stopped','cpu_stopped','budget_or_path_incomplete','environment_subset','unavailable','not_applicable','analysis_missing')
$flags=0;for($i=0;$i -lt 7;$i++){if($m.omission_categories.($categories[$i])){$flags=$flags -bor (1 -shl $i)}}
exit (268435456 -bor ([int]$m.instructions -band 262143) -bor ($status -shl 18) -bor ($flags -shl 21))
'@
    $first=Invoke-FixedGuest ($metricPrefix+[Environment]::NewLine+$query)
    $second=Invoke-FixedGuest ($metricPrefix+[Environment]::NewLine+'exit (268435456 -bor ([int]$m.api_calls -band 65535) -bor (([int]$m.changed_pages -band 511) -shl 16) -bor ([int][bool]$m.emulation_signature_finding -shl 25))')
    if($first -lt 268435456 -or $first -gt 536870911 -or $second -lt 268435456 -or $second -gt 536870911){throw 'Invalid bounded emulator metadata'}
    $categories=@('api_model_stopped','cpu_stopped','budget_or_path_incomplete','environment_subset','unavailable','not_applicable','analysis_missing')
    $gaps=@();for($i=0;$i -lt 7;$i++){if($first -band (1 -shl (21+$i))){$gaps+=$categories[$i]}}
    $target=$comparisonRows['hash_disabled_emulation'] | Where-Object path -eq ($id+'.bin')
    $statusCode=($first -shr 18) -band 7
    if($statusCode -gt 4){throw 'Invalid emulator status'}
    $target | Add-Member -NotePropertyName emulation_metrics -NotePropertyValue ([pscustomobject]@{status=@('Not run','Not applicable','Unavailable','Partial','Complete')[$statusCode];instructions=($first -band 262143);api_calls=($second -band 65535);changed_pages=(($second -shr 16) -band 511);emulation_signature_finding=[bool]($second -band (1 -shl 25));omission_categories=$gaps})
}
# Export only the two previously unknown sample digests, not sample content.
# Each fixed query returns three bytes from SHA-256 metadata as an integer.
$hashPrefix=$reportPrefix+[Environment]::NewLine+@'
$text=''
foreach($name in @('emotet.bin','zeusvm.bin')){
 $entry=@($r.rows | Where-Object path -eq $name)
 if($entry.Count -ne 1 -or $entry[0].sha256 -notmatch '^[0-9a-f]{64}$'){exit 254}
 $text+=$entry[0].sha256
}
$bytes=[byte[]]::new(64)
for($i=0;$i -lt 64;$i++){$bytes[$i]=[Convert]::ToByte($text.Substring($i*2,2),16)}
'@
$hashTargets=if($ZeusValidation){@('zeusbanking.bin','gameoveralt.bin')}elseif($Holdout){@('wannacryplus.bin','gameover.bin')}else{@('emotet.bin','zeusvm.bin')}
if($Holdout){$hashPrefix=$hashPrefix.Replace("'emotet.bin','zeusvm.bin'","'wannacryplus.bin','gameover.bin'")}
if($ZeusValidation){$hashPrefix=$hashPrefix.Replace("'emotet.bin','zeusvm.bin'","'zeusbanking.bin','gameoveralt.bin'")}
if(@($rows | Where-Object { $_.path -in $hashTargets -and !$_.included }).Count -eq 0){
    $hashBytes=[byte[]]::new(64)
    for($offset=0;$offset -lt 64;$offset+=3){
        $query='$n=16777216; for($i=0;$i -lt 3 -and ('+$offset+'+$i) -lt 64;$i++){$n=$n -bor ([int]$bytes['+$offset+'+$i] -shl ($i*8))}; exit $n'
        $status=Invoke-FixedGuest ($hashPrefix+[Environment]::NewLine+$query)
        if($status -lt 16777216 -or $status -gt 33554431){throw 'Invalid SHA-256 metadata transport'}
        for($i=0;$i -lt 3 -and ($offset+$i) -lt 64;$i++){$hashBytes[$offset+$i]=($status -shr ($i*8)) -band 255}
    }
    ($rows | Where-Object path -eq $hashTargets[0]) | Add-Member -NotePropertyName sha256 -NotePropertyValue ([Convert]::ToHexString([byte[]]$hashBytes[0..31]).ToLowerInvariant())
    ($rows | Where-Object path -eq $hashTargets[1]) | Add-Member -NotePropertyName sha256 -NotePropertyValue ([Convert]::ToHexString([byte[]]$hashBytes[32..63]).ToLowerInvariant())
}
if(!$Holdout -and !$ZeusValidation){
$rows[0] | Add-Member -NotePropertyName sha256 -NotePropertyValue 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa'
$rows[3] | Add-Member -NotePropertyName sha256 -NotePropertyValue '03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d'
}
$summary=[ordered]@{checked_utc=[DateTime]::UtcNow.ToString('o');guest_id=$state.guest_id;kit_id=$state.kit_id;source_revision='48515e492013bc5bb2769249ea539436bb3e733f';rows=$rows;
    hash_disabled_rows=$comparisonRows['hash_disabled'];hash_disabled_policy='All exact SHA-256 signatures disabled, including derived content; no trust exclusions; YARA/content settings identical';
    hash_disabled_emulation_rows=$comparisonRows['hash_disabled_emulation'];native_sample_execution=$false;
    inspection_options=@{advanced=$true;content=$true;documents=$true;emulation=$false;amsi=$false;model=$false;reputation=$false};
    selected_malware=$ids.Count;holdout=[bool]$Holdout;zeus_validation=[bool]$ZeusValidation;selected_benign=10;benign_source='Guest image; valid Microsoft Authenticode signatures required';
    sample_execution=$false;host_raw_archives_stored=$false;host_samples_unpacked=$false;
    interpretation='Selected historical samples, not a representative detection rate. Benign detections require review, not automatic false-positive classification.'}
$resultName=if($ZeusValidation){'zeus-validation-result.json'}elseif($Holdout){'static-holdout-result.json'}else{'static-corpus-result.json'}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $lab $resultName) -Encoding utf8
$rows | Format-Table path,label,outcome,hash_detection,yara_detection,coverage_complete -AutoSize

# Purpose: Invoke one explicitly authorized and bounded runtime job inside the owned guest.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

param([string]$JobManifest,[switch]$ResetOnly)
$ErrorActionPreference = 'Stop'
$env:PSModulePath=$PSHOME+'\Modules;'+$env:SystemRoot+'\System32\WindowsPowerShell\v1.0\Modules'
$project = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$stateRoot = Get-SentinelLabRoot
if ($ResetOnly) { $job=[pscustomobject]@{authorization='RUN_ONLY_IN_DISPOSABLE_OFFLINE_GUEST';sha256=('0'*64);seconds=1} }
else {
    if (-not $JobManifest -or (Get-Item -LiteralPath $JobManifest).Length -gt 16384) { throw 'Runtime request is missing or too large.' }
    $job = Get-Content -LiteralPath $JobManifest -Raw | ConvertFrom-Json
}
if ($job.authorization -ne 'RUN_ONLY_IN_DISPOSABLE_OFFLINE_GUEST' -or $job.sha256 -notmatch '^[a-f0-9]{64}$' -or
    (-not ($job.seconds -is [int] -or $job.seconds -is [long])) -or $job.seconds -lt 1 -or $job.seconds -gt 120 -or
    (-not $ResetOnly -and $job.schema -ne 1)) { throw 'Invalid explicit guest runtime request.' }
$mutex = [Threading.Mutex]::new($false,'Local\SentinelAVRuntimeJob')
if (-not $mutex.WaitOne(0)) { $mutex.Dispose(); throw 'Another runtime job is already controlling the lab.' }
$attempted = $false
$result = [ordered]@{schema=1;sample_sha256=$job.sha256;status='Not started';alerts=0;omissions=0;event_count=0;guest_disposal_verified=$false;
    execution_attempted=$false;
    source='Guest-reported bounded summary, not independently authenticated behavior';full_report='Guest-local report; discarded with guest'}
function Invoke-GuestMetadata([string]$code) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $stdout=[IO.Path]::GetTempFileName(); $stderr=[IO.Path]::GetTempFileName()
    try {
        $process=Start-Process -FilePath (Get-Command wsb.exe).Source -ArgumentList @('exec','--id',$guestId,'-r','ExistingLogin','-c',('"powershell.exe -NoProfile -EncodedCommand '+$encoded+'"'),'--raw') -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
        try { if (-not $process.WaitForExit(220000)) { $process.Kill(); throw 'Guest control request timed out; guest disposal will still be attempted.' } }
        finally { $process.Dispose() }
        if ((Get-Item -LiteralPath $stdout).Length -gt 1MB) { throw 'Guest control response exceeded its metadata limit.' }
        $reply=Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json
    } finally { Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue }
    if ($null -eq $reply.ExitCode) { throw 'Missing guest execution status.' }
    return [long]$reply.ExitCode
}
try {
    if ($ResetOnly) { $attempted=$true; $result.status='Reset requested' }
    else {
    Write-Output '[stage] Checking the registered read-only lab kit'
    & (Join-Path $PSScriptRoot 'Test-SandboxBoundary.ps1') | Out-Null
    $state = Get-Content -LiteralPath (Join-Path $stateRoot 'latest.json') -Raw | ConvertFrom-Json
    $inventory = Get-Content -LiteralPath (Join-Path $state.input 'manifest.json') -Raw | ConvertFrom-Json
    $protocolEntry = @($inventory.files.PSObject.Properties | Where-Object { $_.Name.Replace('\','/') -eq 'App/_internal/runtime-protocol.json' })
    if ($protocolEntry.Count -ne 1) { throw 'This kit predates runtime jobs. Rebuild SentinelAV and prepare a current kit; the existing guest was left untouched.' }
    $guestId = if ($state.active_guest_verified) { [string]$state.active_guest_id } else { [string]$state.guest_id }
    $running = wsb.exe list --raw | ConvertFrom-Json
    if ($guestId -notmatch '^[a-f0-9-]{36}$' -or @($running.WindowsSandboxEnvironments).Count -ne 1 -or $running.WindowsSandboxEnvironments[0].Id -ne $guestId) { throw 'Exactly the registered guest must be running.' }
    $wire = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($job | ConvertTo-Json -Compress)))
    $launch = @'
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or @(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 20}
$preflight=Get-Content -LiteralPath 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json
if($preflight.kit_id -ne '__KIT__'){exit 21}
$inventory=Get-Content -LiteralPath 'C:\SentinelAV-Input\manifest.json' -Raw | ConvertFrom-Json
foreach($entry in $inventory.files.PSObject.Properties){
    $relative=$entry.Name.Replace('/','\')
    if($relative.StartsWith('App\',[StringComparison]::OrdinalIgnoreCase)){
        $path=Join-Path 'C:\SentinelAV-Test' $relative
        $item=Get-Item -LiteralPath $path
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Value){exit 22}
    }
}
$request='C:\SentinelAV-Test\runtime-request.json'
[IO.File]::WriteAllBytes($request,[Convert]::FromBase64String('__JOB__'))
$process=Start-Process -FilePath 'C:\SentinelAV-Test\App\SentinelAV.exe' -ArgumentList @('--runtime-job',$request) -WindowStyle Hidden -PassThru
try{if(!$process.WaitForExit(180000)){$process.Kill();exit 23};exit $process.ExitCode}finally{$process.Dispose()}
'@
    $launch = $launch.Replace('__KIT__',[string]$state.kit_id).Replace('__JOB__',$wire)
    Write-Output '[stage] Running the explicitly selected specimen inside the offline guest'
    $attempted = $true
    $result.execution_attempted=$true
    $exit = Invoke-GuestMetadata $launch
    if ($exit -ne 0) { throw "Guest runtime failed or was incomplete (exit $exit)." }
    $result.status = 'Observed; verdict indeterminate'
    Write-Output '[stage] Reading bounded numeric summary; no sample bytes leave the guest'
    foreach ($field in @('alerts','omissions','event_count')) {
        $query = "`$r=Get-Content -LiteralPath 'C:\SentinelAV-Test\runtime-latest.json' -Raw | ConvertFrom-Json; `$v=[int]`$r.$field; if(`$v -lt 0 -or `$v -gt 65535){exit 25}; exit (1073741824+`$v)"
        $value = Invoke-GuestMetadata $query
        if ($value -lt 1073741824 -or $value -gt 1073807359) { throw 'Invalid bounded summary response.' }
        $result[$field] = $value-1073741824
    }
    if ($result.alerts -gt 0) { $result.status='Review required: observed policy alerts' }
    }
} catch { $result.status='Incomplete'; $result['error']=$_.Exception.Message }
finally {
    if ($attempted) {
        Write-Output '[stage] Discarding the used guest and verifying its replacement'
        try {
            $resetScript=Join-Path $PSScriptRoot 'Reset-TestEnvironment.ps1'
            $resetOutput=[IO.Path]::GetTempFileName(); $resetError=[IO.Path]::GetTempFileName()
            $reset=Start-Process -FilePath (Join-Path $env:windir 'System32/WindowsPowerShell/v1.0/powershell.exe') -ArgumentList @('-NoProfile','-File',('"'+$resetScript+'"')) -WindowStyle Hidden -RedirectStandardOutput $resetOutput -RedirectStandardError $resetError -PassThru
            try {
                if (-not $reset.WaitForExit(180000)) { $reset.Kill(); throw 'Guest reset controller timed out. Verify registered guest state manually.' }
                if ($reset.ExitCode -ne 0) {
                    $detail=[IO.File]::ReadAllText($resetError)
                    if($detail.Length -gt 2000){$detail=$detail.Substring(0,2000)}
                    throw ('Guest reset controller failed: '+$detail)
                }
            } finally { $reset.Dispose(); Remove-Item -LiteralPath $resetOutput,$resetError -Force -ErrorAction SilentlyContinue }
            $result.guest_disposal_verified=$true
            if ($ResetOnly) { $result.status='Registered guest reset verified' }
        } catch { $result.status='Guest disposal failed'; $result['cleanup_error']=$_.Exception.Message }
    }
    $mutex.ReleaseMutex(); $mutex.Dispose()
}
$output = Join-Path $project ('artifacts/lab/runtime-jobs/'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $output -Force | Out-Null
$result['host_report']=Join-Path $output 'summary.json'
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $result.host_report -Encoding UTF8
$result | ConvertTo-Json -Depth 6 -Compress | Write-Output

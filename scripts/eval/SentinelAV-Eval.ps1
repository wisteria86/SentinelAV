# Purpose: Run one stage of the 90% detection evaluation by hand, log it fully, then print the status report.
# Works with: tools/evaluation/*, docs/RUNBOOK-90.md
<#
Usage (from the repository folder, in PowerShell):
  .\scripts\eval\SentinelAV-Eval.ps1 -Step tests      # unit tests and guards (~2 min)
  .\scripts\eval\SentinelAV-Eval.ps1 -Step fp         # false alarms on clean software (~2 h)
  .\scripts\eval\SentinelAV-Eval.ps1 -Step dev        # 812 dev malware samples in the Sandbox (~3 h)
  .\scripts\eval\SentinelAV-Eval.ps1 -Step freeze     # lock code + definitions, start the waiting period
  .\scripts\eval\SentinelAV-Eval.ps1 -Step collect    # after the wait: fetch post-freeze malware (~1 h)
  .\scripts\eval\SentinelAV-Eval.ps1 -Step holdout    # the real test, run once (~3 h)
  .\scripts\eval\SentinelAV-Eval.ps1 -Step status     # print the status report only
Every step writes F:\SentinelAV-Work\runs\<step>-<time>.log and F:\SentinelAV-Work\STATUS.txt.
#>
param([Parameter(Mandatory)][ValidateSet('tests','fp','dev','freeze','collect','holdout','status')][string]$Step,
      [int]$WaitDays = 3)
$ErrorActionPreference = 'Stop'
$Repo = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$Work = 'F:\SentinelAV-Work'
$Py = Join-Path $Repo '.venv\Scripts\python.exe'
Set-Location $Repo
$env:PYTHONPATH = "$Repo\src;$Repo"
$env:PYTHONUNBUFFERED = '1'
New-Item -ItemType Directory -Force "$Work\runs" | Out-Null
$Log = "$Work\runs\$Step-$(Get-Date -Format yyyyMMdd-HHmmss).log"
function Say($text) { $line = "[$(Get-Date -Format 'MM-dd HH:mm')] $text"; Write-Host $line -ForegroundColor Cyan; Add-Content $Log $line }
function Run([string[]]$arguments) {
    Say ("python " + ($arguments -join ' '))
    $ErrorActionPreference = 'Continue'  # Python's warnings on stderr must not stop the step.
    & $Py @arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $Log -Append | Out-Host
    $code = $LASTEXITCODE; Say "exit code $code"; return $code
}
function Freeze { $f = "$Work\freeze.json"; if (Test-Path $f) { Get-Content $f -Raw | ConvertFrom-Json } else { $null } }
function Sandbox-Profile([string]$profile, [string]$snapshot) {
    $env:SENTINELAV_EVAL_SNAPSHOT = $snapshot
    $first = Run @('-m','tools.evaluation.critical_harness','--profile',$profile,'--headless')
    for ($i = 1; $i -le 60; $i++) {
        $run = Get-ChildItem "$Repo\logs" -Directory | Sort-Object Name | Where-Object { (Get-Content "$($_.FullName)\report.md" -TotalCount 3 -ErrorAction SilentlyContinue) -match "\($profile\)" } | Select-Object -Last 1
        $state = (Select-String -Path "$($run.FullName)\report.md" -Pattern 'batches recorded' | Select-Object -First 1).Line
        Say "progress: $state"
        if ($state -notmatch 'BLOCKED' -and $state -match '(\d+)/\1 batches') { Say 'all batches done'; return }
        # Windows Sandbox needs 10 GB free on C:, which dips while each guest shuts down.
        while ((Get-PSDrive C).Free -lt 10.4GB) { Say ("waiting for C: space: {0:N1} GB free" -f ((Get-PSDrive C).Free / 1GB)); Start-Sleep 60 }
        Start-Sleep 30
        Run @('-m','tools.evaluation.critical_harness','--profile',$profile,'--headless','--resume',$run.FullName) | Out-Null
    }
    Say 'stopped after 60 resume attempts; send the status report to Claude'
}

Say "step $Step started; log: $Log"
switch ($Step) {
    'tests'  { & powershell -NoProfile -ExecutionPolicy Bypass -File "$Repo\test.ps1" 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $Log -Append | Select-String -Pattern '^(Ran|OK|FAILED|FAIL:|ERROR:)' | Out-Host
               Run @('tools/maintenance/check_structure.py') | Out-Null; Run @('tools/maintenance/check_no_zoo_hardcoding.py') | Out-Null }
    'fp'     { Run @('-X','faulthandler','tools/evaluation/evaluate_false_positives.py','--split','calibrate') | Out-Null }
    'dev'    { Sandbox-Profile 'bazaar-dev' "$Work\snapshots\dev-20261111" }
    'freeze' {
        if (Freeze) { Say 'already frozen; nothing changed'; break }
        if (git status --porcelain src tools tests scripts resources packaging) { Say 'UNCOMMITTED code: commit first, then run freeze again'; break }
        git tag -f eval-freeze-90 | Out-Null
        if ((Run @('tools/evaluation/snapshot_definitions.py','eval-freeze-90')) -ne 0) { Say 'snapshot failed'; break }
        $now = (Get-Date).ToUniversalTime()
        @{ frozen_utc = $now.ToString('yyyy-MM-dd HH:mm:ss'); commit = (git rev-parse --short HEAD); collect_after_utc = $now.AddDays($WaitDays).ToString('yyyy-MM-dd HH:mm:ss') } | ConvertTo-Json | Set-Content "$Work\freeze.json"
        Say "frozen. Do NOT update definitions now. Run -Step collect after $($now.AddDays($WaitDays).ToLocalTime()) local time" }
    'collect' {
        $f = Freeze; if (-not $f) { Say 'run -Step freeze first'; break }
        $end = [datetime]::ParseExact($f.collect_after_utc, 'yyyy-MM-dd HH:mm:ss', $null)
        if ((Get-Date).ToUniversalTime() -lt $end.AddHours(6)) { Say "too early: MalwareBazaar's export lags; wait until $($end.AddHours(6).ToLocalTime())"; break }
        Run @('-c', "import os,urllib.request,urllib.parse;k=os.environ['ABUSECH_AUTH_KEY'];urllib.request.urlretrieve('https://mb-api.abuse.ch/v2/files/exports/'+urllib.parse.quote(k,safe='')+'/full.csv.zip',r'$Work\downloads\abusech\full-holdout.csv.zip');print('export downloaded')") | Out-Null
        Run @('tools/evaluation/bazaar_collect.py','holdout',"$Work\downloads\abusech\full-holdout.csv.zip",'--start',$f.frozen_utc,'--end',$f.collect_after_utc,'--count','1000','--seed','20261128') | Out-Null }
    'holdout' {
        if (-not (Freeze)) { Say 'run -Step freeze first'; break }
        if ((git rev-parse --short HEAD) -ne (Freeze).commit) { Say 'code changed since the freeze: check out tag eval-freeze-90 first'; break }
        Sandbox-Profile 'bazaar-holdout' "$Work\snapshots\eval-freeze-90" }
}
Run @('tools/evaluation/project_status.py') | Out-Null
Say "done. Send Claude the text of $Work\STATUS.txt (and this log if something failed: $Log)"

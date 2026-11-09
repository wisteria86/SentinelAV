# Purpose: Coordinate the owned guest service and AMSI integration checks.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

param(
    [ValidateSet('Install','Register','Unregister','Remove','VerifyRemoved','BoundaryChecks','Check','HostChecks','FailureChecks')][string]$Action='Check',
    [ValidateSet('SelfSigned','Unsigned')][string]$Variant='SelfSigned',
    [ValidateSet('None','AfterService','AfterRegistration')][string]$InjectFailure='None'
)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot=Get-SentinelLabRoot
$latest=Get-Content -LiteralPath (Join-Path $labRoot 'latest.json') -Raw | ConvertFrom-Json
$guestId=[string]$latest.guest_id
if ($guestId -notmatch '^[0-9a-f-]{36}$' -or !$latest.guest_executed) { throw 'A guest-verified Sandbox identity is required' }
$running=wsb.exe list --raw | ConvertFrom-Json
if (@($running.WindowsSandboxEnvironments | Where-Object Id -eq $guestId).Count -ne 1) { throw 'Registered test guest is not running' }
$recordPath=Join-Path $labRoot 'integration-deployment.json'
if ($Action -eq 'Install') {
    $previousRecord=if(Test-Path -LiteralPath $recordPath){Get-Content -LiteralPath $recordPath -Raw}else{$null}
    $deployment=[guid]::NewGuid().ToString('N')
    @{guest_id=$guestId;deployment_id=$deployment;created_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $recordPath -Encoding utf8
} else {
    $record=Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    if ($record.guest_id -ne $guestId -or $record.deployment_id -notmatch '^[0-9a-f]{32}$') { throw 'Deployment belongs to another guest' }
    $deployment=$record.deployment_id
}
$nl=[Environment]::NewLine
$common=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guest/Common.ps1') -Raw
if ($latest.kit_id -notmatch '^[0-9a-f]{32}$') { throw 'Invalid kit identity' }
$prefix='$expectedDeploymentId='''+$deployment+''';$expectedKitId='''+$latest.kit_id+''';$variant='''+$Variant+''';'+$nl+$common
function Invoke-GuestCode([string]$code,[string]$label) {
    $catchBlock=@'
catch {
    $details=($_ | Out-String)
    $serviceError='C:\ProgramData\SentinelAVProtection\data\last-error.txt'
    try { if ((Test-Path -LiteralPath $serviceError) -and (Get-Item -LiteralPath $serviceError).Length -lt 8192) { $details+=[Environment]::NewLine+'Service: '+(Get-Content -LiteralPath $serviceError -Raw) } } catch {}
    $details | Set-Content -LiteralPath 'C:\SentinelAV-Test\integration-error.txt' -Encoding utf8
    $details | Set-Content -LiteralPath 'C:\SentinelAV-Test\error-__STAGE__.txt' -Encoding utf8
    exit 97
}
'@
    $catchBlock=$catchBlock.Replace('__STAGE__',($label -replace '[^A-Za-z0-9_-]','_'))
    $wrapped=$prefix+$nl+'try {'+$nl+$code+$nl+'exit 0'+$nl+'} '+$catchBlock
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapped))
    $command='powershell.exe -NoProfile -EncodedCommand '+$encoded
    if ($command.Length -gt 30000) { throw 'Guest command exceeds transport bound' }
    $reply=wsb.exe exec --id $guestId -r ExistingLogin -c $command --raw | ConvertFrom-Json
    @{time_utc=[DateTime]::UtcNow.ToString('o');guest=$guestId;deployment=$deployment;stage=$label;exit_code=$reply.ExitCode} | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $labRoot 'integration-stages.jsonl')
    if ($null -eq $reply.ExitCode -or $reply.ExitCode -ne 0) { throw ($label+' failed; guest exit '+$reply.ExitCode+'. Details: C:\SentinelAV-Test\integration-error.txt') }
    Write-Output ('PASS: '+$label)
}
function Run-Part([string]$name) { Invoke-GuestCode (Get-Content -LiteralPath (Join-Path $PSScriptRoot ('guest/'+$name+'.ps1')) -Raw) $name }
function Unregister-Owned {
    $reply=wsb.exe exec --id $guestId -r ExistingLogin -c ('C:\SentinelAV-Test\native\AmsiProbe.exe --unregister-owned '+$deployment) --raw | ConvertFrom-Json
    if ($reply.ExitCode -ne 0 -or $null -eq $reply.ExitCode) { throw ('Native owned-key removal refused: '+$reply.ExitCode) }
    Write-Output 'PASS: exact owned provider/class keys removed without loading the DLL into a new PowerShell host'
}
function Remove-Deployment { Unregister-Owned; Run-Part 'Remove' }
try {
    switch ($Action) {
        Install {
            Run-Part 'Install-Before'
            $installer=Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'Install-ProtectionService.ps1') -Raw
            Invoke-GuestCode ('& {'+$nl+$installer+$nl+'} -WatchFolders @($watch) -PackageRoot ''C:\SentinelAV-Test\App''') 'Install protected service'
            if ($InjectFailure -eq 'AfterService') { throw 'Injected failure after service creation' }
            Run-Part 'Install-After'
            Run-Part 'Register'
            if ($InjectFailure -eq 'AfterRegistration') { throw 'Injected failure after provider registration' }
        }
        Register { Run-Part 'Register' }
        Unregister { Unregister-Owned }
        Remove { Remove-Deployment }
        VerifyRemoved {
            Invoke-GuestCode @'
Read-State
Assert-OtherProviders
foreach ($path in @($install,$dataRoot,$providerRoot,$watch,$classKey,$providerKey)) {
    if (Test-Path -LiteralPath $path) { throw ('Owned deployment still present: '+$path) }
}
if (Get-Service SentinelAVProtection -ErrorAction SilentlyContinue) { throw 'Service still registered' }
& $probe --absent
if ($LASTEXITCODE) { throw 'Removed COM provider remains activatable' }
if ($state.phase -ne 'Removed' -or !$state.completed) { throw 'Removal state incomplete' }
if ((Get-Content -LiteralPath (Join-Path $root 'unrelated-fixture.txt') -Raw).Trim() -ne 'Preserve this harmless sibling fixture') { throw 'Sibling fixture changed' }
'@ 'Removed deployment verification'
        }
        BoundaryChecks {
            Invoke-GuestCode @'
Read-State
Assert-OtherProviders
if (Test-Path -LiteralPath $classKey) { throw 'Class key already exists; fixture refused' }
try {
    New-Item -Path $classKey | Out-Null
    New-ItemProperty -LiteralPath $classKey -Name SentinelAVDeploymentId -Value 'foreign-fixture' -PropertyType String | Out-Null
    New-ItemProperty -LiteralPath $classKey -Name PreserveFixture -Value 'keep' -PropertyType String | Out-Null
    & $probe --unregister-owned $state.id
    if ($LASTEXITCODE -ne 73 -or (Get-ItemProperty -LiteralPath $classKey).PreserveFixture -ne 'keep') { throw 'Foreign registry ownership was not preserved' }
} finally {
    if ((Get-ItemProperty -LiteralPath $classKey -ErrorAction SilentlyContinue).SentinelAVDeploymentId -eq 'foreign-fixture') {
        Remove-Item -LiteralPath $classKey -Recurse
    }
}
Assert-OtherProviders
'@ 'Foreign ownership refusal'
        }
        Check {
            Invoke-GuestCode @'
Read-State
Assert-OtherProviders
$health=Get-Content -LiteralPath (Join-Path $dataRoot 'data\status.json') -Raw | ConvertFrom-Json
if (!$health.amsi_broker.running -or $health.account -ne 'LocalService') { throw 'Broker is not healthy' }
& $probe --registered
if ($LASTEXITCODE) { throw ('Registered COM probe failed: '+$LASTEXITCODE) }
& $probe --system
if ($LASTEXITCODE) { throw ('Windows AMSI consumer probe failed: '+$LASTEXITCODE) }
$state.phase='Registered COM and Windows AMSI checks passed'; Save-State
'@ 'Registered provider checks'
        }
        HostChecks {
            Invoke-GuestCode @'
Read-State
Assert-OtherProviders
$ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$benign=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'SentinelAV ordinary fixture'"))
$p=Start-Process -FilePath $ps -ArgumentList @('-NoProfile','-EncodedCommand',$benign) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $root 'benign.stdout.txt') -RedirectStandardError (Join-Path $root 'benign.stderr.txt')
if ($p.ExitCode -ne 0) { throw 'Benign PowerShell comparison failed' }
$marker='SENTINELAV_'+'DEMO_THREAT_7C23A'
$test="Set-Content -LiteralPath 'C:\SentinelAV-Test\should-not-run.txt' -Value 'harmless'; Write-Output '"+$marker+"'"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($test))
$p=Start-Process -FilePath $ps -ArgumentList @('-NoProfile','-EncodedCommand',$encoded) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $root 'demo.stdout.txt') -RedirectStandardError (Join-Path $root 'demo.stderr.txt')
$errorText=Get-Content -LiteralPath (Join-Path $root 'demo.stderr.txt') -Raw
if ($p.ExitCode -eq 0 -or $errorText -notmatch 'ScriptContainedMaliciousContent|malicious content' -or (Test-Path -LiteralPath (Join-Path $root 'should-not-run.txt'))) { throw 'Expected harmless PowerShell AMSI block was not proven' }
$children=@()
try {
    foreach ($n in 1..4) { $children+=Start-Process -FilePath $probe -ArgumentList '--system' -WindowStyle Hidden -PassThru }
    foreach ($child in $children) {
        if (!$child.WaitForExit(10000) -or $child.ExitCode -ne 0) { throw 'Concurrent native AMSI probe failed' }
    }
} finally {
    foreach ($child in $children) { if (!$child.HasExited) { $child.Kill(); $child.WaitForExit() }; $child.Dispose() }
}
$state.phase='Real PowerShell benign/block and four concurrent AMSI probes passed'; Save-State
'@ 'Real PowerShell and concurrency'
        }
        FailureChecks {
            # Native SCM commands still work if a script host rejects content
            # while its AMSI backend is intentionally unavailable.
            $reply=wsb.exe exec --id $guestId -r ExistingLogin -c 'C:\Windows\System32\sc.exe stop SentinelAVProtection' --raw | ConvertFrom-Json
            if ($reply.ExitCode -ne 0) { throw 'Could not stop owned test service' }
            try {
                $reply=wsb.exe exec --id $guestId -r ExistingLogin -c 'C:\SentinelAV-Test\native\AmsiProbe.exe --unavailable' --raw | ConvertFrom-Json
                if ($reply.ExitCode -ne 0) { throw 'Unavailable backend was not returned as failure' }
                Write-Output 'PASS: stopped service produces failure, not a clean direct-provider verdict'
            } finally {
                $reply=wsb.exe exec --id $guestId -r ExistingLogin -c 'C:\Windows\System32\sc.exe start SentinelAVProtection' --raw | ConvertFrom-Json
                if ($reply.ExitCode -ne 0) { throw 'Could not restart owned test service' }
                $ready=$false
                foreach ($attempt in 1..15) {
                    Start-Sleep -Seconds 1
                    $reply=wsb.exe exec --id $guestId -r ExistingLogin -c 'C:\SentinelAV-Test\native\AmsiProbe.exe --registered' --raw | ConvertFrom-Json
                    if ($reply.ExitCode -eq 0) { $ready=$true; break }
                }
                if (!$ready) { throw 'Owned service did not recover after restart' }
                Write-Output 'PASS: LocalService recovery and registered-provider verdict verified'
            }
        }
    }
} catch {
    $failure=$_
    if ($Action -eq 'Install') {
        $ownershipCode='if(!(Test-Path -LiteralPath ''C:\SentinelAV-Test\deployment-state.json'')){exit 1}; $s=Get-Content -LiteralPath ''C:\SentinelAV-Test\deployment-state.json'' -Raw | ConvertFrom-Json; if($s.id -eq '''+$deployment+'''){exit 0}; exit 1'
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ownershipCode))
        $ownership=wsb.exe exec --id $guestId -r ExistingLogin -c ('powershell.exe -NoProfile -EncodedCommand '+$encoded) --raw | ConvertFrom-Json
        if ($null -ne $ownership.ExitCode -and $ownership.ExitCode -eq 0) {
            Write-Output 'Install did not complete; attempting owned deployment rollback.'
            try { Remove-Deployment; Write-Output 'PASS: install failure rolled back' } catch { Write-Output ('Rollback requires attention: '+$_.Exception.Message) }
        } else {
            Write-Output 'No matching deployment ownership was created; pre-existing state preserved.'
            if ($previousRecord) { $previousRecord | Set-Content -LiteralPath $recordPath -Encoding utf8 }
        }
    }
    throw $failure
}

@echo off
title SentinelAV - Disposable Development Lab
echo SentinelAV disposable test environment - harmless checks only
echo.
if /i not "%USERNAME%"=="WDAGUtilityAccount" (
  echo This helper runs only in the Windows Sandbox guest.
  exit /b 1
)
powershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; $machine=Get-CimInstance Win32_ComputerSystem; if($machine.Model -ne 'Virtual Machine'){throw 'Guest virtual-machine identity not verified'}; if(@(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up').Count){throw 'Active guest network adapter detected; refusing tests'}; $inputRoot='C:\SentinelAV-Input'; $manifestPath=Join-Path $inputRoot 'manifest.json'; if((Get-Item -LiteralPath $manifestPath).Length -gt 2097152){throw 'Manifest too large'}; $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json; if($manifest.schema -ne 1){throw 'Manifest schema mismatch'}; $files=@($manifest.files.psobject.Properties); if(!$files.Count -or $files.Count -gt 8192){throw 'Manifest entry limit'}; foreach($file in $files){$path=[IO.Path]::GetFullPath((Join-Path $inputRoot $file.Name)); if(!$path.StartsWith($inputRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or $file.Value -notmatch '^[0-9a-f]{64}$'){throw 'Invalid manifest entry'}; if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.Value){throw 'Input checksum mismatch'}}; $work='C:\SentinelAV-Test'; New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null; Copy-Item -LiteralPath (Join-Path $inputRoot 'App') -Destination (Join-Path $work 'App') -Recurse; Copy-Item -LiteralPath (Join-Path $inputRoot 'native') -Destination (Join-Path $work 'native') -Recurse; foreach($file in $files){if($file.Name -like 'App\*' -or $file.Name -like 'native\*'){$path=Join-Path $work $file.Name; if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.Value){throw 'Copied file checksum mismatch'}}}; @{kit_id=$manifest.kit_id;state='Guest preflight passed; app checks pending';no_up_network_adapter=$true;computer=$env:COMPUTERNAME} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $work 'preflight.json'); Write-Host 'PASS: guest identity, network preflight, and copied package checksums.'"
if errorlevel 1 goto failed
echo Running packaged harmless file, buffer, UI and cryptography checks...
powershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; $process=Start-Process -FilePath 'C:\SentinelAV-Test\App\SentinelAV.exe' -ArgumentList @('--self-test','--data-dir','C:\SentinelAV-Test\SelfTest') -WindowStyle Hidden -Wait -PassThru; if($process.ExitCode -ne 0){throw 'Packaged self-test failed; inspect C:\SentinelAV-Test\SelfTest\last-error.txt'}; $result=Get-Content -LiteralPath 'C:\SentinelAV-Test\SelfTest\self-test.json' -Raw | ConvertFrom-Json; if($result.status -ne 'PASS' -or !$result.buffer.detected -or !$result.buffer.complete){throw 'Missing successful buffer/file self-test result'}; Write-Host 'PASS: packaged SentinelAV checks.'"
if errorlevel 1 goto failed
if not exist "C:\SentinelAV-Test\native\AmsiHarness.exe" goto nonative
"C:\SentinelAV-Test\native\AmsiHarness.exe" --dll "C:\SentinelAV-Test\native\SentinelAVAmsi.dll"
if errorlevel 1 goto failed
:nonative
echo.
echo PASS: harmless environment checks completed. Opening SentinelAV inside the guest.
echo Native provider is NOT registered. Service deployment is NOT performed.
echo Guest results: C:\SentinelAV-Test\SelfTest
echo Closing Windows Sandbox discards guest changes. No host output folder is shared.
start "SentinelAV guest" "C:\SentinelAV-Test\App\SentinelAV.exe" --data-dir "C:\SentinelAV-Test\GUI-State"
goto :eof
:failed
echo.
echo FAILED: environment is not ready. Review the error above; do not continue testing.
exit /b 1

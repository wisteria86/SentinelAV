# Purpose: Verify response IPC and protected-resource boundaries with guest fixtures.
# Works with: Common.ps1; platform/remediation_broker.py; response/remediation.py
# Used by: the CLI, desktop launcher, or packaging workflow

# Harmless protected deployment checks. This must never run on the host.
param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{32}$')][string]$ExpectedKitId)
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if($env:USERNAME -ne 'WDAGUtilityAccount' -or !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Disposable guest administrator required'}
if((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or @(Get-NetAdapter | Where-Object Status -eq 'Up').Count){throw 'Offline VM required'}
if((Get-Content 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json).kit_id -ne $ExpectedKitId){throw 'Kit identity mismatch'}
trap { ($_ | Out-String) | Set-Content 'C:\SentinelAV-Test\response-boundary-error.txt' -Encoding utf8; exit 93 }
if(Get-Service SentinelAVProtection -ErrorAction SilentlyContinue){throw 'Fresh guest without an existing service required'}
$controls='C:\Users\Public\SentinelAV-Broker-Controls'
New-Item -ItemType Directory -Path $controls | Out-Null
$file=Join-Path $controls 'ordinary.txt';Set-Content -LiteralPath $file -Value 'ordinary harmless configuration'
$name='SentinelAV_Control_'+[guid]::NewGuid().ToString('N')
$key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$value='"'+$file+'"';New-ItemProperty -LiteralPath $key -Name $name -Value $value -PropertyType String | Out-Null
$installed=$false
try {
 $package='C:\SentinelAV-Test\App'
 # Explicit fixed controller commands; leave the guest's script policy intact.
 $installer=Get-Content -LiteralPath (Join-Path $package '_internal/Install-ProtectionService.ps1') -Raw
 & ([ScriptBlock]::Create($installer)) -WatchFolders @($controls) -PackageRoot $package -TrackAppChanges
 $installed=$true;Start-Service SentinelAVProtection
 $viewFile='C:\ProgramData\SentinelAVProtection\data\app-changes-view.bin'
 $deadline=(Get-Date).AddSeconds(90)
 while(!(Test-Path -LiteralPath $viewFile)){
  if((Get-Date) -gt $deadline){
   Get-Content 'C:\ProgramData\SentinelAVProtection\data\last-error.txt' -ErrorAction SilentlyContinue
   throw 'Protected history was not published'
  }
  Start-Sleep -Milliseconds 500
 }
 Add-Type -AssemblyName System.Security
 $raw=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($viewFile),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
 $view=[Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
 $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 if($view.owner_sid -ne $owner){throw 'Service owner mismatch'}
 $record=@($view.rows | Where-Object {$_.resource.kind -eq 'registry' -and $_.resource.name -eq $name -and $_.resource.view -eq 64})
 if($record.Count -ne 1){throw 'Generated machine control was not inventoried'}
 if(@($view.rows | Where-Object {$_.resource.hive -eq 'HKCU'}).Count){throw 'Service misrepresented LocalService HKCU as user tracking'}
 $requests=Join-Path $env:LOCALAPPDATA 'SentinelAV/broker-requests';New-Item -ItemType Directory -Path $requests -Force | Out-Null
 $exe=Join-Path $env:ProgramFiles 'SentinelAVProtection/SentinelAV.exe'
 function Invoke-ControlRequest($request){
  $id=[guid]::NewGuid().ToString('N')
  $inputFile=Join-Path $requests ($id+'.json')
  $request | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $inputFile -Encoding utf8
  $process=Start-Process -FilePath $exe -ArgumentList @('--remediation-broker',$id) -WindowStyle Hidden -Wait -PassThru
  $output=Join-Path ('C:\ProgramData\SentinelAVProtection\response\'+$owner) ('result-'+$id+'.bin')
  $bytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($output),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
  $answer=[Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
  if($answer.ok -or $process.ExitCode -ne 1){throw 'Unsafe control request was accepted'}
  Remove-Item -LiteralPath $inputFile
  return @{response=$answer;path=$output}
 }
 $benign=Invoke-ControlRequest @{schema=1;operation='prepare';change_ids=@($record[0].id)}
 if($benign.response.error -notlike '*No fresh malicious*'){throw ('Unexpected benign-control response: '+$benign.response.error)}
 Set-Content -LiteralPath $file -Value 'SENTINELAV_DEMO_THREAT_7C23A'
 $demo=Invoke-ControlRequest @{schema=1;operation='prepare';change_ids=@($record[0].id)}
 if($demo.response.error -notlike '*No fresh malicious*'){throw ('Unexpected demo-control response: '+$demo.response.error)}
 $forged=Invoke-ControlRequest @{schema=1;operation='prepare';change_ids=@($record[0].id);verdict='malicious'}
 if($forged.response.error -notlike '*Unsupported broker input*'){throw 'Client verdict was not explicitly rejected'}
 $acl=Get-Acl -LiteralPath $forged.path
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544'){throw 'Broker record has an untrusted owner'}
 $sid=[Security.Principal.SecurityIdentifier]::new($owner)
 $rights=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference -eq $sid -and $_.AccessControlType -eq 'Allow'})
 foreach($rule in $rights){if(([int]$rule.FileSystemRights -band 0xD0156) -ne 0){throw 'Non-elevated owner received write/ACL rights'}}
 if((Get-ItemPropertyValue -LiteralPath $key -Name $name) -cne $value){throw 'A protected control was changed'}
 if((Get-Content -LiteralPath $file -Raw).Trim() -ne 'SENTINELAV_DEMO_THREAT_7C23A'){throw 'Control file was changed'}
 @{schema=1;status='PASS';protected_service=$true;machine_history=$true;benign_cleanup_denied=$true;demo_cleanup_denied=$true;client_verdict_denied=$true;administrative_record_owner=$true;owner_read_only=$true;controls_unchanged=$true;malware_executed=$false} | ConvertTo-Json | Set-Content 'C:\SentinelAV-Test\response-boundary.json' -Encoding utf8
 Write-Output 'PASS: protected service history and broker controls'
} finally {
 Remove-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue
 if($installed){Stop-Service SentinelAVProtection -ErrorAction SilentlyContinue}
}

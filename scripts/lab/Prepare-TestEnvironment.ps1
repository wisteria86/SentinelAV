# Purpose: Stage a hashed read-only Sandbox input kit and its isolation configuration.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts/lab
# Used by: the CLI, desktop launcher, or packaging workflow

# Stage only known application/native build files. No certificate private keys or samples.
param([string]$PackageRoot,[switch]$SealedStaticPilot,[switch]$SealedStaticCorpus,[switch]$SealedStaticHoldout,[switch]$SealedZeusValidation,[string]$ApprovedInventory,[ValidateRange(0,100000)][int]$BatchOffset=0,[ValidateRange(1,32)][int]$BatchCount=32,[string]$ZooInput)
$ErrorActionPreference = 'Stop'
if ($SealedStaticPilot -and ($SealedStaticCorpus -or $SealedStaticHoldout -or $SealedZeusValidation)) { throw 'Pilot cannot be combined with corpus inputs' }
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot 'WorkPaths.ps1')
$labRoot = Get-SentinelLabRoot
if (!(Test-Path -LiteralPath (Join-Path $labRoot 'latest.json')) -and (Get-Command wsb.exe -ErrorAction SilentlyContinue)) {
    $existing=wsb.exe list --raw | ConvertFrom-Json
    if (@($existing.WindowsSandboxEnvironments).Count) { throw 'A legacy or unregistered guest is running; do not replace its ownership registry during work-drive migration.' }
}
if (!$PackageRoot) { $PackageRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $labRoot)) 'builds/dist/SentinelAV' }
$packageRoot = [IO.Path]::GetFullPath($PackageRoot)
$nativeRoot = Join-Path $projectRoot 'artifacts/native/amsi'
if (Test-Path -LiteralPath (Join-Path $nativeRoot 'SentinelAVAmsi.dev-signed.dll')) {
    $signing=Get-Content -LiteralPath (Join-Path $nativeRoot 'signing-record.json') -Raw | ConvertFrom-Json
    if ((Get-FileHash -LiteralPath (Join-Path $nativeRoot 'SentinelAVAmsi.dll')).Hash -ne $signing.source_sha256 -or (Get-FileHash -LiteralPath (Join-Path $nativeRoot 'SentinelAVAmsi.dev-signed.dll')).Hash -ne $signing.signed_sha256) {
        throw 'Signed provider is stale or unrecorded. Re-sign the current build with scripts/Sign-DevelopmentProvider.ps1.'
    }
}
function Assert-UnlinkedPath([string]$Path) {
    $entry = Get-Item -LiteralPath $Path -ErrorAction Stop
    while ($null -ne $entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Linked staging path rejected: ' + $entry.FullName) }
        $entry = $entry.Parent
    }
}
Assert-UnlinkedPath $projectRoot
if (-not (Test-Path -LiteralPath (Join-Path $packageRoot 'SentinelAV.exe') -PathType Leaf)) { throw 'Build the application first: .\build.ps1 -Installer' }
Assert-UnlinkedPath $packageRoot
$packageFiles = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force)
if ($packageFiles.Count -gt 8192) { throw 'Package file limit exceeded' }
if ($packageFiles | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Linked package member rejected' }
New-Item -ItemType Directory -Path $labRoot -Force | Out-Null
Assert-UnlinkedPath $labRoot
$previous=$null
if (Test-Path -LiteralPath (Join-Path $labRoot 'latest.json')) { $previous=Get-Content -LiteralPath (Join-Path $labRoot 'latest.json') -Raw | ConvertFrom-Json }
$kitId = [guid]::NewGuid().ToString('N')
$kitRoot = Join-Path $labRoot ('kit-' + $kitId)
$inputRoot = Join-Path $kitRoot 'input'
New-Item -ItemType Directory -Path $inputRoot | Out-Null
Copy-Item -LiteralPath $packageRoot -Destination (Join-Path $inputRoot 'App') -Recurse
$nativeOutput = Join-Path $inputRoot 'native'
New-Item -ItemType Directory -Path $nativeOutput | Out-Null
foreach ($name in @('SentinelAVAmsi.dll','SentinelAVAmsi.dev-signed.dll','AmsiHarness.exe','AmsiProbe.exe')) {
    $source = Join-Path $nativeRoot $name
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Assert-UnlinkedPath $source
        Copy-Item -LiteralPath $source -Destination (Join-Path $nativeOutput $name)
    }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Start-Guest.cmd') -Destination (Join-Path $inputRoot 'Start-Guest.cmd')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guest/Check-ResponseBoundary.ps1') -Destination (Join-Path $inputRoot 'Check-ResponseBoundary.ps1')
if ($SealedStaticPilot) {
    $sealedRoot=Join-Path (Split-Path -Parent $labRoot) 'sealed-static-pilot'
    $sealed=Join-Path $sealedRoot 'pilot.sealed'
    Assert-UnlinkedPath $sealed
    $record=Get-Content -LiteralPath (Join-Path $sealedRoot 'acquisition.json') -Raw | ConvertFrom-Json
    if ((Get-Item -LiteralPath $sealed).Length -ne 3481617 -or (Get-FileHash -LiteralPath $sealed).Hash -ne $record.sealed_sha256 -or $record.host_storage -ne 'AES-256-GCM ciphertext') { throw 'Sealed pilot identity mismatch' }
    Copy-Item -LiteralPath $sealed -Destination (Join-Path $inputRoot 'pilot.sealed')
    # Never map the DPAPI transfer key or any unpacked sample.
}
foreach($group in @(@{enabled=$SealedStaticCorpus;folder='sealed-static-corpus';names='corpus-emotet.sealed,corpus-mirai.sealed,corpus-wannacry.sealed,corpus-zeusvm.sealed';count=4},@{enabled=$SealedStaticHoldout;folder='sealed-static-holdout';names='corpus-gameover.sealed,corpus-wannacryplus.sealed';count=2},@{enabled=$SealedZeusValidation;folder='sealed-zeus-validation';names='corpus-gameoveralt.sealed,corpus-zeusbanking.sealed';count=2})) {
    if(!$group.enabled){continue}
    $sealedRoot=Join-Path (Split-Path -Parent $labRoot) $group.folder
    $acquisition=Join-Path $sealedRoot 'acquisition.json'
    Assert-UnlinkedPath $acquisition
    if((Get-Item -LiteralPath $acquisition).Length -gt 32768){throw 'Oversized acquisition record'}
    $record=Get-Content -LiteralPath $acquisition -Raw | ConvertFrom-Json
    $names=@($record.files.file | Sort-Object -Unique)
    if($record.host_storage -ne 'AES-256-GCM ciphertext' -or @($record.files).Count -ne $group.count -or ($names -join ',') -ne $group.names){throw 'Unexpected sealed corpus inventory'}
    foreach($item in $record.files){
        $sealed=Join-Path $sealedRoot $item.file
        Assert-UnlinkedPath $sealed
        if((Get-Item -LiteralPath $sealed).Length -ne $item.sealed_bytes -or $item.sealed_bytes -gt 8388636 -or (Get-FileHash -LiteralPath $sealed).Hash -ne $item.sealed_sha256){throw 'Sealed corpus identity mismatch'}
        Copy-Item -LiteralPath $sealed -Destination (Join-Path $inputRoot $item.file)
    }
}
$supportRoot=Join-Path (Split-Path -Parent $labRoot) 'qualification/support'
if(Test-Path -LiteralPath (Join-Path $supportRoot 'manifest.json')) {
    Assert-UnlinkedPath $supportRoot
    $support=Get-Content -LiteralPath (Join-Path $supportRoot 'manifest.json') -Raw | ConvertFrom-Json
    if($support.schema -ne 1 -or !$support.sysmon_eula_accepted){throw 'Lab support not approved'}
    $supportOutput=Join-Path $inputRoot 'LabSupport'
    New-Item -ItemType Directory -Path $supportOutput | Out-Null
    foreach($item in $support.files){
        $source=[IO.Path]::GetFullPath((Join-Path $supportRoot $item.path))
        if(!$source.StartsWith($supportRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Support path escapes root'}
        Assert-UnlinkedPath $source
        if((Get-FileHash -LiteralPath $source).Hash -ne $item.sha256){throw 'Lab support changed'}
        $destination=Join-Path $supportOutput $item.path
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
    }
}
$installer=Join-Path (Split-Path -Parent (Split-Path -Parent $labRoot)) 'builds/release/SentinelAV-Setup-0.17.0.exe'
if(Test-Path -LiteralPath $installer){Assert-UnlinkedPath $installer;Copy-Item -LiteralPath $installer -Destination (Join-Path $inputRoot 'Installer.exe')}
$previousInstaller=Join-Path (Split-Path -Parent (Split-Path -Parent $labRoot)) 'builds/release/SentinelAV-Setup-0.15.0.exe'
if(Test-Path -LiteralPath $previousInstaller){Assert-UnlinkedPath $previousInstaller;Copy-Item -LiteralPath $previousInstaller -Destination (Join-Path $inputRoot 'PreviousInstaller.exe')}
if($ApprovedInventory){
    if($ApprovedInventory -notmatch '^[a-zA-Z0-9_.-]{1,100}$'){throw 'Invalid approved inventory name'}
    $qualificationRoot=Join-Path (Split-Path -Parent $labRoot) 'qualification'
    $inventoryPath=Join-Path $qualificationRoot ('inventories/'+$ApprovedInventory+'.json')
    Assert-UnlinkedPath $inventoryPath
    $approved=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
    if($approved.schema -ne 1 -or !$approved.approved -or $approved.role -ne 'qualification'){throw 'Unapproved qualification corpus'}
    $approvedOutput=Join-Path $inputRoot 'Approved';New-Item -ItemType Directory -Path $approvedOutput|Out-Null
    $selected=@($approved.files|Select-Object -Skip $BatchOffset -First $BatchCount)
    if($approved.positive_control){$selected+=@($approved.positive_control)}
    foreach($item in $selected){
        if($item.blob -notmatch '^[a-zA-Z0-9_.-]{1,100}\.sealed$'){throw 'Invalid ciphertext name'}
        $sealed=Join-Path $qualificationRoot ('corpora/'+$ApprovedInventory+'/'+$item.blob)
        Assert-UnlinkedPath $sealed
        if((Get-Item -LiteralPath $sealed).Length -gt 8388636 -or (Get-FileHash -LiteralPath $sealed).Hash -ne $item.sealed_sha256){throw 'Approved ciphertext differs'}
        Copy-Item -LiteralPath $sealed -Destination (Join-Path $approvedOutput $item.blob)
    }
}
if($ZooInput){
    Assert-UnlinkedPath $ZooInput
    $archives=@(Get-ChildItem -LiteralPath $ZooInput -File -Force)
    if($archives.Count -gt 4){throw 'Zoo batch exceeds archive limit'}
    $zooOutput=Join-Path $inputRoot 'Zoo'
    New-Item -ItemType Directory -Path $zooOutput | Out-Null
    foreach($archive in $archives){
        Assert-UnlinkedPath $archive.FullName
        if($archive.Name -cnotmatch '^[a-f0-9]{40}\.zip$' -or $archive.Length -gt 67108864){throw 'Invalid pinned Zoo archive'}
        Copy-Item -LiteralPath $archive.FullName -Destination (Join-Path $zooOutput $archive.Name)
    }
}
$hashes = [ordered]@{}
Get-ChildItem -LiteralPath $inputRoot -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($inputRoot.Length + 1)
    $hashes[$relative] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifest = [ordered]@{schema=1;kit_id=$kitId;purpose='Harmless SentinelAV/AMSI development checks only';files=$hashes}
if ($SealedStaticPilot) { $manifest.purpose='Harmless bootstrap plus one AES-GCM sealed static pilot; no sample execution' }
if ($SealedStaticCorpus) { $manifest.purpose='Harmless bootstrap plus four pinned AES-GCM sealed static samples; no sample execution' }
if ($SealedStaticHoldout) { $manifest.purpose='Harmless bootstrap and fixed AES-GCM sealed static evaluation/holdout inputs; no sample execution' }
if ($SealedZeusValidation) { $manifest.purpose='Harmless bootstrap and fixed AES-GCM sealed Zeus validation inputs; no sample execution' }
$manifestPath = Join-Path $inputRoot 'manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$escapedInput = [Security.SecurityElement]::Escape($inputRoot)
$configuration = @"
<Configuration>
  <Networking>Disable</Networking>
  <vGPU>Disable</vGPU>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$escapedInput</HostFolder>
      <SandboxFolder>C:\SentinelAV-Input</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\Windows\System32\cmd.exe /d /k C:\SentinelAV-Input\Start-Guest.cmd</Command>
  </LogonCommand>
</Configuration>
"@
$configPath = Join-Path $kitRoot 'SentinelAV-Test.wsb'
$configuration | Set-Content -LiteralPath $configPath -Encoding utf8
$status = [ordered]@{
    schema=1;kit_id=$kitId;created_utc=[DateTime]::UtcNow.ToString('o');configuration=$configPath;input=$inputRoot
    configuration_sha256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    manifest_sha256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    state='Prepared; guest isolation and checks not yet verified';guest_executed=$false
}
if ($previous.active_guest_verified -and $previous.active_guest_id -match '^[0-9a-f-]{36}$') {
    $status['active_guest_id']=$previous.active_guest_id
    $status['active_guest_kit_id']=$previous.active_guest_kit_id
    $status['active_guest_verified']=$true
} elseif ($previous.guest_executed -and $previous.guest_id -match '^[0-9a-f-]{36}$') {
    $status['active_guest_id']=$previous.guest_id
    $status['active_guest_kit_id']=$previous.kit_id
    $status['active_guest_verified']=$true
}
$status | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'latest.json') -Encoding utf8
Write-Output ('Prepared: ' + $configPath)
Write-Output 'No VM or guest has been started. No provider/service registration or Windows policy change was performed.'

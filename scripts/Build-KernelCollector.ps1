# Purpose: Build the read-only native ETW collector into managed F: storage.
# Works with: the matching src/sentinelav subsystem; related scripts in scripts
# Used by: the CLI, desktop launcher, or packaging workflow

param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$workRoot=if($env:SENTINELAV_WORK_ROOT){[IO.Path]::GetFullPath($env:SENTINELAV_WORK_ROOT)}else{'F:\SentinelAV-Work'}
if(!(Test-Path -LiteralPath ([IO.Path]::GetPathRoot($workRoot)))){throw 'Managed work drive unavailable; no C: fallback'}
$env:DOTNET_CLI_HOME=Join-Path $workRoot 'cache/dotnet-home'
$env:NUGET_PACKAGES=Join-Path $workRoot 'cache/nuget'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $workRoot ('builds/native/telemetry/'+[guid]::NewGuid().ToString('N')) }
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if(!$destination.StartsWith($workRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Collector build output must stay under managed F: work storage'}
if (Test-Path -LiteralPath $destination) { throw 'Build output must be a new directory.' }
$dotnet=Join-Path $projectRoot 'tools/vendor/dotnet-sdk/dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) {
    $command=Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $command) { throw '.NET 8 SDK is required to build the collector.' }
    $dotnet=$command.Source
}
$project = Join-Path $projectRoot 'native/telemetry/SentinelAV.Telemetry.csproj'
$intermediate=(Join-Path $workRoot ('builds/native/collector-intermediate/'+[guid]::NewGuid().ToString('N'))).Replace('\','/')+'/'
& $dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false ('-p:BaseIntermediateOutputPath='+$intermediate) -o $destination
if ($LASTEXITCODE -ne 0) { throw 'Native collector build failed; no deployment was attempted.' }
$files = @()
foreach ($file in Get-ChildItem -LiteralPath $destination -File -Recurse) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked build output rejected.' }
    $relative = $file.FullName.Substring($destination.TrimEnd('\').Length+1).Replace('\','/')
    $files += [ordered]@{path=$relative;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$file.Length}
}
$manifest = Join-Path $destination 'collector-manifest.json'
[ordered]@{schema=1;product='SentinelAV.Telemetry';files=$files} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifest -Encoding UTF8
Write-Output $manifest
Get-FileHash -LiteralPath $manifest -Algorithm SHA256

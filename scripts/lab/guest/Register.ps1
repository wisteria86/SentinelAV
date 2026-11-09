# Purpose: Register the explicitly owned guest AMSI provider and record deployment state.
# Works with: Common.ps1; native/amsi/probe.cpp; Remove.ps1
# Used by: the CLI, desktop launcher, or packaging workflow

Read-State
if (Test-Path -LiteralPath $classKey) { throw 'Existing class key preserved' }
if (Test-Path -LiteralPath $providerKey) { throw 'Existing provider key preserved' }
Assert-Unlinked $install
$source=Join-Path $root ('native\'+$(if ($variant -eq 'SelfSigned') {'SentinelAVAmsi.dev-signed.dll'} else {'SentinelAVAmsi.dll'}))
if (!(Test-Path -LiteralPath $source)) { throw 'Requested provider artifact is missing' }
if (!(Test-Path -LiteralPath $providerRoot)) { New-Item -ItemType Directory -Path $providerRoot | Out-Null; Mark-Owned $providerRoot }
if ((Get-Content -LiteralPath (Join-Path $providerRoot '.sentinelav-deployment') -Raw).Trim() -ne $state.id) { throw 'Provider directory ownership mismatch' }
$dll=Join-Path $providerRoot 'SentinelAVAmsi.dll'
Copy-Item -LiteralPath $source -Destination $dll -Force
& icacls.exe $providerRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' '*S-1-5-11:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE) { throw 'Provider ACL failed' }
& icacls.exe $providerRoot '/setowner' '*S-1-5-32-544' '/T' '/C' | Out-Null
if ($LASTEXITCODE) { throw 'Provider ownership failed' }
Assert-OtherProviders
New-Item -Path $classKey | Out-Null
New-ItemProperty -LiteralPath $classKey -Name SentinelAVDeploymentId -Value $state.id -PropertyType String | Out-Null
Set-Item -LiteralPath $classKey -Value 'SentinelAV development provider'
$server=New-Item -Path ($classKey+'\InprocServer32')
Set-Item -LiteralPath $server.PSPath -Value $dll
New-ItemProperty -LiteralPath $server.PSPath -Name ThreadingModel -Value Both -PropertyType String | Out-Null
New-Item -Path $providerKey | Out-Null
New-ItemProperty -LiteralPath $providerKey -Name SentinelAVDeploymentId -Value $state.id -PropertyType String | Out-Null
Set-Item -LiteralPath $providerKey -Value 'SentinelAV development provider'
$state.variant=$variant; $state.phase='Provider registered'; Save-State
Assert-OtherProviders

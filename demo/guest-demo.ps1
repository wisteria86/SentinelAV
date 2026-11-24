# Purpose: Runs inside the Windows Sandbox started by SampleRun.bat: opens SentinelAV and scans the demo samples.
# Works with: SampleRun.bat
# Encrypted samples are decrypted here to theZoo's password-protected ZIPs, which SentinelAV reads in memory; nothing is run.

$ErrorActionPreference = 'Continue'
$Host.UI.RawUI.WindowTitle = 'SentinelAV live demo'
$app = 'C:\SentinelAV\SentinelAV.exe'
$work = 'C:\DemoRun'
New-Item -ItemType Directory -Force "$work\clamd", "$work\data" | Out-Null

# Frozen definitions and ClamAV from the evaluation snapshot, mapped read-only.
$env:SENTINELAV_DEFINITIONS = 'C:\Definitions\definitions'
$env:SENTINELAV_CLAMAV_DB = 'C:\Definitions\clamav-db'
$env:SENTINELAV_CLAMAV_HOME = 'C:\Definitions\clamav'
$env:SENTINELAV_CLAMAV_RUNTIME = "$work\clamd"

function Line($text, $color = 'Gray') { Write-Host $text -ForegroundColor $color }

Clear-Host
Line ''
Line '  SentinelAV live demo' 'Cyan'
Line '  Offline Windows Sandbox. No network. Erased when closed.' 'DarkCyan'
Line ''
# The host keeps samples encrypted; turn them back into theZoo's password-protected ZIPs here, inside the Sandbox.
$samples = "$work\samples"
New-Item -ItemType Directory -Force $samples | Out-Null
foreach ($sealed in Get-ChildItem C:\Samples -Filter *.sealed) {
    $hex = (Get-Content ($sealed.FullName -replace '\.sealed$', '.key') -Raw).Trim()
    $key = [byte[]]::new(32); for ($i = 0; $i -lt 32; $i++) { $key[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    $bytes = [IO.File]::ReadAllBytes($sealed.FullName)
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $key; $aes.IV = $bytes[0..15]
    $plain = $aes.CreateDecryptor().TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    [IO.File]::WriteAllBytes((Join-Path $samples ($sealed.Name -replace '\.sealed$', '')), $plain)
}

Line '  Samples (still inside their password-protected theZoo ZIPs):' 'White'
foreach ($file in Get-ChildItem $samples -File) {
    $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
    Line ("    {0}  ({1:N0} KB)" -f $file.Name, ($file.Length / 1KB))
    Line ("    SHA-256 {0}" -f $hash) 'DarkGray'
}
Line ''

Line '  Opening SentinelAV...' 'White'
Start-Process $app
Start-Sleep -Seconds 5

Line "  Scanning $samples (archives are read in memory, nothing is run)..." 'White'
$started = Get-Date
$out = "$work\scan.json"
$process = Start-Process $app -ArgumentList '--scan', $samples -RedirectStandardOutput $out -RedirectStandardError "$work\scan.err" -PassThru -Wait -WindowStyle Hidden
$seconds = [int]((Get-Date) - $started).TotalSeconds

try { $result = Get-Content $out -Raw | ConvertFrom-Json } catch { $result = $null }
if (-not $result) {
    Line '  The scan did not return a result.' 'Red'
    Get-Content "$work\scan.err" -ErrorAction SilentlyContinue | Select-Object -Last 5 | ForEach-Object { Line "    $_" 'DarkGray' }
} else {
    Line ("  Done in {0} s: {1} file(s) checked." -f $seconds, $result.scanned) 'White'
    Line ''
    # One line per file: when the archive and the program inside it are both reported, show the fuller finding.
    $found = @($result.detections) + @($result.suspicious) | Where-Object { $_ } | Group-Object path |
        ForEach-Object { $_.Group | Sort-Object { @($_.reasons).Count } -Descending | Select-Object -First 1 }
    if (-not $found) { Line '  Nothing was flagged.' 'Yellow' }
    foreach ($item in $found) {
        $color = if ($item.verdict -eq 'Malicious') { 'Red' } else { 'Yellow' }
        Line ("  {0}  score {1}/100, {2} confidence" -f $item.verdict.ToUpper(), $item.score, $item.confidence) $color
        Line ("    Threat:  {0}" -f $item.threat_name) 'White'
        $where = if ($item.member_chain) { ($item.member_chain -join ' > ') } else { $item.path }
        Line ("    File:    {0}" -f $where)
        foreach ($reason in @($item.reasons | Select-Object -First 4)) { Line ("    - {0}" -f $reason) 'Gray' }
        Line ''
    }
}
Line '  The result is also in the SentinelAV window under Reports.' 'Cyan'
Line '  You can run your own scan there: Scan > Custom scan > C:\DemoRun\samples.' 'Cyan'
Line ''
Read-Host '  Press Enter to close this window' | Out-Null

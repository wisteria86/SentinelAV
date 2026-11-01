$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$source = 'SentinelAV.ProcessStart'
try {
    Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier $source -ErrorAction Stop | Out-Null
    Write-Output '{"kind":"ready"}'
    while ($true) {
        $pending = @(Get-Event -SourceIdentifier $source -ErrorAction SilentlyContinue)
        if ($pending.Count -gt 512) {
            $trim = @($pending | Select-Object -First ($pending.Count - 256))
            foreach ($event in $trim) { Remove-Event -EventIdentifier $event.EventIdentifier }
            Write-Output ([pscustomobject]@{kind='dropped';count=$trim.Count} | ConvertTo-Json -Compress)
        }
        $event = Wait-Event -SourceIdentifier $source -Timeout 1
        if ($null -ne $event) {
            $item = $event.SourceEventArgs.NewEvent
            Write-Output ([pscustomobject]@{kind='start';pid=[int]$item.ProcessID;parent_pid=[int]$item.ParentProcessID;name=[string]$item.ProcessName;timestamp=[string]$item.TIME_CREATED} | ConvertTo-Json -Compress)
            Remove-Event -EventIdentifier $event.EventIdentifier
        }
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
} finally { Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue }

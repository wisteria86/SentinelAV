# Protected machine remediation — 0.14.0

The protection service remains LocalService. It tracks machine Run entries,
common Startup files, tasks and service configuration independently of the GUI.
Its own HKCU hive is excluded. Personal settings and Startup tracking remain in
the per-user agent.

For a new administrator-reviewed protected deployment:

```powershell
.\scripts\Install-ProtectionService.ps1 -WatchFolders @('C:\Users\Public') -PackageRoot F:\SentinelAV-Work\builds\dist\SentinelAV -TrackAppChanges
Start-Service SentinelAVProtection
```

The installer refuses to overwrite an existing deployment. Do not delete live
deployment directories to force an upgrade. Broader upgrade/repair migration is
still a release requirement. GUI and helper must use the configured owner SID;
elevation with different administrator credentials is rejected.

Choose **Protected service — machine changes** in App Changes, then refresh.
The encrypted view is readable only by the configured owner and trusted
administrative/service accounts. Machine DPAPI supports the LocalService-to-user
handoff; protected ACLs enforce account access. The private journal retains
service-account DPAPI encryption.

**Review cleanup** requests UAC. The helper under protected Program Files verifies
installation integrity, owner identity, current configuration and fresh exact-file
detections. It accepts bounded change IDs rather than commands, arbitrary paths,
claimed verdicts, baselines or scanner options. Demo/EICAR and unmanaged YARA
matches cannot authorize machine repair.

Plans are encrypted, administratively owned and read-only to the ordinary user
token. **Apply reviewed plan** requests UAC again and the elevated helper confirms
the exact targets in its own dialog. This prevents a substituted unprivileged
request from silently selecting another target. Two-minute expiry, conflict
checks, journalling and fresh evidence still apply. Cancellation makes no repair.

The broker disables verified machine Run entries, tasks and services. Machine
persistence restoration, process termination and file quarantine are outside this
broker's scope; supported per-user response remains separate. Receipts report
payloads that remain: disabling persistence alone cannot claim verified removal.
System, shared-host and protected-application safeguards remain in force.

The fixed harmless test `scripts/lab/Test-ResponseBroker.ps1` proved protected
deployment, encrypted machine history, exclusion of service HKCU, administrative
record ownership, owner read-only ACLs, rejection of benign/demo/forged-verdict
requests and unchanged controls in an offline Sandbox. No host service or Windows
protection was modified. Explicit fixed controller commands leave the guest's
Restricted script policy intact.

This evidence does not prove interactive UAC behavior, positive malware repair,
large-scale false-positive safety or broad efficacy. Those remain release gates.

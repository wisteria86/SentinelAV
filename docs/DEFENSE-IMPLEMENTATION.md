# Defense-layer milestone — scope and deployment gates

This release adds user-mode capabilities and protected-service deployment code.
It does not implement every commercial anti-evasion protection. Broad efficacy,
VM, and live-malware evaluation remain deferred at the user's request.

| Requested layer | Implemented now | Still required / scope limit |
| --- | --- | --- |
| Windows service / secure GUI relationship | SCM service host, LocalService-only guard, protected-path/ACL checks, integrity manifest, admin deployment script, recovery configuration, read-only SCM/heartbeat/recent-alert UI | Not installed or started on this PC. Actual LocalService deployment and lifecycle require administrator approval and folder-access review. GUI source/per-user mode remains separate; it cannot reconfigure the service. |
| Event-driven process telemetry | Temporary Win32_ProcessStartTrace WMI subscription, bounded queues, ancestry capture, polling reconciliation and explicit gaps | Current account returned Access denied in the probe; polling fallback remains. Rights/configuration must be reviewed for the deployment account. No permanent WMI subscription or Windows audit-policy changes are made. |
| AMSI | Opt-in consumer calls for directly scanned script files through installed Windows providers | An x64 native COM provider and guarded LocalService byte-scanning broker are implemented and tested with a local inert harness. Neither is deployed as active protection. Signing, registration/removal, actual LocalService and real-host/VM validation remain. See AMSI-PROVIDER.md. No Windows signing checks are weakened. |
| Pre-execution | Read-only file check with explicit Block/Indeterminate/Not-approved decisions; checks file identity; never launches the file | No system-wide launch interception or enforcement. A caller must enforce a verdict and handle later races. A reviewed native minifilter or carefully deployed OS application-control integration is needed. |
| Archives / formats | ZIP inspection in memory, including prepended ZIPs; bounded PE-header metadata | ZIP depth 2, 128 entries, 8 MiB/member, 32 MiB total expansion, ratio 100:1 and wall-clock bounds. No disk extraction. Encrypted, oversized, unsafe, unsupported or timed-out members are omissions. No general executable unpacker, OLE parser, or complete document engine. |
| Memory / runtime | Isolated, read-only same-account executable-region inspection; two source-attributed memory candidate rules; no raw-memory saving | 32 MiB total, 128 regions, 1 MiB/region and time/traversal limits. Not a full memory scan; candidates require review. No injection, process modification, SeDebugPrivilege enabling, or protected-process bypass. |
| Behavioral correlation | PID/create-time graph; visible-ancestor validation; indirect Office/interpreter context; existing multi-indicator scoring | Polling/event gaps and exited ancestors remain limits. Filesystem activity is not falsely attributed to a PID. Scores are suspicion, not proof. |
| Tamper / installation hardening | Staged admin-owned Program Files code/policy, explicit SCM/data ACLs, startup ownership/write-permission checks and integrity validation | Per-user mode stays user-writable. No PPL, ELAM, kernel self-protection, signed publisher deployment, or protection against an administrator/kernel attacker. |
| Policy containment | Default-off approved-exact-hash quarantine in per-user monitoring, bounded local folder scope, fresh verification, exclusive file handling, DPAPI, audit, cooldown and rate limit; manual restore | No score-only/YARA-only/memory-only automatic response, no automatic process termination, no archive-member auto-response. Service auto-response is disabled. Users must explicitly choose hashes and folders before enabling. |
| Parser fault isolation | Scan/response-verification workers in separate processes; Windows jobs with 768 MiB memory and two-process cap (venv redirector compatibility), bounded JSON framing, wall-clock timeout/cancellation, partial exact-hash result retention | Resource/fault isolation is **not** a VM, AppContainer or a restricted-token security sandbox. Workers retain the caller's account access. Definition conversion and other trusted tooling are not all isolated. |

## UI

Settings → Defense has Layers, Inspection, and Response Policy pages. Layer
details explain actual scope and remaining prerequisites. The pre-execution
button inspects only and never executes a file. Memory findings are review-only.
Automatic quarantine is off by default and applies only after settings are
saved and monitoring is restarted. Monitoring reports its process-event source,
dropped/uninspected starts, worker isolation, and policy activity.

## Native deployment prerequisites

MSVC 14.44 and Windows SDK 10.0.26100.0 are installed and verified with a native
compile/link check. The x64 AMSI provider now builds and has local harness
coverage. No signing certificate is supplied; WDK/kernel deployment remains
separate. Provider signature checks may be
enforced by Windows; our deployment must use an appropriately signed provider,
not disable those checks. A kernel minifilter additionally needs WDK work,
Microsoft-supported signing/deployment, recovery planning, and controlled
validation. None is installed or represented as active in this release.

References:
- https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/krnlprov/win32-processstarttrace

## Service deployment is a separate administrator action

The regular per-user installer does not register/start a service. Review
scripts/Install-ProtectionService.ps1 and the package before using an elevated shell:

```powershell
.\scripts/Install-ProtectionService.ps1 -WatchFolders 'C:\a\reviewed\folder'
```

For an installed package, supply `-PackageRoot` pointing at the directory
containing SentinelAV.exe. The script refuses existing deployment directories
or a pre-existing service instead of overwriting them. It copies packaged code
to Program Files\SentinelAVProtection; removes user write permissions; makes
Administrators the owner; creates a protected ProgramData policy/data split;
records installed file hashes; registers a LocalService service with explicit
SCM control permissions and failure recovery. It does not start the service.
Automatic startup is configured only after setup succeeds.

Existing watch-folder ACLs are not changed. LocalService must have sufficient
read/traverse access to chosen folders; an administrator must review minimum
access or use an appropriate shared folder. Do not broadly grant write access.
Then the administrator can use `Start-Service SentinelAVProtection` and inspect
Settings → Defense → Layers → Windows service details. To stop it, use the
normal administrator SCM controls; the per-user Stop Protection button controls
only per-user monitoring. Runtime policy fields are intentionally restricted;
GUI settings do not silently become privileged service policy.

Service status exposes a heartbeat and ten bounded recent warning/alert
summaries to the designated installer account. Full service events remain in
its protected SQLite store. Service definitions/publisher configuration are
admin-controlled and separate from per-user updates. Service deployment has
been checked with simulated SCM callbacks, not activated on this PC. Do not
interpret source/fixture checks as an actual deployed-service certification.

## Verification performed

Routine regressions use generated inert ZIP/text fixtures and test-owned worker
processes. Approved-hash quarantine/restore was checked against one generated
text fixture; an unrelated file remained unchanged. Native bounded memory reads
were checked against a test-owned Python process, with omissions retained and
no raw bytes saved. A harmless AMSI buffer returned a platform no-detection
result; this does not prove a SentinelAV provider exists. The WMI probe returned
Access denied and verified the need for the visible polling fallback.

No service installation, watch-folder permission change, kernel driver,
AMSI-provider registration, disabled security check, VM, or live malware test
was performed. Broader detection/evasion and false-positive evaluation remain
unmeasured.

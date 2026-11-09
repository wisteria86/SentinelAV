# Guest-only AMSI integration — 0.13.0

Validated on 2 November 2026 in Windows Sandbox on Windows 11 Pro build 26200.
The host antivirus configuration, trust stores and AMSI registrations were not
changed. No live malware was used, downloaded or introduced.

## Observed results

| Check | Result |
| --- | --- |
| Disposable reset | Guest-only marker disappeared after the old guest was stopped; a new identity, expected kit and harmless baseline were verified. |
| LocalService deployment | Real service startup passed protected code/policy ownership checks; broker became healthy and returned actual detection verdicts. |
| Self-signed DLL | Registered COM activation and the real Windows AMSI API both passed with the development-signed x64 DLL. |
| Real PowerShell | Benign comparison ran; an inert demo marker was blocked with a malicious-content error before its harmless test-write executed. |
| Concurrency | Four concurrent native Windows AMSI consumers passed the benign/marker comparison. This is not a production throughput benchmark. |
| Backend unavailable | Direct provider returned failure rather than a clean verdict with the service stopped; service restart restored a detected verdict. |
| Removal | Exact owned COM/AMSI keys, service and dedicated directories were removed. COM activation then returned class-not-registered. Repeated removal passed. |
| Rollback | Injected failures after service creation and after provider registration removed the owned deployment; sibling fixture and other provider inventory were preserved. |
| Ownership refusal | The native removal helper rejected a deliberately foreign-marked class fixture without deleting its contents. The harness cleaned up only its own fixture. |
| Source regression | 98 unit tests and ten UI scripts passed. Native tests include invalid-address rejection and Windows-style address-only streams. |

The guest had **FeatureBits=1** throughout. The certificate chain remained
untrusted, and no trusted-root/publisher certificate was installed. This proves
that the tested configuration accepted this provider without a purchase; it
does not establish acceptance under enforced signing, other Windows versions,
protected processes, or public distribution policies.

Defender's service existed but was **stopped** in this Sandbox image. Existing
provider registrations were preserved, but active Defender coexistence has
**not** been verified. It must not be reported as passed.

## Commands

From the project root, with an already verified guest running:

```powershell
.\scripts\lab\Invoke-GuestIntegration.ps1 -Action Install -Variant SelfSigned
.\scripts\lab\Invoke-GuestIntegration.ps1 -Action Check
.\scripts\lab\Invoke-GuestIntegration.ps1 -Action HostChecks
.\scripts\lab\Invoke-GuestIntegration.ps1 -Action FailureChecks
.\scripts\lab\Invoke-GuestIntegration.ps1 -Action Remove
.\scripts\lab\Invoke-GuestIntegration.ps1 -Action VerifyRemoved
.\scripts\lab\Invoke-GuestIntegration.ps1 -Action BoundaryChecks
```

To exercise rollback, start from a removed deployment and use Install with
either `-InjectFailure AfterService` or `-InjectFailure AfterRegistration`.
An error is expected, followed by successful owned rollback and VerifyRemoved.

After rebuilding the native DLL, re-sign only its development copy with your
existing self-signed code-signing certificate:

```powershell
.\scripts\Sign-DevelopmentProvider.ps1 -Thumbprint YOUR_40_HEX_THUMBPRINT
.\scripts\lab\Prepare-TestEnvironment.ps1
.\scripts\lab\Reset-TestEnvironment.ps1
```

Reset discards the explicitly registered guest. Preparing a new kit preserves
the active guest identity separately, so a new profile is not mistaken for a
verified running environment. A second launch is refused while a guest exists.

## Boundaries and recovery

The controller validates the recorded Sandbox ID against the official CLI and
uses fixed reviewed command bodies. The guest checks administrator context,
WDAG account, VM identity, matching kit ID and absence of active network
adapters. It leaves PowerShell execution policy unchanged; commands are sent
through the official Sandbox exec interface, not an arbitrary guest RPC server.

Registration uses only SentinelAV's fixed x64 CLSID and provider subkey with
deployment ownership markers. It refuses existing keys. Removal validates both
markers before deleting either key. A native helper unregisters before a new
PowerShell process is started, avoiding a DLL-in-use problem caused by loading
the provider into the uninstaller itself. Service handles are disposed, and
the owned process is allowed to exit before files are removed.

Recursive directory cleanup is restricted to four exact guest paths, rejects
reparse points, and requires matching deployment markers. Unmarked partial
directories are recoverable only during an installation whose preflight
recorded those exact targets as absent. This is not protection against a guest
administrator deliberately modifying both controller state and ownership data.

Rollback is orchestrated across guest commands, not an atomic transaction.
A host/controller crash can leave guest state requiring a subsequent Remove
or a disposable reset. Unknown ownership and unexpected changes fail closed.
Stage errors are retained separately so cleanup cannot hide the startup error.

During development, rebuilt native files were delivered through an additional
read-only update mapping. No writable host folder was added. Fresh prepared
kits return to a single read-only input mapping. Results remain guest-local;
host audit files contain stage/exit status, not raw script or memory content.

## Compatibility fix and limits

Windows' actual AmsiScanBuffer stream returned E_NOTIMPL from Read, unlike the
initial test stream. The provider now uses its content-address attribute as a
source for a checked ReadProcessMemory copy of at most 1 MiB **inside the same
host process**. Invalid pointers fail safely; there is no direct pointer
dereference, cross-process inspection, injection or privilege enabling here.

The YARA demo fixture now recognizes ASCII and UTF-16LE. That enabled the
harmless PowerShell check and is not new real-malware detection coverage.
General deobfuscation, cross-session reconstruction, x86, active antivirus
coexistence, broader OS/policy coverage and real-world efficacy remain pending.

References: [Microsoft provider registration](https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience),
[stream attributes](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iamsistream-getattribute),
[Windows AMSI consumer API](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer).

# Disposable SentinelAV development environment

The first environment uses built-in Windows Sandbox on this PC's Windows 11
Pro installation. It needs no separate Windows ISO. This is for harmless
application/AMSI integration checks, not a live-malware lab.

## Host checks performed

- Windows 11 Pro, build 26200.
- Ryzen 5 5600, virtualization enabled; Hyper-V hypervisor and services running.
- About 16 GB installed RAM. The profile requests 4 GB.
- Windows Sandbox feature was disabled during the initial check.
- No separate Windows ISO or VirtualBox/VMware installation was found.

The processor's SLAT field returned false while a hypervisor was already active.
That report alone is not a reliable rejection of this host. Actual Windows
feature activation and guest startup remain the decisive checks.

## Setup

The initial input kit has already been prepared and hash-checked. Rebuild it
after changing app/native binaries, from the project root:

    .\scripts\lab\Prepare-TestEnvironment.ps1
    .\scripts\lab\Start-TestEnvironment.ps1 -CheckOnly

Enable the Windows feature from an administrator PowerShell:

    & "C:\Users\pc\Downloads\sqlilab\sentinelav\scripts\lab\Enable-WindowsSandbox.ps1"

This enables only the requested Sandbox feature and its required dependencies,
and never restarts automatically. Save work and restart Windows if requested.
Activation details are saved to F:/SentinelAV-Work/lab/windows-sandbox/feature-status.json
and enable-feature.log.

After activation/restart, launch from the project root:

    .\scripts\lab\Start-TestEnvironment.ps1

Do not launch the default Windows Sandbox shortcut for these tests; use this
validated profile.

## Boundary

The profile requests networking, clipboard, GPU, microphone, camera and printer
redirection disabled, Protected Client enabled, and one **read-only** mapped
folder. That folder contains only a staged app package, native build artifacts,
and a fixed harmless bootstrap. No Downloads/home directory, credentials,
certificate private keys, or writable host result folder is mapped.

The launch helper verifies the pinned configuration, input inventory and file
hashes before launching. These are configuration checks, not proof of runtime
containment. A modified kit is refused; prepare a new one to update it.

The guest bootstrap checks expected guest identity, refuses active network
adapters, verifies input/copy hashes, and copies the app to guest-local storage.
It then runs the packaged harmless self-test and native COM/stream harness and
opens SentinelAV's normal UI inside the guest. Failures stop this sequence.

Results stay inside C:\SentinelAV-Test in the guest. No files are automatically
exported to the host. Closing Sandbox discards guest-local changes; relaunching
starts fresh. Prepared host input kits remain on disk.

## What is not ready yet

Prepared is not the same as guest-verified. Until the guest starts and checks
pass, the environment must be shown as unverified. This setup does not register
an AMSI provider, install a service, trust a certificate, or change any signing
policy. Those integration steps follow after this baseline works.

This is not the full Hyper-V snapshot/reset backend described in the lab plan.
The normal profile runs harmless checks. A separate pinned static-only pilot
now supports authenticated ciphertext transfer and guest-only unpacking of one
hash-verified research sample. A separate fixed four-family corpus mode adds
signed guest-image controls; see [Static evaluation](STATIC-EVALUATION.md).
There is no arbitrary sample execution or general sample-import UI.

References: [Microsoft installation](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install),
[configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file),
[disposable environment behavior](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview).

## Verified integration milestone

Reset, real LocalService deployment and self-signed registered-provider tests
have now passed inside Sandbox. See [GUEST-AMSI-VALIDATION.md](GUEST-AMSI-VALIDATION.md)
for commands, cleanup, failure tests and limitations. The normal launch still
does not install/register anything automatically. Preparing a new kit retains
the old verified guest identity for Reset-TestEnvironment.ps1; it does not
mark that new kit as already verified.

## Repeatable runtime boundary check

After launching the pinned profile and allowing its bootstrap to finish, run:

    .\scripts\lab\Test-SandboxBoundary.ps1

This checks the guest account/model, matching input kit, absence of active
network adapters, successful packaged detection and four harmless simulation
profiles. It attempts one uniquely named inert text-file write to the mapped
input folder and requires access-denied/write-protected failure. It does not
read the host clipboard or change any sharing settings. On success it records
the currently verified guest identity for subsequent integration checks.

The configuration checks cover clipboard/device redirection; runtime clipboard
is still untested. Neither this script nor the integration suite establishes
that this environment is suitable for arbitrary live malware execution. The
separate pinned static pilot does not grant permission to execute samples.

For service/AMSI verification, use the fixed Install, Check, HostChecks,
FailureChecks, Remove and VerifyRemoved actions of Invoke-GuestIntegration.ps1.
Always remove the temporary deployment in a finally block. Reset checks use
Reset-TestEnvironment.ps1 and discard only the registered disposable guest.

The source unit suite exercises encrypted quarantine, exact-content recovery,
no-overwrite, stale detection, tampered blobs and audit events.

The updated packaged --self-test also runs a Qt response lifecycle. It reserves
a fresh harmless marker under the guest's temporary directory, activates Select
Files, Quarantine Selected and Restore controls, and runs real scan/response
workers. Only file-picker answers and confirmation answers are supplied by the
test harness. It checks encrypted storage, original removal, refusal to overwrite
an occupied destination, restored byte/hash equality, unchanged trust, repeat
detection and audit events. The generated temporary files are removed afterward.
Two widget screenshots and response evidence stay in the guest self-test folder.
This is an automated Qt integration check, not a manual desktop-click test or
validation of the native file-picker and confirmation-dialog interactions.

To stage a separate experimental bundle without replacing the release installer:

    .\scripts\lab\Prepare-TestEnvironment.ps1 -PackageRoot C:\absolute\path\to\SentinelAV
    .\scripts\lab\Reset-TestEnvironment.ps1
    .\scripts\lab\Test-GuestResponse.ps1

The last command verifies the current kit and guest boundaries before validating
the packaged response evidence, then records response-validation.json under the
local lab artifacts. An older package without response evidence fails this check.

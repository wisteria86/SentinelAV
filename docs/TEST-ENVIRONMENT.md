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
Activation details are saved to artifacts/lab/windows-sandbox/feature-status.json
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
There is no sample ingestion, malware downloading, arbitrary sample execution,
or automatic evidence-return channel. Use only the provided harmless checks.

References: [Microsoft installation](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install),
[configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file),
[disposable environment behavior](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview).

# Harmless Sandbox telemetry integration — 2026-11-04

**Result: failed; full telemetry readiness is not established.**

The integration test exposed real lifecycle and product-startup failures rather
than producing a demonstration pass. No malware was executed. The latest two
guest kits contained no sealed specimen inputs.

## Measured outcomes

- Windows Sandbox starts and connects automatically to the exact owned guest.
- The packaged harmless baseline passes inside the guest.
- Runtime guest identity, offline state and denied writes to the host input
  share pass the boundary checks. Clipboard behavior remains configuration-only.
- Microsoft Authenticode verification passes inside the guest.
- Sysmon installation exits **0**, its service is running, and the ETW collector
  is staged with SYSTEM ownership and administrator-only write permissions.
- The typed probe exits **73** with **RuntimeError: Background engine did not
  start**. It fails before the independent event probes complete, so working
  end-to-end Sysmon/ETW delivery and collector-loss detection are **not proven**.
- All owned guests were stopped and their disposal verified. Per-case staging
  copies were removed only after preserving manifests and receipts.

## Evidence

- [Initial setup failure](../logs/2026-11-04_21-19-38-660b2d43894a/report.md)
- [Successful installation, export transport failure](../logs/2026-11-04_21-42-44-4c9460ae8208/report.md)
- [Latest probe: background-engine failure](../logs/2026-11-04_21-49-47-03c514888e08/report.md)

The latest attempt retains `telemetry-setup.json`, `execution-*.json`,
`guest-error.json`, the input manifest and `disposal.json` under its `attempts`
folder. Product source/binary/model identities remain frozen; the updated host
adapter's source identity and probe-launcher identity are recorded separately.
The diagnostic launcher is preserved in the run folder. These are scoped
diagnostics, not a complete qualification run or an externally attested result.

## Corrections implemented

1. Explicitly connect after CLI Sandbox creation so the user logon bootstrap runs.
2. Stage specimen inputs only for cases that require them.
3. Install Sysmon through an owned process with captured stdout/stderr and an
   explicit exit code; its normal stderr banner is not a PowerShell exception.
4. Apply the collector's required restrictive permissions inside the guest.
5. Preserve bounded installation diagnostics before disposal.
6. Explicitly wait for the GUI-subsystem qualification executable to exit before
   reading its bounded result; preserve its actual exit code and reject missing
   exports.

## Next investigation

Capture the engine's startup exception and actual guest token elevation. The
per-user engine deliberately rejects administrator elevation; its safeguard must
remain intact. Validate a genuinely non-elevated launch or the supported service
path, then repeat the independent event and collector-loss probes in a new guest.
Live-malware trials remain gated on successful telemetry and monitoring proof.

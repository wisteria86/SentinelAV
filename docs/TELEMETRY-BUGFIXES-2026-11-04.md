# Telemetry startup fixes — 2026-11-04

## Implemented

- Added the missing Windows event-log dependency, pinned `pywin32==312`, to the
  requirements and rebuilt the application/installer. `win32evtlog.pyd` is
  confirmed in the frozen package.
- Added a guest-only launcher for the fixed per-user engine. An elevated lab
  process creates a restricted copy of its own token: administrative groups are
  deny-only, maximum privileges are removed, integrity is medium, and the account
  SID must remain unchanged. The launcher verifies the reduced token before
  creating the child. It refuses host execution and unrelated data directories.
- Only fresh guest engine/watch fixture directories receive the same user's
  required write access and medium-integrity labels. Host accounts, host policy,
  installed security protections and the protected application code are not
  changed.
- Preserved the engine's administrator-elevation refusal. Engine startup errors
  now return a failure code without a GUI exception dialog; failures after its
  non-elevated startup checks save a bounded diagnostic.
- Added guest launch metadata, probe-stage diagnostics and error export of known
  diagnostic files. Added independent probe witnesses with timestamps, record
  IDs and process identities; bounded summaries retain category/loss counters.

The restricted-token design follows Microsoft's
[restricted process documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens).
It reduces the test engine's privileges; it is not an additional malware
containment boundary or a substitute for the disposable guest.

## Verified

- **272 source unit tests passed**, including preservation of the elevated-engine
  refusal, host/scope rejection, startup failure receipts and lock release.
  Transcript: `artifacts/guest-engine-fix-tests.log`.
- A native Windows API check created and closed only a temporary restricted
  token, confirming same account, medium integrity and disabled administrator
  membership. That check launched no process and modified no parent token.
- The rebuilt executable passed **15 harmless packaged self-checks**.
  Local evidence: `F:/SentinelAV-Work/evaluations/restricted-engine-selftest-23513f4922b344568d36958d9479f4c6/self-test.json`.
- [Current-build preflight](../logs/2026-11-04_22-18-54-fb7fde3f8819/report.md)
  confirms current-source package attestation and the pinned collector manifest.

## Still unverified

The corrected engine has **not yet completed the fresh Sandbox integration
rerun**. The last actual guest trial remains a failure, documented in
[the integration record](TELEMETRY-PROBE-2026-11-04.md). Source tests and the
standalone token check do not prove successful child-process creation, IPC or
end-to-end Sysmon/ETW event collection inside Sandbox.

C: currently has approximately 9 GiB free, below the frozen 10 GiB Sandbox
reserve. Six installer downloads totaling about 1.3 GiB have been inventoried
and hashed for an optional verified move to F:. That move awaits the user's
choice; Downloads files have not been relocated. Heavy builds, caches and lab
material already use F:.

**What's next:** meet the system-drive reserve, rerun the harmless guest case,
and require actual engine mode attestation, independent event witnesses and
collector-loss detection before allowing live-malware trials.

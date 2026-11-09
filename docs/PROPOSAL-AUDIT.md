# Proposal implementation audit — 2026-11-08

Scope reviewed against both pages of `23L0553_IS_Proposal (1).pdf`.
This is an implementation and functional-validation audit. It does not establish
commercial antivirus effectiveness or replacement suitability for Malwarebytes.

| Proposal requirement | Connected implementation | Verification |
| --- | --- | --- |
| Windows desktop UI | PySide6 window with orange/cream dashboard, scanning, protection, quarantine, reports and settings | UI navigation, sizing, background workers, close/cancel checks |
| Selected file/folder scanning | UI picker → isolated inspection worker → SHA-256 index, EICAR recognition, optional reviewed YARA → SQLite results | Engine, worker, signature database, YARA and UI checks |
| Filesystem monitoring | Selected watchdog roots → bounded queue/debounce → shared scanner → persisted alerts | Real harmless file creation, rewriting, rename and exclusion checks |
| Windows security events | Existing Sysmon channel and optional WMI process-start events → identity-aware correlation | Cursor, event parsing, ancestry, missing-source and lifecycle tests; host Sysmon installation is optional |
| Process/behavior analysis | psutil snapshots and process events → creation-time identities, ancestry, explainable indicators and time-window scores | PID reuse, parent identity, behavioral sequences and UI checks |
| Ransomware warnings | File write/rename bursts and user-created canaries → independent indicators → warning/risk alert | Harmless canary alteration and multi-file burst integration |
| Network threat detection | Established connections → verified PID/creation-time attribution → configured IP/CIDR indicators and public-peer fanout | Indicator, fanout, PID reuse, inaccessible process and failed collector checks |
| Automatic quarantine | Explicit approved hash and folder scope → fresh independent detection → rate-limited worker → encrypted quarantine | Real harmless approved-hash automatic quarantine/restore UI workflow; no unvalidated broad automatic policy |
| Malware removal and recovery | Reviewed deletion of encrypted copies, no-overwrite restoration, exclusions/exact-file trust, interrupted-operation recovery | DPAPI round-trip, stale detection, tampering, hard-link refusal, overwrite refusal and recovery tests |
| Guarded process stopping | Individual PID/creation-time and executable revalidation, same-account and critical-process checks, reviewed process-tree plans | Controlled process-response and identity regression tests; arbitrary host processes are not killed by tests |
| Recurring scans | Scheduling UI → Windows Task Scheduler or app timer → shared scanner → history; opt-in sign-in startup | Schedule catch-up, task ownership, headless scan, error audit and UI tests; registration APIs mocked in UI tests |
| Event history and reports | SQLite history, settings, events and quarantine → report views → HTML/JSON/CSV exports | History concurrency/cache checks, escaped HTML, formula-neutralized CSV, coverage/recovery tables and exports |
| Continuous protection | Optional per-user background process survives GUI closure; opt-in startup resumes saved sources; separately deployable protected Windows service | Background process continues scanning after GUI exit, reconnects and stops explicitly; service deployment remains an administrative choice |
| Python/PySide6/psutil/watchdog/SQLite | Existing runtime dependencies retained, YARA optional with visible absence | Full functional suite and packaged self-test |
| Reliable everyday alternative to commercial antivirus | Effectiveness remains unqualified | Harmless integration tests cannot establish real-world detection/false-positive rates or commercial parity |

## Corrections in this pass

- Retain telemetry failure/loss status for the session and show degraded coverage
  on the dashboard, including after collector disposal or queue draining.
- Verify network process creation times after collecting connections; omit stale,
  exited and unidentifiable PIDs. Use verified ancestry for parent-name indicators.
- Separate behavioral alerts from confirmed malware counts and threat rows.
- Include detection evidence, scan omissions, engine warnings, analysis reviews
  and quarantine/recovery outcomes in HTML reports.
- Audit failed scheduled scans without advancing their due time. Flag incomplete
  and detected scheduled results at the appropriate event level.
- Reject linked scan roots and report unavailable/empty root selection as omitted
  coverage. Preserve the Full Scan tab and history label.
- Replace unused future-page scaffolding and inactive General settings switches
  with explicit implemented page builders and functional settings shortcuts.
- Route test fixtures and installer validation to F: and correct documented build
  output paths. Preserve module headers and the 250-line limit.
- Count workspace quota usage with per-entry metadata and directory checks,
  avoiding repeated parent traversal for each file. A read-only measurement of
  this 21,397,803,578-byte workspace completed in 3.563 seconds; timings depend
  on disk/cache state. Linked entries still cause rejection.

## Validation records

Current run evidence is under `logs/2026-11-08-proposal-audit/`.
The full suite passed 283 unit tests and 13 UI integration checks. A subsequent
focused run passed 17 workspace/change-journal tests, including two new quota
accounting checks (285 distinct unit tests verified overall). The structure
guard passed for 323 first-party code files, all at most 250 lines.
The restricted initial test run encountered Windows named-pipe and hard-link
permission failures. The suite is rerun with normal Windows access, without
weakening those application guards. Build and installer evidence is recorded
separately from unit/UI results.

- Executable and installer build passed; release hashes are in
  `artifact-hashes.json`.
- Packaged self-test passed Qt navigation, YARA/SHA-256 detection, isolated file
  and byte workers, SQLite, DPAPI, Ed25519 verification, quarantine/restore UI,
  overwrite refusal, response audit, HTML export, safe profiles, normalized
  content and bounded emulated Win32 dispatch. See `package.json`.
- Packaged background engine passed local RPC rejection, fixture detection,
  idempotent startup and explicit stop/shutdown. See `package-background.txt`.
- A uniquely registered installer fixture passed install/reinstall, preservation
  of definitions/publisher trust, installed self-test, uninstall registration
  removal and user-database retention. See `installer.txt`. This was a local
  isolated installation test, not a clean-VM or reboot compatibility evaluation.
- No real malware was executed, no host security configuration was weakened,
  and no empirical protection-rate claim was produced.

## Operational limits

- Scans cover readable supported files within configured limits. A clean result
  is not proof of absence of malware. There is no guaranteed pre-execution block.
- Behavioral scores indicate suspicion. Network polling cannot establish the
  direction or content of every connection, inspect encrypted traffic, or recover
  activity missed between observations. Configured destinations are user supplied.
- Sysmon/ETW availability and permissions are external prerequisites for those
  optional sources. Existing Windows protections remain enabled.
- Background mode lasts through GUI closure in the current user session.
  Sign-in startup is opt-in. Always-on service installation needs administrator
  deployment and an appropriate protected policy.
- Quarantine encryption is scoped to the Windows account. Same-account malware
  and administrators are outside its tamper-resistance guarantee. Recovery is
  limited to recorded quarantine material, not arbitrary ransomware decryption.
- Signing/hosting a public update service, representative malware/benign corpora,
  and controlled long-running/reboot qualification remain external work. Public
  trust/code signing and commercial effectiveness are not manufactured by code.

## Run

```powershell
.\start.ps1
.\test.ps1 -UI
.\build.ps1 -Installer
.\scripts\verify_installer.ps1
```

The source launcher uses the existing `.venv`. Built output is
`F:\SentinelAV-Work\builds\dist\SentinelAV\SentinelAV.exe` and the installer is
`F:\SentinelAV-Work\builds\release\SentinelAV-Setup-0.16.0.exe`.

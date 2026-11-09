# Proposal audit

Checked against both pages of `23L0553_IS_Proposal (1).pdf`, on 9 November 2026, for version 0.17.0. Every item below is connected in the application. Measured results are in the [evaluation report](EVALUATION-2026-11-09.md).

| Proposal item | Status | How it was checked |
| --- | --- | --- |
| Windows desktop interface | Done | UI checks, plus the real screens reviewed by eye |
| File scanning with signatures, hashes and rules | Done | Unit tests, real Quick scan, Sandbox runs on real samples |
| Generalized detection of unfamiliar threats | Done | Holdout: 64.0% of unseen archives flagged without hashes or family rules |
| Real-time detection in selected locations | Done | End-to-end check; real samples in the Sandbox detected 12 of 12 times |
| Windows security events (Sysmon) | Done, optional | Unit tests. Needs Sysmon already installed; not run live here |
| Behavior and process monitoring with explainable scores | Done | End-to-end process observation, unit tests |
| Ransomware warnings, canaries | Done | End-to-end: a changed canary warns; adding a file-change burst raises a scored alert |
| Network threat detection | Done, limited | Built-in heuristics and unit tests with simulated connections. Not run against live malicious traffic |
| Automatic quarantine | Done, with a known risk | 7 real samples automatically quarantined; 0 candidates among 3,201 legitimate files, but security text such as rule files can qualify |
| Malware removal, deletion and restoration | Done | 24 of 24 cycles on real samples; end-to-end checks |
| Stopping flagged processes with safeguards | Done | End-to-end on a harmless copy of `ping.exe`: three refusals, then a verified stop |
| Scheduled scans | Done | End-to-end for a Folder schedule, with unit tests. Windows task registration is mocked in UI checks |
| Reports and event history | Done | End-to-end HTML, JSON and CSV exports with verdicts and reasons |
| Python, PySide6, psutil, watchdog, SQLite, optional YARA | Done | Kept. Added `py7zr`, `rarfile`, `pyzipper`, and `oletools` as a runtime dependency |

## Where the proposal's goal is not met

The proposal aims to serve as an alternative to commercial antivirus such as Malwarebytes. **This is not established, and the evidence does not support the claim:**

- About a third of unseen malware archives went unflagged, and most flagged files reach only Suspicious.
- Files are checked after they are written. Blocking before execution would need a signed kernel driver.
- There is no public update service, signed releases or independent test results.
- The corpus is small and mostly old.

SentinelAV is a working detection, explanation and removal system for study and evaluation. Keep your regular antivirus enabled.

## Validation

On the final build:

| Check | Result |
| --- | --- |
| Unit tests | 354 pass |
| UI checks | All 13 pass (run on the frozen commit) |
| Harmless end-to-end cycle | 17 of 17 pass |
| Proposal end-to-end checks | 16 of 16 pass (run on the frozen commit) |
| Installer: install, reinstall, 15-check installed self-test, uninstall | Pass |
| Structure and Zoo hardcoding guards | Pass |

The installer check uses an isolated fixture on the work drive. It was not run on a clean machine or across a reboot.

## Run

```powershell
.\start.ps1
.\test.ps1 -UI
.\build.ps1 -Installer
.\scripts\verify_installer.ps1
```

The packaged app is at `F:\SentinelAV-Work\builds\dist\SentinelAV\SentinelAV.exe`, and the installer is at `F:\SentinelAV-Work\builds\release\SentinelAV-Setup-0.17.0.exe`.

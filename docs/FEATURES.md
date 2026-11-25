# SentinelAV

Historical feature notes follow. Use [the current proposal audit](PROPOSAL-AUDIT.md)
for verified capability and deployment status; older phase limits below describe
the implementation at the time of those entries.

Windows desktop prototype implementing scanning, monitoring, behavioral analysis, reviewed response, scheduling, reports, and Windows packaging (Phases 1–6). Inspired by the supplied orange/cream desktop reference. Current prototype version: 0.13.0.

## Optional independent background engine

On Real-Time Protection, enable **Keep monitoring when this window closes** before starting protection. This runs monitoring in a separate non-elevated process under your Windows account and reconnects when the UI reopens. Explicit Stop ends monitoring. It stops at sign-out/reboot; it is not a Windows service or tamper-resistant protection. Default window-owned monitoring still stops on close. See [BACKGROUND-ENGINE.md](BACKGROUND-ENGINE.md) for IPC boundaries, health reporting, limitations, and harmless verification.

## Definition maintenance

Settings → Definitions supports incremental recent CSV imports, reviewed
corrections, signed-package verification, full ZIP imports, rollback, and import
age warnings. `python -m tools.feeds.download_hashes --apply` downloads and merges recent additions
using a transient key. No recurring downloader or update publisher is configured;
the default publisher trust store is empty and signed packages are rejected.
See [DEFINITION-UPDATES.md](DEFINITION-UPDATES.md) for operation formats, provenance,
activation guarantees, anti-replay behavior, and deployment limitations.

## Reviewed YARA source subset

Settings → YARA Rules reports compilation status and pinned provenance. The
managed set includes 10 ESET research detections, two private helpers, and the
existing harmless demo. Source/license notices and catalog hashes are preserved;
includes and compile warnings are rejected. Matches carry source/license/review
details into JSON and live events. See [YARA-REVIEW.md](YARA-REVIEW.md) for exact
scope and exclusions. Effectiveness and false-positive evaluation remain deferred.

## Defense layers

Settings → Defense groups layer status, bounded memory/file inspection, script
AMSI consumer options, process-event preferences, and default-off approved-hash
quarantine policy. Application scanning/response verification now uses limited
worker processes, with in-memory ZIP inspection and bounded PE metadata.
Protected Windows-service code and an administrator deployment script are staged
but not installed. The native x64 AMSI provider and byte broker are implemented for local harness
testing but are not signed, registered, or active. System-wide pre-execution
enforcement remains unimplemented. See [AMSI-PROVIDER.md](AMSI-PROVIDER.md). See
[DEFENSE-IMPLEMENTATION.md](DEFENSE-IMPLEMENTATION.md) for the exact ten-layer
matrix, Windows prerequisites, privacy/resource limits, and deployment gates.

## Run

From the project root (the folder containing `app.py`), on Python 3.12 or newer:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements/requirements.txt
.venv/Scripts/python.exe app.py
```

If pip is absent in the virtual environment, use `python -m pip --python .venv/Scripts/python.exe install -r requirements/requirements.txt`.
Once dependencies are installed, `./start.ps1` launches the app.

## Implemented

- PySide6 navigation, dashboard, scan controls, reports, and persistent settings.
- Cancellable QThread worker keeps file reading and detection off the GUI thread. Progress is indeterminate because files are discovered during traversal.
- File/folder selection and quick scanning of Downloads and the current user's temporary directory.
- Streaming SHA-256 hashing, built-in EICAR test recognition, and local YARA rules with timeouts. Files are held in memory for YARA up to the configured size cap (default 100 MB).
- SQLite scan history, full JSON report export, scan error reporting, file-size cap, and path exclusions.
- No elevated permissions required; inaccessible files are reported. Folder symlinks and Windows junctions are not traversed.

## Safe demonstration

Create an ordinary text file containing `SENTINELAV_DEMO_THREAT_7C23A`, select it with **Select Files**, and inspect the YARA detection. This marker is harmless and does not require real malware. Do not use live malware for testing. The demo rule proves rule execution; it does not provide general malware coverage.

`resources/signatures.json` maps lowercase SHA-256 digests to threat names and acts as a small local overlay. A full MalwareBazaar CSV ZIP can be streamed into an indexed SQLite database with `python -m tools.feeds.import_hash_archive <archive> --activate`. New scanners read the version selected by `resources/signature-data/active.json`; existing scans keep their snapshot. No samples are extracted or downloaded. Settings → Scanning displays the imported feed count/date, and live monitoring reports its actual loaded hash count. See `HASH-IMPORT.md` for validation, omissions, rollback, and scope. Place reviewed `.yar` files in `resources/rules/`; they are compiled at the start of each scan. Invalid rules fail the scan visibly. There is no automatic remote signature updater. YARA is optional at runtime and its absence appears in scan warnings.

## Scope and limits

The app does not register as Windows antivirus or run as a Windows service. Default monitoring stops when the app closes; optional background-engine monitoring continues within the current Windows session. Opt-in Windows tasks can run separate scheduled scans while the user is logged in. Scanning and monitoring are read-only. Explicitly confirmed response actions can quarantine, restore, delete an encrypted quarantine copy, or terminate a matching process. The optional Create Canary action writes a new, uniquely named harmless text file only in the folder you choose.

Archives are inspected as raw files, not unpacked. Locked, oversized, excluded, or changed-during-read files can limit coverage. A no-detection result is not proof that a system is clean. Keep Windows' existing protection enabled.

History and settings are stored in `%LOCALAPPDATA%/SentinelAV/sentinelav.db`. Reports include local file paths. Engine, SQLite storage, and GUI are separate modules; a future monitoring service should communicate with the GUI through authenticated IPC rather than depend on the GUI process.

## Verification

### Presumed-benign corpus evaluation

Run `.venv/Scripts/python.exe -m tools.evaluation.evaluate_benign` for two read-only passes over
up to 200 eligible top-level Windows System32 files (20 MiB per-file cap).
Use repeated `--root <folder>` options for other installed software or ordinary
documents. Selection is deterministic and alphabetical, not a representative
random sample; nested folders are not traversed. `--limit`, `--repeats`, and
`--max-mb` control scope. Reports are written separately under `evaluations/`
as JSON and standalone orange/cream HTML, without altering protection history.

Reports include a SHA-256 corpus inventory, rule/overlay hashes, feed version,
scan errors/skips/warnings, repeated timings, CPU time, sampled process RSS,
and before/after corpus checks. No files are executed, uploaded, quarantined,
or modified. Input ground truth is presumed rather than independently verified:
detections require review and are never automatically counted as confirmed
false positives. Cached repeated reads and sampled RSS are explicitly limited
measurements, not production performance or malware protection guarantees.

```powershell
.venv/Scripts/python.exe -m unittest -v
```

Tests cover hash and optional YARA detection, duplicate input paths, exclusions, cancellation, oversized and unavailable files, and SQLite persistence. They use temporary harmless fixtures.

## Phase 3: real-time protection

1. Open **Real-Time Protection**, add existing folders, and select sources. No monitoring starts automatically on launch.
2. **Start Protection** enables watchdog events for created, modified, or renamed files. Events are debounced for 0.7 seconds and inspected serially in a worker thread using the saved size cap and exclusions. SentinelAV's own database directory is automatically excluded to prevent detections from matching text in its event logs. Existing folder contents are not scanned automatically: use an on-demand scan for a baseline.
3. **Track new processes** samples psutil every three seconds. The first sample establishes a baseline; later process arrivals record PID, parent PID, name, and accessible executable path and enqueue that executable for signature inspection. Protected/inaccessible paths are counted. Short-lived processes between samples may be missed. Process creation alone is informational, not a malware verdict.
4. **Read existing Sysmon events** optionally polls `Microsoft-Windows-Sysmon/Operational` every 15 seconds, beginning after its latest record. Sysmon must already be installed and logging; channel permissions must permit reading. The app does not install Sysmon or elevate itself. Missing/inaccessible channels produce a visible warning and disable that source for the session; other sources continue. Restart monitoring to retry. Sysmon events are telemetry, not automatic threat classifications.
5. A signature/rule detection appears in the live list, dashboard count, **Reports → Threats / Protection Events**, and a tray notification when available. Windows may suppress notifications; the in-app alert remains. Repeated detections of the same path/content are suppressed for 60 seconds. Files remain unchanged.
6. **Stop Protection** shuts down monitoring. Closing the app requests cancellation and waits asynchronously for window-owned workers before exiting. With background mode enabled, closing disconnects the UI and leaves monitoring running; reopening reconnects. Saved folders/options are restored for the next manual start.

The queue holds up to 1,024 distinct pending files. Overflows and oversized/unreadable files are reported as warnings; use an on-demand scan to cover omissions. This is user-space monitoring, not kernel interception: it cannot prevent a file from running before inspection, guarantee visibility into all processes, or provide tamper resistance. Events are retained locally up to 5,000 records; JSON export includes the retained events and scan history. Telemetry can contain local paths and Windows event details. Scan-limit and exclusion changes take effect when monitoring restarts.

Phase 3 verification (harmless fixtures only):

```powershell
.venv/Scripts/python.exe -m unittest -v
.venv/Scripts/python.exe -m tests.ui.verify_ui
.venv/Scripts/python.exe -m tests.ui.verify_protection_ui
```

The monitoring tests exercise an actual filesystem observer, modification/rename detection, exclusions, shutdown, queue backpressure, process baseline/PID reuse, and mocked Sysmon cursor handling. The protection UI check verifies actual background detection, persistence, reports, stop/restart, and closing while monitoring. A live Sysmon channel is environment-dependent and is not required for these tests.

## Phase 4: behavioral risk analysis

**Real-Time Protection** now includes **Behavior and ransomware warnings** (enabled by default) and optional **Network telemetry**. Start protection to activate selected sources. Both respect saved exclusions and use bounded in-memory state. These rules are experimental heuristics, not a trained malware classifier or a commercial reputation feed.

Each entity accumulates distinct indicators over 60 seconds. A repeated indicator refreshes its timestamp rather than adding more weight. Scores are capped at 100. A score of 30 or more produces a warning. A risk alert requires at least 70 points **and two distinct indicators**. Notifications are throttled per entity/severity for 60 seconds. Full event details and exports retain the score, reasons, weights, and entity. Double-click a live event or a Protection Events row to inspect it.

| Indicator | Points | Scope |
| --- | --- | --- |
| 30 distinct file paths changed in 10 seconds | 30 | Watched folder |
| 15 distinct rename destinations in 10 seconds | 40 | Watched folder |
| Tracked canary changed, missing, redirected, or unreadable | 70 | Watched folder |
| Executable under a Temp, Tmp, or Downloads path component | 25 | Process identity (PID + creation time) |
| Office application launches a command interpreter | 35 | Process identity |
| PowerShell uses an encoded-command flag | 30 | Process identity |
| Established connection matches a user-configured IP/CIDR | 70 | Process identity |
| At least 20 public remote IPs observed in 60 seconds | 45 | Process identity |

Folder and process scores are kept separate. Watchdog does not identify the writing process, so a folder risk is never attributed to a PID. Signature detections still raise their existing direct alerts independently of heuristic scores. Installers, sync clients, browsers, and administration scripts may trigger these heuristics; review the evidence before deciding whether activity is malicious.

### Canary setup

In **Settings → Advanced**, choose **Create Canary…**, then select a folder. This creates a new ordinary text file without overwriting anything, records its expected SHA-256, and adds the folder to the watch list. Start/restart protection with behavior warnings enabled. Canaries are checked every two seconds while their folders are watched and not excluded. Up to 64 canaries can be tracked. **Stop Tracking Selected** removes tracking only; the file stays on disk. A single changed canary produces a warning; a concurrent write or rename burst can escalate it to a risk alert. Canary files are detection aids, not backups or ransomware prevention.

### Network setup

Enable **Network telemetry** to sample accessible established socket endpoints every five seconds. Process metadata is sampled to associate connections with a PID and creation time. In **Settings → Advanced**, optionally enter reviewed IP addresses or CIDR ranges, one per line, and save settings. No IP feed is bundled, no DNS requests or packet capture are performed, and no connections are blocked. A configured IP match alone is a warning; executable-context or another independent indicator can escalate it.

Normal Windows execution was verified to enumerate socket records. The restricted test sandbox blocks the native Windows socket API; that failure path is tested to disable network telemetry visibly while folder monitoring continues. Access and visibility vary by account permissions; short-lived sockets/processes may be missed. Stop/start protection to retry a disabled source or apply configuration changes.

Run `.venv/Scripts/python.exe -m tests.ui.verify_behavior_ui` for a safe end-to-end simulation confined to a fresh temporary directory. It creates a canary through the UI, edits it, creates ordinary text files to trigger a burst, verifies warning-to-alert escalation and saved evidence, then stops tracking. The tests never encrypt user files, execute encoded commands, contact indicator IPs, or use real malware.

## Phase 5: reviewed response

Stop monitoring and finish active scans, then open **Quarantine → Detected Files**. This list contains existing files from signature/hash detections; folder behavior warnings alone are not eligible for quarantine or termination. No response action runs automatically.

- **Quarantine Selected** re-scans the file using saved exclusions and trusted hashes, verifies the original detection hash, opens an exclusive Windows handle, encrypts content using current-user Windows DPAPI, verifies the encrypted copy, and removes the original using that same handle. The encrypted `.sav` object is stored in `%LOCALAPPDATA%/SentinelAV/quarantine` with an ACL granting the current user and SYSTEM access. Size limits apply. Locked files, hard links, linked paths, Windows directories, installed application directories, SentinelAV files, and the current Python installation are refused.
- **Isolated Files → Restore…** decrypts and verifies content, then creates a file at the destination you explicitly select. It never overwrites an existing file. The encrypted object is removed only after a successful write and hash check. Restore does not preserve the original ACL, timestamps, alternate data streams, or other filesystem metadata. Quarantine supports ordinary single-link files only, not a full filesystem backup.
- **Restore and Trust…** additionally trusts the restored content's exact SHA-256 for future signature scans. **Trust Exact File** adds the same exception without moving a file. Changed bytes have a different digest and are detected normally. Behavior analysis is unaffected. Remove trust under **Settings → Trusted Files**. No exception is inferred from a filename or a whole directory.
- **Exclude File Path** adds an explicit path exception for future scans and monitoring. Unlike exact-hash trust, this also excludes changed content at that path. Manage path exclusions under **Settings → Exclusions**. Restart monitoring after policy changes.
- **Permanently Delete** removes only the encrypted quarantine object after confirmation, retaining its metadata/action history. This is ordinary filesystem deletion, not guaranteed secure erasure from SSDs, backups, or forensic recovery.
- **Terminate Matching Process…** requires selecting a process whose executable path matches a signature-detected file and confirming the action. The backend performs a fresh scan, verifies PID/creation time and executable identity, checks current-user ownership and Windows critical-process status, and refuses system/self/ancestor/protected paths. Behavior scores alone never authorize termination. The Windows termination API can lose unsaved work. Tests mock termination and do not kill user processes; this does not prove all Windows process-protection combinations behave identically.

All response actions, trust/exclusion changes, and worker failures are recorded under **Reports → Protection Events** and included in exports. Response file operations run on a separate worker, and the app waits for them before closing. Scans and monitoring are blocked while a response operation is active.

Quarantine uses journal states **Preparing**, **Quarantined**, **Restore pending**, **Restored**, **Delete pending**, and **Deleted**. **Recover Interrupted Action** can verify and finalize an interrupted operation. If an original still exists after an incomplete quarantine, it is preserved and the encrypted backup remains for review; restore to another location or explicitly delete that encrypted copy. An incomplete restored file is never overwritten automatically. Keep the database and encrypted objects together. DPAPI restoration requires the original Windows user profile and its keys; this prototype is not resistant to tampering by that user, administrators, or malware already running as that user.

Verification:

```powershell
.venv/Scripts/python.exe -m unittest -v
.venv/Scripts/python.exe -m tests.ui.verify_response_ui
```

The response tests use only fresh temporary harmless marker files. They cover real Windows DPAPI encryption, quarantine/restore/deletion, no-overwrite and tamper rejection, hard-link refusal, stale detections, exact-hash trust, interrupted-state recovery, and mocked process-termination guards. The UI simulation verifies scan → quarantine → restore/trust → rescan → remove trust → quarantine/delete, including persisted audit records. Windows sandbox policies can block hard-link creation; run those tests in a normal user shell when needed. No real malware or live process termination is used in verification.

## Phase 6: scheduling, reports, and Windows packaging

Under **Settings → Scheduling**, opt in to Windows sign-in startup, resuming saved protection sources on app launch, and a daily **Quick** or **Folder** scan. These settings have their own **Apply Startup and Schedule** button. Startup uses the current user's Run registry value. Applying a daily schedule attempts to create `SentinelAV Daily Scan` in Windows Task Scheduler using the current user's interactive token and least privilege; no password is stored and no administrator access is requested. If Windows registration fails, the UI states that only the app timer is available.

Schedules use **Asia/Karachi** time and display their next run with an explicit offset. The app checks every 30 seconds while open. A closed-app task invokes `--scheduled-scan` with the same user data directory; it requires the user to be logged in, will not wake the computer, and is limited to four hours. Multiple instances sharing a data directory are prevented by a Qt lock file. If the GUI is open, its timer handles due scans instead. A missed run catches up once, then advances to the next daily time. Busy scans/response operations defer the GUI timer. Starting a scheduled GUI scan advances its next run even if that scan is later cancelled. Headless scans retain results and counts in history; they do not quarantine or automatically respond to findings.

The dashboard includes last-scan omissions and quarantine counts. **Reports → Export Report** provides escaped, standalone HTML for review, JSON with full evidence/quarantine metadata, and CSV scan history with spreadsheet formula prefixes neutralized. Reports include local paths and may include process/event details. Export only to destinations you choose.

History/event reads are cached and invalidated on local writes or SQLite data-version changes from background workers. `benchmark.py` measures harmless small-file scan throughput and idle folder-monitor CPU time, writing `artifacts/release/benchmark.json`. These are local measurements, not broad performance or detection-quality guarantees. EICAR detector coverage is tested with an in-memory standard test signature to avoid placing a test-virus file on the host; ordinary YARA marker fixtures exercise actual disk I/O.

### Build and install

```powershell
.venv/Scripts/python.exe -m pip install -r requirements/requirements-build.txt
./build.ps1 -Installer
```

The build uses PyInstaller and a portable Inno Setup compiler at `tools/vendor/inno/ISCC.exe`. Obtain the compiler from the [official Inno Setup downloads](https://jrsoftware.org/isdl.php), verify its digital signature, and extract it using its documented [portable installer mode](https://jrsoftware.org/ishelp/topic_technotes.htm). Build tools are local dependencies, not runtime requirements.

- `artifacts/dist/SentinelAV/SentinelAV.exe`: standalone Windows executable; keep the entire sibling `_internal` folder with it.
- `artifacts/release/SentinelAV-Setup-0.13.0.exe`: per-user installer, defaulting to `%LOCALAPPDATA%/Programs/SentinelAV`. Python is bundled. Optional desktop shortcut; Start menu shortcut and uninstaller included. Startup/scheduling are never enabled by installation.
- Uninstall preserves `%LOCALAPPDATA%/SentinelAV`, including history, settings, and encrypted quarantine. It removes startup/tasks only when their executable points to that installed copy. Reinstall under the original Windows user to restore quarantined data.

For an isolated packaged smoke check, run `SentinelAV.exe --self-test --data-dir C:\path\to\isolated-test-data`. The directory must be new and unused; existing directories and linked components are refused before any test files or database changes. It writes only harmless test fixtures, a smoke result, and a local HTML report under that directory. It checks packaged Qt navigation, detection, SQLite, Windows DPAPI, and exports. Do not pass your normal data directory to a smoke test.

The executable and installer are **unsigned**. Keep Windows Security enabled. Detection coverage depends on the installed local hash feed and rules; source-tree imports do not update existing installers. The prototype has limited user-space visibility, no tamper-resistant service, no automatic updater, and no Security Center integration. Code signing, clean-VM compatibility testing, broader detection evaluation, and independent security review remain before a public/commercial release.

## Hardening review (0.6.1)

See `HARDENING.md` for the scoped review and regression evidence. Startup and scheduled-task changes verify executable, arguments, and task data-directory ownership before replacing or deleting registrations. Restore and interrupted-restore verification hold an exclusive destination handle through encrypted-backup cleanup. Files that change during scanning are reported as omissions. These controls reduce specific data-loss and cross-copy interference risks; they do not add tamper resistance or expand the bundled malware detection content.

## Phase 7 milestone: setup checks and safe local simulations

The original safe-lab milestone adds Overview, Test Queue, Live Activity and Results. The current source also has a separately confirmed Offline Guest Job path and real source-controller prepare/start actions. No guest readiness is assumed from a static badge. These newer paths remain unexecuted and unvalidated.

Choose allowlisted profiles under Test Queue, then **Run Selected Safe Tests**:

- Demo signature: actual scanner runs on a generated harmless marker text file.
- Benign documents: actual scanner checks 20 generated ordinary text files.
- Canary and file burst: edits only newly generated fixture files and feeds labelled synthetic file events to the existing scorer.
- Network indicator rules: feeds synthetic process/connection records to the scorer; it launches no process and makes no network connections.

The runner has no arbitrary command, sample upload, or executable selection feature. Every run uses a fresh temporary child directory inside the application's lab-workspaces directory, refuses linked workspace components, checks cancellation/time limits, and verifies fixture removal. Runs are retained separately from scan history (up to 200); simulated alerts do not become real protection alerts. Results expose whether telemetry was actual fixture scanning or synthetic input and can be exported as JSON. Stop and closing the app request cleanup without blocking the UI. A cleanup failure is visible and blocks another run in that session.

Run `.venv/Scripts/python.exe -m unittest tests.unit.test_lab -v` and `.venv/Scripts/python.exe -m tests.ui.verify_lab_ui` to verify the safe profiles, absence of subprocess/network calls in the simulation runner, evidence separation, cleanup, export, sizing, and cancellation. Read-only readiness checks use a bounded Windows PowerShell subprocess independently of simulation execution. Do not place real malware in the simulation workspace; the runner accepts only its built-in profiles.

A disposable offline Windows guest and registered isolation/reset controller are prerequisites for runtime jobs. The original safe-profile runner does not acquire or execute malware; the separately confirmed guest-job path is described in the first-iteration contract.

Defense-layer scope and native deployment prerequisites: see [DEFENSE-IMPLEMENTATION.md](DEFENSE-IMPLEMENTATION.md). Service deployment is staged, not active.

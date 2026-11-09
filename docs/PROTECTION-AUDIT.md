# Protection path audit — 2026-11-03

## Finding and repair

A reproducible runtime defect interrupted continuous protection: terminating the
owned persistent inspection worker between requests caused the next scan to raise
`RuntimeError: Inspection worker is not running`. A timeout also closes that
worker, leaving subsequent requests unable to proceed. Monitor.run did not recover
it, so the monitor could exit instead of inspecting later files.

Persistent scanning now checks worker liveness before a new request, closes stale
handles and initializes a replacement with the existing job limits. It does not
silently retry the file that crashed or timed out: that result remains incomplete,
and the omitted file requires a rescan. Recovery is logged as a warning. If worker
initialization fails, monitoring still fails visibly rather than claiming recovery.

Incomplete file inspections now propagate an inspection-error status to the GUI.
The dashboard shows `DEGRADED` and “Monitoring needs attention”; a later complete
inspection restores Active. Previous omissions remain in protection events and
are not retroactively covered by that status change. An oversized file remains a
coverage omission. Cancellation during shutdown does not constitute a new failure.

## Verification

`test.ps1 -UI` passed 123 unit tests and all ten Qt integration scripts. These
exercise application code directly with harmless fixtures, not manual desktop
interaction or live malware execution.

| Path | Evidence and practical limit |
| --- | --- |
| Changed/renamed file → alert | Real watchdog, isolated scanner, Qt delivery and SQLite history checks pass; exclusion is respected. |
| GUI closed → continued monitoring | Independent per-user background process detects a fixture; reconnect and exactly-once persistence pass. It stops at sign-out and is not tamper resistant. |
| Approved hash → automatic quarantine | Real temporary hash definition, explicit opt-in scope, fresh verification and encrypted quarantine pass. This is not default automatic response to unknown malware. |
| Detection → manual quarantine → restore | DPAPI round trip, content equality, occupied-target refusal, stale finding refusal, audit records and restored-file rescan pass. |
| Worker lost → later detection | Newly added real-process regression kills only its own worker, then verifies replacement and detection; closed-worker state also recovers. |
| Incomplete coverage → visible status | Unit fault injection and Qt status injection verify warnings and degraded state, followed by real monitoring status recovery. |

A fresh read-only System32 evaluation selected 500 files: 500 scanned, zero
signature detections, zero errors/skips, 18.4954 seconds for one run, sampled peak
RSS 48.67 MiB. Active database: 1,164,912 hashes. Evidence:
`artifacts/evaluations/benign-20261103T104028Z-90337fbe/report.json` and `.html`.
This is a local operational/performance check on presumed-benign files, not an
independently labelled false-positive study. Structural review signals are
separate from signature detections. Timing includes the new feature analysis;
it is not directly comparable to older runs under different cache/load conditions.

## What remains unproven or unavailable

The historical guest-only validation on 2026-11-02 missed both unused Zeus-family
specimens (`zeusbanking.bin` and `gameoveralt.bin`) by hash and YARA. Those misses
remain preserved in `artifacts/lab/windows-sandbox/zeus-validation-result.json`.
They were not rerun or added to the hash database during this audit. Structural
review and the offline anomaly tooling have not established improved malware
detection on those specimens or on a representative unseen corpus.

Filesystem monitoring is detection after a change, not guaranteed prevention
before execution. Rapid execution or encryption may precede any response. The
default application does not enforce system-wide launch decisions. Unknown-file
blocking, automatic containment of arbitrary suspicious processes, protected host
service deployment, broad unpacking, tamper resistance and demonstrated unseen
malware coverage remain gaps. Keep Windows' existing protection enabled.

These fixes are in source; the desktop source launcher uses them on the next
launch. The existing installer and frozen lab bundles were not rebuilt here.

Next priority: independently labelled evaluation of unfamiliar files with a frozen
holdout, explicit false positives and omissions, before promoting review scores
to detection or expanding automatic response. Workflow success is not efficacy.

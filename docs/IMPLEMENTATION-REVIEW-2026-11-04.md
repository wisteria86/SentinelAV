# Implementation review and next security subsystem

This review inspected the cleanup executor, recovery journal, protected broker,
service history and the existing implementation ledger. It is not an independent
malware efficacy assessment or an exhaustive source audit.

## Confirmed defects fixed in 0.14.1

1. Cleanup execution and reconciliation had no cross-process serialization.
   Concurrent helpers could both read a plan as Planned, or recovery could mark
   another live helper's operation as interrupted. Execution and recovery now
   acquire the same OS-backed lock for their journal before reading plan state.
   Protected broker locks are created with administrative ownership and verified
   ACLs. Crashed processes release the lock through the OS; lock files persist
   and are never deleted as a stale-lock shortcut.
2. Interrupted receipts omitted actions not yet journalled, and left Pending
   actions ambiguous. Recovery now records these actions as Skipped, preserves
   finished results, checks the observed postcondition for Applying actions and
   never replays a side effect. Every recovered receipt requires a fresh review;
   it cannot claim incident removal.
3. Recovery inspected only the most recent 500 local or 64 protected operations.
   It now enumerates all interrupted operations separately from UI history
   pagination. Enumeration finishes before recovery changes stored records.

These locks serialize SentinelAV operations sharing one journal. They do not
lock Windows configuration against legitimate installers or coordinate different
journals. Existing immediate state checks and postcondition verification remain
necessary. Scan/planning work remains concurrent; only mutation and recovery
must serialize. Recovery currently scans encrypted operation history; a future
indexed migration can optimize large histories without omitting pending work.

## Remaining implementation priorities

| Priority | Gap | Required work |
| --- | --- | --- |
| 1 | Positive cleanup and deployment validation | Verify reviewed repairs, cancellation, interrupted protected actions, repair/upgrade/uninstall and reboot recurrence in a suitable disposable Windows environment. Existing native guest evidence primarily covers negative controls. |
| 2 | Full incident cleanup | Coordinate protected persistence response with per-user file quarantine and supported recovery. The machine broker currently disables persistence and reports remaining payloads. |
| 3 | Independent unknown-threat detection | Complete validated Win32/Win64/.NET models, temporal/family-disjoint evaluation and evidence-fusion gates. The existing .NET pilot failed its release gate and remains inactive. |
| 4 | Telemetry and attribution | Expand authorized telemetry, event-loss accounting, broker-mediated attribution and per-application grouping. Do not infer writers from timing alone. |
| 5 | Extraction and emulation | Rescan extracted members through the complete shared pipeline, broaden bounded format coverage and validate modeled Windows semantics. |
| 6 | Consumer deployment and evidence | Complete installation without terminal work, protected recovery and update lifecycle checks. Obtain an operational Defender baseline for any comparison. |

The base product and Defender superiority objective remain unfinished. No test
count, new subsystem or version number is treated as evidence that malware
protection has reached a particular numerical rating.

## Focused verification

`tests/unit/test_remediation_transactions.py` uses a real child process to hold
the lock, checks rejection of a competing owner, crashes the child without
cleanup, and verifies subsequent acquisition. Additional cases cover exception
release, rejection of recovery while an operation is live, complete interrupted
receipts with no replay, and recovery beyond the UI history limit. These tests
use generated temporary files and do not modify host persistence or services.

Source verification: 211 unit tests passed. The real DPAPI/scanner/exclusive-file
recovery integration passed with its control file unchanged. The three affected
desktop checks (response, App Changes, signed analysis data) passed. Packaged and
protected-guest evidence is recorded separately on the managed F: drive.

The final frozen 0.14.1 self-test passed. In a fresh offline Sandbox, the packaged
broker passed its harmless negative controls. An independent Windows process
then held the protected execution lock; the broker returned the expected busy
failure before requesting any repair. The guest was subsequently discarded.
This checks protected deployment/serialization, not positive malware cleanup,
interactive UAC approval or reboot recurrence.

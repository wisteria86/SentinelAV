# SentinelAV 0.6.1 hardening review

This review covers source-level release safety around test execution, Windows persistence, quarantine restoration, and file inspection. It is not an independent security certification, malware-detection evaluation, or clean-VM compatibility audit.

## Findings corrected

| Area | Previous behavior | Corrected behavior |
| --- | --- | --- |
| Self-test isolation | Supplying an existing directory could overwrite a same-named fixture and append test records to an existing database. | Self-test reserves a brand-new directory atomically before creating Qt state or fixtures. Existing directories, files, symlinks, and junction components are refused. |
| Windows startup ownership | Enabling or disabling startup could replace or delete the same registry value belonging to another SentinelAV copy. | The current command must match this copy's executable and arguments. Foreign or unexpected registry values are preserved and an explicit error is returned. |
| Windows task ownership | A globally named task could be overwritten or deleted by another copy/data directory. | Existing task XML is inspected. Changes require exactly one matching executable action and matching arguments/data directory. Uninspectable existing tasks are preserved. Task-name discovery uses CSV rather than localized error messages. |
| Restore verification | The destination file was closed before verification and encrypted-backup removal, permitting concurrent modification during that window. | Restore uses an exclusive Windows create-new handle, verifies the same handle, and holds it through backup cleanup. Interrupted restore recovery also verifies under an exclusive handle. Existing destinations are never overwritten. |
| Changed files during inspection | A file could change during streaming without being reported as incomplete. | Descriptor identity, size, and timestamps are checked before and after reading and against the current path. Inconsistent files are recorded as omissions and require another scan. Windows descriptor/path ctime differences are handled without rejecting stable rewritten files. |

## Regression verification

- 38 unit/integration tests, including exact-hash trust, stale detections, tamper refusal, hard links, exclusive restore behavior, changed-file omission, fresh self-test directories, and foreign Windows-registration preservation.
- Five UI checks: navigation/scanning; live protection; behavioral/canary warnings; quarantine/restore/trust/deletion; and scheduling/export preferences.
- Native Windows Task Scheduler test: create a uniquely named temporary task, query ownership, reject replacement/deletion from another data directory, and delete the owned task. No real startup or daily schedule is enabled by verification.
- Packaged release checks are recorded in `artifacts/release/validation.json`, with executable and installer checksums in `artifacts/release/SHA256SUMS.txt`.

All destructive test operations are confined to newly created harmless temporary fixtures. Process-termination tests use mocks and do not kill user processes.

## Remaining material limits

- Bundled threat coverage remains an empty hash feed plus the harmless demo rule and EICAR test recognition. Heuristics are experimental; no sensitivity/false-positive benchmark against a representative malware/benign corpus has been performed.
- No kernel interception, protected Windows service, tamper-resistant storage, or Security Center registration. A process already running as the same user or an administrator is outside the protection boundary.
- No automatic signature/rule updater or authenticated update channel. The executable and installer remain unsigned.
- File inspection checks improve snapshot consistency but cannot stop execution or changes after an inspection. Archives are not unpacked; protected files and processes can be inaccessible.
- Native validation was performed on this Windows machine, not across clean Windows VMs, other accounts, all privilege combinations, storage types, or recovery scenarios.
- User data is local and retained after uninstall. DPAPI recovery depends on the original user's Windows profile and keys. Ordinary deletion does not guarantee forensic erasure.

Keep existing Windows protection enabled. These corrections support a safer demonstration prototype; they do not establish commercial-antivirus reliability.

# Independent protection and App Changes implementation

## Current integrated implementation

The desktop has an App Changes page in the orange/cream design. Refresh captures
Run/RunOnce, Startup files, non-Microsoft tasks, service configuration, and
explicitly selected application setting files. Continuous tracking is optional
and applies when protection restarts. Existing entries are labelled pre-existing;
an initial inventory does not invent an earlier baseline or identify a writer.

The private SQLite journal encrypts state and operations with account-bound
Windows DPAPI and restricts its directory ACL. It is separate from existing
history/quarantine tables. State, process identities and versioned changes have
integrity fingerprints. Sysmon writer attribution requires a matching process
creation identity, exact registry target and matching observed value; inventory
timing alone never becomes verified attribution. Tasks/services remain
unattributed unless trustworthy writer telemetry exists.

Users can select changes, review a stored two-minute cleanup/restoration plan,
and explicitly apply it. Cleanup requires fresh detections on the exact
referenced file, rather than detections on unrelated descendants of a directory.
Persistence is disabled before related process/file response. Existing Windows,
critical-process, same-account, file identity and quarantine safeguards apply.
Every action is journalled before applying, conflicts are skipped, and the
resulting state is checked. Interrupted operations reconcile without blindly
replaying writes. Restoration scans recorded file bytes again at execution and
refuses currently detected content. Missing original state cannot be restored.
Task credential requirements and protected-resource permissions can prevent an
operation; no elevation or authorization is silently invented.

Receipts and unresolved items are shown locally. Exported App Change summaries
omit all raw before/after content, command lines, file paths and exception text.
There is no generic registry cleaner or automatic permanent deletion.

The detection pipeline now includes a versioned AnalysisResult envelope,
bounded PE directory descriptions, retained partial import evidence, and a
strict pinned Speakeasy adapter. Emulated effects remain virtual. Unsupported
API resolution stops analysis instead of using declaration-only success
fallbacks. The minimal emulator remains an explicitly selected regression
backend. A selected semantic handler is not proof of complete Windows behavior;
Speakeasy coverage remains partial.

LightGBM/EMBER2024 feature extraction, local training, calibration, signed model
validation and signed fusion-policy loading are implemented. Correlated static
features cannot alone satisfy independent confirmation. Automatic unfamiliar
response requires a separately trusted signed policy meeting its evaluation
gates. Automatic persistence response additionally needs explicit opt-in and is
limited to recent verified HKCU autorun changes. Process termination stays off
by default. Circuit-breaker, rate and scope limits remain in force.

## Measured model status

Only public nonexecutable .NET feature rows were acquired for this iteration.
The dataset snapshot is joyce8/EMBER2024 at
3d23efef7c0f0b702c5024400cfff4c3744a3832 (Apache-2.0 recorded by its card).
The extractor source is FutureComputing4AI/EMBER2024 at
0ef753e81d98bf209f71b03cd331dfc190b5b54d. Speakeasy source is
mandiant/speakeasy at 57d22dd475be9897cc939e3a4f01608104b0f903.

The pilot used 4,400 training, 4,000 calibration and 5,993 test rows, with exact
hash deduplication and exact TLSH-group split separation. Exact TLSH equality
does not establish family separation. On 3,000 malicious and 2,993 benign test
rows it achieved 1,026 true positives (34.2%) and zero false positives, whose
one-sided 95% upper bound is 0.100041214%. **Both the recall and false-positive
release gate fail.** The artifact is unvalidated, unsigned and inactive.
Win32/Win64 trained artifacts, family-disjoint evidence, raw end-to-end sample
evaluation and the 30,000-control automatic-action gate are outstanding.

## Work storage and builds

New feature datasets, models, build output, dependency manifests and evaluation
reports use F:\SentinelAV-Work. Workspace quotas/reserve checks reject unavailable
drives and linked paths instead of falling back to C:. Reports use unique
exclusive-create files; these are preserved records, not administrator-proof
tamper-resistant storage. Application preferences/history remain in their
existing user-data location for compatibility.

Run `scripts/Install-AnalysisDependencies.ps1` to install reviewed source
revisions and required API metadata without recursively fetching upstream
specimen-test submodules. Existing native Unicorn compatibility verification
is still required. `build.ps1 -Installer` writes to the F: builds area and records
installed dependency versions. No signing private keys or feature datasets are
added to the package.

## Remaining implementation and release work

This is not a declaration that all eight phases are finished.

| Area | Still required |
| --- | --- |
| Work storage | New native builds and lab controllers use F:. Legacy evidence is preserved; active legacy guests prevent an unowned migration. Opt-in cache retention preserves source, datasets and reports. Historical journal retention needs release policy. |
| Analysis | Broader archive coverage, recursive full-pipeline extraction, deeper PE/CLR resources, and frozen Windows semantic compatibility coverage. |
| Emulation | Broader verified semantic coverage, report-to-behavior normalization, and real-sample diagnostics evaluation; no general CLR execution is provided. |
| Models | Separate Win32/Win64/.NET validated artifacts, scalable training, temporal/family-disjoint and raw sample evidence. |
| Attribution | More authorized telemetry, broker-mediated task/service causation, complete event-loss accounting and per-application grouping. |
| Privilege boundary | Implemented: one-shot UAC broker, independent machine cleanup decisions and encrypted owner-readable service history. Native harmless negative controls passed in Sandbox. Interactive approval, positive repair, broader principals and upgrade/uninstall require further deployment validation. |
| Cleanup | Broader incident-wide reconciliation, reboot recurrence verification, backup-loss/disk-full/reboot integration fixtures, and task/service repair validation. Per-action verification and a fresh inventory checking active references to known incident paths are implemented; incomplete inventories prevent verified removal. |
| UI | Rich per-application timeline/graph and evidence navigation; current UI offers change rows, before/after evidence, reviewed plans and receipts. |
| Deployment | Install/repair/upgrade/uninstall validation of the new subsystem, final frozen regression checks, release signing/update acceptance and compatibility review. |
| Comparative evidence | Defender-active matched environments and 30 paired, ten-family frozen cleanup cases. Current Sandbox is not a valid Defender baseline. |

The comparison evaluator rejects inactive Defender, mismatched or missing
environment/reset metadata, incomplete observations and missing reboot checks.
It reports actual recurrence/collateral and gates any superiority claim. This
metadata evaluator does not itself create ground truth or prove an environment
was reset. No Defender superiority claim has been established.

What's next: expand incident verification and detection coverage,
then validate the remaining detection and deployment gates before enabling
broader automatic cleanup.

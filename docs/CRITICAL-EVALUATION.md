# Critical evaluation harness — 0.16.0

Double-click **Run-SentinelAV-Tests.cmd** in the project root. The progress window
starts the Critical profile and writes a unique `logs/<timestamp>-<run-id>` folder.
The **Open report** button opens `report.md`. Cancel requests disposal of the owned
guest before the window closes. No malware repository is downloaded automatically.

Profiles:

- **regression**: approved historical specimens, Microsoft controls, harmless
  functional tests and the existing frozen 4,000-row .NET feature regression.
- **critical**: all regression and qualification tracks. Missing VM, independent
  datasets, active policy or telemetry yields blocked/inconclusive evidence.
- **soak**: 24-hour dedicated VM observation. `--release-soak` requests seven days.
  Release qualification requires seven-day evidence; 24h is an engineering trial.

The eight cached Zoo specimens are regression fixtures, never a representative
qualification corpus. Warnings, confirmed detections, prevention and verified
cleanup are separate. A no-match with missing inspection/telemetry is not clean.

## First-time prerequisites

The project Python environment must exist. Current-source builds use `build.ps1`
and the portable Inno compiler; stale builds are not silently reused. Heavy output
stays under `F:\SentinelAV-Work`, including build and evaluation temporary files.
The project report drive needs 2 GiB free for bounded metadata logs and headroom;
the work drive retains a 20 GiB reserve. Windows Sandbox separately requires
10 GiB on the system drive because F: staging does not relocate its Windows-managed
guest storage. A dedicated Hyper-V VM can keep its guest disks on F: and is not
blocked by the Sandbox-only reserve. The harness never frees space by deleting
your files. Reports contain metadata; specimens and private transfer keys do not
belong in `logs`. Logs are excluded from Git.

The first progress window offers guest-only telemetry setup with an explicit
Microsoft Sysinternals license choice. It downloads Sysmon from Microsoft's
official HTTPS endpoint, verifies Microsoft's Authenticode signer, builds the
local ETW collector, and freezes hashes for subsequent runs. It does **not**
install Sysmon on the host. Choosing No leaves telemetry-dependent cases blocked.
The .NET 8 SDK or existing portable SDK is required to build the collector.

Equivalent explicit setup:

```powershell
.\.venv\Scripts\python.exe -m tools.evaluation.setup_lab_telemetry --accept-sysmon-eula
```

Review [Microsoft's terms](https://learn.microsoft.com/sysinternals/license-terms)
before accepting. Existing support artifacts are preserved rather than updated
silently. Collection failures do not justify disabling Windows protections.

## Dedicated VM enrollment

Prepare a **dedicated, legitimately licensed Windows VM** in Hyper-V. Store its
disks on F:, disconnect its network adapters, enable PowerShell Direct, and create
a clean baseline checkpoint. Do not enroll a personal/work VM: evaluation restores
the selected checkpoint and powers the enrolled VM off after cases.

Run an elevated PowerShell from the project root:

```powershell
.\scripts\lab\Register-EvaluationVM.ps1 -VMName 'SentinelAV-Lab' `
  -BaselineCheckpoint 'Clean-Windows' -LicensedWindows -CleanBaselineAcknowledged
```

Enrollment prompts locally for the guest administrator's credentials. Windows
DPAPI protects the credential XML for the current host account, and its ACL is
restricted. It remains under private F: lab configuration and is never exported
in reports or copied into a guest. Enrollment supplies no Windows license and
does not certify that a user-provided baseline is clean.

Sandbox and VM jobs verify guest identity, offline state, known package hashes
and exact ownership. Sandbox never receives a writable host output share. VM
transport uses PowerShell Direct and guest-local files. Every running attempt
has an ownership record before mutation and a disposal receipt afterward.

## Independent inventory contracts

Place reviewed JSON inventories under
`F:\SentinelAV-Work\lab\qualification\inventories`. Required outer fields:

```json
{"schema":1,"approved":true,"reviewer":"reviewer identity",
 "provenance":"source, revision, selection method and label evidence",
 "role":"qualification"}
```

Approval is a caller attestation, not independent proof. Unknown training overlap
or labels cannot be advertised as unseen/family-disjoint evidence.

### Feature qualification

Files `temporal-Win32.json`, `temporal-Win64.json`, `temporal-Dot_Net.json` add:

- `feature_rows`: absolute managed `datasets` path to nonexecutable JSONL.
- `feature_rows_sha256`, `training_cutoff` (ISO date/time),
  `model_training_overlap: "excluded"`.
- `family_disjoint`, and `training_families` when family separation is claimed.

Each JSONL row supplies `sha256`, integer `label` (0/1), `file_type`, extracted
`features`, `first_submission_date`, and `family` when available. Prior prepared
rows are excluded from new qualification. No threshold fitting, signing or active
model changes occur. Published pinned feature download tools remain separate;
acquisition does not establish an untouched approved evaluation partition.

### Raw/control/workflow/cleanup corpora

Use `independent-raw-corpus.json`, `automatic-action-controls.json`,
`legitimate-app-workflows.json`, `remediation-cases.json` and `recurrence.json`.
Their `files` list contains `{blob, sealed_sha256, sha256, label, family,
family_verified, independently_selected, independent_control}` metadata.
Blob names end in `.sealed`; sample files are capped at 8 MiB.

Ciphertext lives in `lab/qualification/corpora/<inventory-name>/` on F:. Each
blob is `12-byte nonce || AES-256-GCM ciphertext/tag`, with AAD
`SentinelAV-qualified-corpus-v1`. The 32-byte key is protected using current-user
Windows DPAPI in `transfer-key.dpapi`. Only ciphertext and reviewed metadata are
staged; plaintext is decoded only after guest verification. This interface does
not authorize opening or executing specimen plaintext on the host.

The harness batches approved inventories in groups of at most 32. Do not include
regression specimens in qualification: duplicate measured identities are rejected.
The raw gate needs 200 independent Windows files across 20 verified families.
Each qualification entry declares `format: PE` independently of the scanner;
failed inspections remain in the all-selected denominator. Feature inventories
must attest `untouched_holdout: true` and `related_build_separation: true`.

Automatic-action controls additionally require an explicit `automatic_policy`
snapshot with `enabled: true`. Actual product eligibility, validation, rate limits
and exclusions remain in force. No policy is fabricated or granted extra powers.
Each control is scanned while the policy worker is active; false actions are
reported separately from warnings. The safety gate needs 30,000 unique controls.

Application workflows add `workflows` entries selecting a reviewed benign `sha256`,
bounded `arguments`, `seconds` (at most 600), `expected_exit_code` and
`expected_files` assertions (`path`, `exists`, optional `sha256`). Assertions are
restricted to test and application-install locations; unrelated personal content
is not collected. A launched installer without expected-state evidence is not a
successful compatibility test.

Cleanup/recurrence manifests add `expected_artifacts`. Seeded external
fixtures support trial-relative `file` records and owned HKCU Run values named
`SentinelAV-Lab-*`. File records specify `relative` and `malicious`; registry
records use `key: Software\\Microsoft\\Windows\\CurrentVersion\\Run`, `name`
and `malicious`. Existing values/files are never overwritten. Product signature
verification and remediation policy decide permitted response. Task and service
fixtures require individually owned `SentinelAV-Lab-*` names and reject existing
resources. They are created without launching their payloads; the recurrence
track subsequently reboots the offline VM. Broad unrelated settings remain
unsupported. Harmless response contract tests provide separate synthetic evidence.

Recurrence uses the same recorded artifacts and protected controls after two
independently observed guest reboots. The verifier performs no additional repair
between those checks. No Sandbox restart is represented as a persistent reboot.

Optional Defender comparison takes approved `comparison.json` containing frozen
`cases` and matched `trials` records consumed by the existing comparison evaluator.
It requires operational Defender, matching environments, 30 pairs across ten
families and two reboot checks. Imported metadata still requires independent audit.

## Reports, limits and recovery

The report has a critical-failure backlog, gates, track coverage and per-sample
ledgers. JSON, CSV, redacted telemetry health/summaries and checksums accompany it.
Feature misses include individual expert scores for targeted improvement. All
formats have separate mandatory statistical gates. There is no overall antivirus
quality percentage. Compatible cohorts can be compared with paired confidence
intervals; source/model differences remain recorded.

Raw guest journals are bounded and guest-local. At most 64 KiB of structured
case metadata is exported through a bounded numeric control channel, compressed
to at most 32 KiB. Malformed or oversized exports fail rather than disappear.
Guest errors are also exported through that channel. Large evidence summaries
can be incomplete; no certification is inferred from collection alone.

Default Critical/Regression duration is two hours. Soak has its own extended
budget. An interrupted queue can resume only with its frozen source/build and
after ownership reconciliation. Completed results are never replayed silently:

```powershell
Run-SentinelAV-Tests.cmd --headless --profile regression
Run-SentinelAV-Tests.cmd --headless --preflight-only
Run-SentinelAV-Tests.cmd --headless --host-only
Run-SentinelAV-Tests.cmd --resume "C:\path\to\sentinelav\logs\RUN"
Run-SentinelAV-Tests.cmd --profile soak --release-soak
```

Resume preserves completed cases; rerunning blocked cases with new prerequisites
requires a new run so configurations are not mixed. Collection/response capabilities
stay visible: an inactive automatic policy or unsupported API is not a pass.

### Current verification boundary

Host unit tests and preflight reporting are safe to run without a test VM. Full
guest integration, collector probes, reboot trials and live malware observation
must be measured in the corresponding enrolled environments. A passing host unit
suite is not evidence that those product tracks passed.

The run log budget is 1 GiB, with pending work preserved when reached. Only
regenerable per-case input kits are removed after verified guest disposal;
their input manifests and disposal receipts are retained. Frozen packages,
original encrypted corpora and reports are preserved. A changed lab enrollment,
collector manifest or execution scope prevents resume into a mixed environment.

Feature qualification requires at least 2,000 malicious and 10,000 benign
examples per supported format, in addition to the specified recall/FPR gates.
Automatic-action controls need a separately approved positive control proving
the frozen policy actually acted; an inactive policy cannot pass 30,000 controls.

Soak samples protection/collector health every two seconds, repeats harmless
collection probes every five minutes, and enforces a 1 GiB process-tree memory
budget. It retains bounded event excerpts and cumulative category counters;
intentional rolling retention is distinguished from collector loss. It currently
exercises the per-user agent; protected-service recovery is a separate VM case.
Physical sleep/resume and the broader application performance matrix remain
explicitly incomplete. Qualification stays blocked until that evidence exists.

Methodology references: [AMTSO testing principles and guidance](https://www.amtso.org/documents/)
and [AV-Comparatives' 2026 real-world methodology](https://av-comparatives.org/tests/real-world-protection-test-february-may-2026/).
This internal offline harness is neither AMTSO certification nor that online test.

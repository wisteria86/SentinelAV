# Unvalidated implementation pass — 2026-11-03

These are chronological implementation notes. The current authoritative user-path
map is [FIRST-ITERATION.md](FIRST-ITERATION.md). Later integration changes supersede
older review-only content matches, audit-only host policy tooling, missing trust UI
and manual-only guest orchestration described below.

The user explicitly requested code without testing. **No tests, syntax checks,
builds, scans, model training, sample execution, installation or policy deployment
were performed for this pass.** Earlier passing test counts predate these changes
and do not validate them. Existing installers and lab bundles are unchanged.

This is a substantial source implementation, not a declaration of a completed or
commercially reliable antivirus. Newly added analysis is opt-in. No publisher key,
trained model or reputation feed has been invented or silently trusted.

## Code written and integration points

| Component | Source implementation | Connection / activation |
| --- | --- | --- |
| Evidence decisions | `detection/decisions.py` | Single-file scan reports combine signature, structural and experimental evidence. Existing response authorization remains separate. |
| Script normalization | `detection/content_analysis.py` | Bounded UTF-16, Base64 literals, escape decoding and literal concatenation feed existing detection patterns. No eval or script-engine invocation. |
| Containers/documents | `detection/content_analysis.py`, `detection/documents.py` | In-memory GZIP, TAR, partial PDF Flate stream inspection and optional VBA extraction join experimental scanning. Existing ZIP inspection remains. |
| Supervised classifier | `detection/classifier.py`, `tools/evaluation/train_classifier.py` | Standardized L2-regularized logistic regression, JSON inference, per-feature contributions and independent benign threshold calibration. No model was trained. |
| Reputation | `detection/reputation.py` | Signed, expiring SHA-256/domain entries; exact domain matching; no file uploads or automatic trust override. A real feed must be supplied. |
| Publisher/update pipeline | `updates/artifacts.py`, `tools/feeds/manage_artifacts.py` | Encrypted publisher key generation, signing, pinned-key verification, expiry, revision replay rejection, exclusive download and atomic activation. Model/reputation imports have a UI path. Hosting, trust distribution and operational feed production are external work. |
| CPU emulation/unpacking pass | `detection/emulation.py` | Optional Unicorn-backed PE32/PE32+ image/stack mapping, bounded instruction execution, changed executable-page inspection. No native sample execution; unsupported imports and Windows semantics remain omissions. |
| Behavior sequences | `monitoring/sequences.py`, `resources/behavior/additional-sequences.json` | Additional data-defined sequences, process-GUID lineage and attributed create/delete churn. These are review alerts, not confirmed ransomware verdicts. |
| Kernel file-write telemetry | `native/telemetry/`, `monitoring/kernel_telemetry.py` | C# TraceEvent collector, bounded JSON transport, PID/start-time verification, device-path mapping, scoped write/canary correlation and protected executable path checks. Not built or deployed. |
| Runtime lab job | `lab/runtime_job.py`, `tools/evaluation/run_guest_job.py` | Explicit guest-only authorization, offline guest checks, predeclared SHA-256, suspended creation, job assignment before resuming, bounded runtime, attributed Sysmon correlation and guest-local report. Not invoked. |
| Process-tree response | `response/containment.py`, `tools/evaluation/process_tree_response.py` | Snapshot planning, explicit hash approval, child-before-parent ordering and existing fresh-signature, ownership, PID identity and critical-process guards. No automatic execution. |
| Windows application control | `scripts/Export-AppControlAudit.ps1`, `scripts/Deploy-GuestAppControl.ps1` | Hash-identity-checked audit policy export using ConfigCI, plus separately explicit offline-guest deployment. No host policy deployment, no custom kernel driver and no weakening of Windows security. |
| Shared service policy | `platform/engine_policy.py`, `platform/windows_service.py` | Common option validation, configurable service source selection and protected-service analysis-store support. Service identity remains LocalService; no elevation workaround. |
| UI/reporting | `ui/defense_ui.py`, `ui/application.py`, `ui/protection.py` | Experimental options, signed artifact import, review rows and telemetry-source visibility. Results requiring review do not enter automatic quarantine. |

## Entry points (documented, not executed)

Run source tools from the project root. `requirements/experimental.txt` lists
optional Unicorn and oletools dependencies; they were not installed. The native
telemetry project targets .NET 8 Windows with the TraceEvent package reference.

```powershell
# Produce an unvalidated model from an independently labelled feature dataset:
.\.venv\Scripts\python.exe -m tools.evaluation.train_classifier dataset.json --output model.json

# Publisher operations; private keys stay outside bundles and version control:
.\.venv\Scripts\python.exe -m tools.feeds.manage_artifacts keygen --output publisher.pem
.\.venv\Scripts\python.exe -m tools.feeds.manage_artifacts sign model.json --key publisher.pem --key-id research --kind model --revision 1 --output signed-model.json

# Verify and explicitly activate against separately reviewed/pinned trust keys:
.\.venv\Scripts\python.exe -m tools.feeds.manage_artifacts activate signed-model.json --kind model --trust resources/trusted-update-keys.json --store resources/analysis-data
```

The GUI imports to the current user's state directory and saves that analysis
store in inspection options. A running persistent scanner retains its loaded
assets until restarted; model expiry is checked before inference. Restart
monitoring after imports. Per-user artifact revision history is not resistant to
an attacker who can rewrite that user's application/state. Protected deployment
requires the existing administrative ownership/ACL boundary.

The update trust file currently contains no keys. Key generation does not pin its
own public key. Unsigned training output is never directly activated as trusted
analysis data. Model scores are not calibrated malware probabilities and never
authorize process termination or file removal.

## Runtime jobs

A runtime job JSON requires `authorization` exactly
`RUN_ONLY_IN_DISPOSABLE_OFFLINE_GUEST`, an absolute guest-local `sample` path,
its predeclared `sha256`, and `seconds` between 1 and 120. The CLI calls a second
guest verification before launching anything. Ordinary scans never invoke this
runner. Output remains under a new `C:/SentinelAV-Test/Runtime-…` directory.
Reports include coverage limitations; a match requests review, and absence of a
match remains indeterminate. Raw guest-wide telemetry is distinguished from
correlation restricted to the subject's observed Sysmon process tree.

The host must discard the guest afterward using the existing reset controller.
This runner does not constitute a security guarantee against VM escape, malware
that exploits the guest kernel, or instrumentation blind spots. Networking and
host writable mappings must remain disabled; existing guest checks are a workflow
guard, not tamper resistance against an administrator already inside the guest.

## Native and detection limits still present

- CPU emulation does not implement Windows DLL/API dispatch, TLS callbacks,
  exceptions, kernel behavior or arbitrary packers. It is a bounded first pass,
  not a general Windows emulator. Changed-page signatures can miss cross-page code.
- PDF parsing is partial; macro extraction does not analyze VBA p-code, every
  document format, every obfuscation scheme or every archive type.
- Kernel ETW needs suitable Windows authorization and native deployment. The
  LocalService account is not silently granted administrative rights. Collector
  startup/permission failure is reported as unavailable. Source delivery gaps,
  exited processes and unresolvable identities are not attributed by guesswork.
- Sysmon must be installed/configured for the relevant event types; its presence
  alone does not establish complete coverage. Create/delete churn and write bursts
  can be legitimate and do not establish that files were encrypted.
- The tree response is a snapshot, not atomic containment of future descendants.
  It deliberately refuses nonapproved/nonmatching binaries instead of killing an
  entire tree based on a behavioral score.
- App Control export/deployment is not dynamic interception of every launch.
  Host enforcement, safe rollout/rollback and actual OS policy activation remain
  undeployed. No signed native minifilter, PPL or kernel tamper resistance exists.
- Native AMSI provider deployment still uses the existing prerequisites and
  Windows trust requirements; this pass does not manufacture a trusted certificate.
- Hosting a publisher, curating feeds, obtaining trustworthy labels and producing
  validated model weights cannot be replaced by application source code.

## External API references

- Unicorn: https://www.unicorn-engine.org/docs/tutorial.html
- VBA extraction: https://github.com/decalage2/oletools/wiki/olevba
- ConfigCI: https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy
- Defender architecture: https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav

## Continuation: Windows API model and deployment lifecycle

Additional code was written in the same untested implementation series:

| Area | Added source / behavior |
| --- | --- |
| PE addressing | `detection/pe_image.py`: bounded RVA lookup, ordinary and delay-load IAT slots, TLS callback enumeration |
| Delay-load static analysis | `detection/delay_imports.py`: delay imports join static capability evidence; malformed input becomes an omission |
| Windows API-aware execution | `detection/windows_emulation.py`, `detection/winapi_emulator.py`: x86/x64 calling conventions, import dispatch, dynamic lookup of modeled APIs, TLS callbacks before entry point, cumulative CPU limits |
| Virtual OS effects | Bounded emulated memory, file I/O, registry writes, HTTP intentions, environment strings, timing, process identity, single-thread synchronization and TLS API slots; no corresponding host mutations |
| Unpacking evidence | Inspect modified image/heap pages, overlapping page windows, virtual output files and combined API intentions; evidence stays review-only |
| Additional documents | `detection/active_content.py`: bounded RTF hex object extraction, HTML inline scripts/event handlers and text normalization; no renderer or script execution |
| Attributed DNS | Sysmon event 22 queries can be checked against the signed domain index; this does not inspect encrypted traffic or fetch URLs |
| Recurring analysis updates | `updates/agent.py`: opt-in configured HTTPS GETs, signature/expiry/revision checks, same-revision equivocation rejection and persistent worker reload after activation |
| Update UI | Settings → Defense → Analysis Data: model/reputation URLs, hourly opt-in checks, no uploads and separate analysis activation |
| Native collector staging | `scripts/Build-KernelCollector.ps1`, `scripts/Install-KernelCollector.ps1`: build/publish code, hash manifest, explicit reviewed-manifest staging, protected ACLs and ownership; no implicit launch or privilege grants |
| Host audit lifecycle | `scripts/Manage-AppControl.ps1`: fresh policy IDs, reviewed XML hash, audit-mode submission, protected receipts, status query and removal limited to the recorded managed policy |

The earlier “CPU-only” limit above describes the first pass. The current default
emulation entry point delegates to the new API-aware backend. It still reports
partial coverage: API models cover a subset, not arbitrary DLL implementations;
PEB/TEB-based loader traversal, static TLS memory, SEH/VEH, multithreading, direct
syscalls, unmodeled runtimes and architectures remain gaps. Unsupported APIs stop
analysis rather than returning invented success. Virtual API results describe the
modeled environment and must not be presented as observed Windows behavior.

TLS callback dispatch does not imply complete TLS loader compatibility. Virtual
file/registry/network events are intentions inside one emulation context, not
evidence that the host performed those operations. No host network connection is
made by modeled WinHTTP APIs. Unknown DLL implementations are not modeled merely
because they export a familiar function name.

The native installer stages files only. ETW authorization remains an explicit
Windows deployment requirement; LocalService is not silently elevated. Host
application-control tooling submits audit mode only. It never disables existing
Windows protections or claims an OS policy is active solely from a successful
submission. Audit policy removal can be rejected by Windows signing restrictions;
the tool records failure and does not bypass them.

**Still not run:** every new Python path, the .NET build, installers, updater,
policy tools, model trainer and emulator. The optional dependencies, real model
weights, reputation feed, publisher pins and deployment permissions remain absent
unless separately supplied. No earlier test result validates this continuation.

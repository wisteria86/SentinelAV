# Defender method comparison and implementation status

Reviewed 2026-11-03 against Microsoft's public description:
https://learn.microsoft.com/en-us/defender-endpoint/adv-tech-of-mdav

These are method categories, not a claim that Defender's proprietary models can
be reproduced from public documentation. “Implemented” below describes local code,
not demonstrated parity, detection coverage or successful native deployment.

| Method | SentinelAV now | What remains |
| --- | --- | --- |
| Signatures and pattern matching | SHA-256 lookup, source-compiled YARA, local versioned definitions and signed-delta verification code | Broader reviewed coverage, an operating authenticated publisher/update service, freshness monitoring and independent detection measurements |
| Static heuristics | Bounded PE headers, section statistics, entry-point/range checks; **new PE32/PE32+ import parsing and combined API capability evidence** | Delay imports, dynamically resolved APIs, richer document/script analysis, validated classification and reduced review noise |
| Local/cloud ML | Offline benign-distance baseline, versioned numeric features and leakage-checked calibration tooling | Representative independent labels, supervised file-type classifiers, appropriate calibration, adversarial testing and validated deployment; no cloud ML service exists |
| Behavior monitoring | Folder/canary heuristics, process ancestry and network indicators; **new process-GUID-attributed, ordered Sysmon sequence detector** | Live source deployment/configuration, more validated behavioral sequences, child-process chain correlation, attributed file-write telemetry, detection latency and false-positive measurements |
| Emulation/unpacking | ZIP member scanning only; this is not executable unpacking | CPU/OS/API emulation, packed-code recovery, architecture coverage and safe resource/fault containment |
| Sandbox/detonation | Offline Windows Sandbox preparation and static corpus tests | Automated runtime instrumentation, controlled execution lifecycle, behavior capture, scoring and reset verification; test infrastructure is not a detonation classifier |
| Reputation | Exact local hash decisions and explicit hash trust | Independently trusted file/publisher/domain reputation, prevalence, age, revocation/freshness and privacy-controlled queries. A signed file alone is not safe. |
| Scripts/AMSI/memory | Optional AMSI consumer, native provider/service code with earlier guest validation, bounded manual same-account memory checks | Trusted host deployment, broader script/content normalization and memory evidence, protected-process coverage and enforcement verification |
| Network analysis | Visible connection snapshots and configured IP/CIDR indicators | Richer attributed network telemetry, domain/protocol context and validated detection models. Snapshot fanout alone is not malicious. |
| Pre-execution blocking / response | Manual launch inspection; verified manual quarantine and default-off approved-hash response | System-wide interception/control, deployed protected service and safe decisions fast enough to prevent harm. New review signals do not grant response permission. |

## Implemented in this change

### PE imports and capability evidence

`detection/pe_imports.py` reads import descriptors, library names, thunk tables,
named symbols and ordinal imports for PE32 and PE32+. It maps virtual addresses
to file-backed sections and rejects ambiguous mappings, unterminated tables,
oversized names and traversal outside file bounds. Work and output are bounded.
Nothing is loaded or executed. The parser follows the Microsoft PE specification:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

API groups describe potential capabilities: cross-process memory access,
remote-thread creation, registry writes, networking and encryption. The combined
remote-memory/thread group adds an explainable structural-review signal. It does
not prove those imports are ever called or are malicious. It is separate from
signature detections and automatic response. API names describe Windows semantics,
not malware-family or specimen names. Missing coverage is explicit in single-file
analysis; malformed imports also become scan omissions. Delayed imports and runtime
symbol resolution remain uninspected.

### Process-attributed ordered sequences

`monitoring/sequences.py` parses bounded Sysmon event XML, verifies the provider,
and correlates events by ProcessGuid with PID and image agreement. It ignores
duplicate record IDs, backdated events, expired sequences and ambiguous identities.
A bounded state machine matches ordered semantic categories. The current reviewed
policy is stored separately in `resources/behavior/sequence-policy.json`:

1. Encoded PowerShell interpreter launch (event 1).
2. Same process writes an autorun registry value (event 13).
3. Same process initiates a public network connection (event 3).

All steps must occur in order within 120 seconds. A match emits an alert with
its rule ID, ProcessGuid and contributing event record IDs, classified as a
suspicious sequence requiring review. No automatic termination, quarantine or
network blocking follows. Legitimate administration can also produce this chain.
This first policy does not cover every interpreter spelling, persistence technique
or event ordering; it is not a complete ransomware or malware detector.

Monitoring now consumes structured XML rather than only displaying Sysmon's
localized text. Existing exclusions apply. Filesystem watchdog events remain
folder-level evidence; they are never assigned to a nearby PID. ProcessGuid-based
correlation is documented by Microsoft:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

**Live availability:** read-only host checks found zero Sysmon services and no
`Microsoft-Windows-Sysmon/Operational` channel. No software, driver, logging policy,
or Defender setting was changed. Live sequence coverage therefore remains
unavailable on this PC. Using it requires Sysmon with events 1, 3 and 13 configured,
access to its channel, and SentinelAV's Sysmon and behavior options enabled.
Sysmon's default setup does not enable network monitoring. The existing reader
polls every 15 seconds in batches of 100, so this is post-execution review with
potential backlog, not guaranteed real-time prevention. Configuration filtering,
log loss and absence of a matched sequence must never be treated as proof of safety.

## Evidence and next work

Unit tests use inert PE bytes and synthetic Sysmon XML; they cover both PE
widths, ordinal imports, bad/ambiguous RVAs, bounds, single-capability rejection,
correct sequence ordering, PID reuse, duplicate/backdated records, expiry, capacity,
monitor routing and exclusions. They do not execute the command text in fixtures.
The existing Qt checks cover alerts, history and guarded response separately.
The final `test.ps1 -UI` run passed all 135 unit tests and ten Qt integration
scripts. Live Sysmon capture was not tested, because that source is absent here.

A new 500-file System32 check completed in 18.3243 seconds, with zero signature
detections and zero inspection errors/skips. **One file received structural review
for the combined API capabilities.** This is evidence of review noise on a
presumed-benign corpus, not a confirmed false-positive rate or malware efficacy.
Report: `artifacts/evaluations/benign-20261103T115459Z-f0370bfb/report.json` and `.html`.

No new malware samples or hashes were added. Previous real-sample misses remain
recorded misses. Existing installers and lab bundles have not been rebuilt; the
source launcher uses the changes after restart. Future bundles include the policy.

Next implementation priority is guest deployment and validation of attributed
telemetry, then broader evaluated sequence policies and file-type analysis. A
supervised classifier needs independent labelled data; an emulator/detonation
engine and trusted reputation service remain substantial separate implementations.

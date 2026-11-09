# Signature-free evaluation — 0.15.0

This mode disables saved malware hashes, YARA compilation/matching, EICAR/demo
patterns, hash allowlists, reputation and AMSI. Signature stores are not opened.
The same disabled callback is used by decoded content, containers and virtual
emulation. Normal protection defaults remain unchanged. SHA-256 still identifies
samples and verifies integrity; model/update cryptographic authentication remains
enabled. Neither operation performs malware hash matching in this mode.

The evaluator requires explicit worker attestation and zero loaded signatures.
Unattested/contaminated findings become unavailable, not successful detections.
Signed model candidate scores are recorded separately from production decisions;
unvalidated models and structural review signals are not promoted to detections.
Non-PE inputs lack independent classifier coverage and are not counted as clean.

Generate readiness evidence without opening sample contents:

```powershell
.\.venv\Scripts\python.exe -m tools.evaluation.prepare_signature_free
# Optionally freeze a supplied inventory and enumerate its batches:
.\.venv\Scripts\python.exe -m tools.evaluation.prepare_signature_free --manifest F:\path\manifest.json
```

Version 0.15.0 installs an active signed EMBER2024 feature ensemble and a pinned
MalConv2 raw-byte classifier; see [learned detection](LEARNED-DETECTION.md).
These are research review classifiers. The measured .NET false-positive gate
has not passed, native PE and neural thresholds still require calibration, and
no complete pinned Zoo corpus inventory is available. Installing the algorithms
does not establish validated independent protection.

When the next evaluation is explicitly started, the packaged CLI supports:

```powershell
# Only inside the verified offline guest with an existing corpus:
.\SentinelAV.exe --evaluate-corpus C:\Corpus\manifest.json --evaluation-output C:\Results\batch-0 --signature-free --batch-offset 0
```

Use offsets 0,64,128,... from the metadata plan. A frozen manifest can contain up
to 10,000 entries; each run inspects at most 64 unique hashes. Duplicate hashes
are excluded consistently, conflicting labels are rejected, and the original
manifest digest is retained. All selected files retain pre/post identity checks.
Limits remain 8 MiB per file, one worker, 1 GiB worker memory for emulation and a
bounded per-file timeout. Unsupported/oversized/failed cases must remain visible.
Batch outputs are exclusive new directories outside the corpus; no malware is
launched or remediated by this evaluator. Virtual emulation is not native Windows
behavior testing. The default historical pilot covers only selected families,
not the full Zoo. A full test needs an independently inventoried, revision-pinned
corpus and suitable resettable lab; no samples were acquired in this preparation.

Aggregate exported report metadata with `python -m tools.evaluation.aggregate_signature_free --manifest MANIFEST --reports REPORT1 REPORT2`.
This rejects mixed manifests/modes, duplicate measurements, contaminated workers,
identity/label mismatches and mixed engine/model versions. Missing and unavailable
cases remain explicit. Caller labels and guest reports still require audit.

Remaining prerequisites include validated independent classifiers, richer
modeled-behavior evidence, complete shared-pipeline inspection of extracted
members, full corpus selection/provenance and positive cleanup
evaluation. A full-repository superiority or protection claim is unsupported.

## Fixed cached specimens

`python -m tools.evaluation.run_learned_zoo` evaluates the eight previously
acquired, revision-pinned specimens in the registered offline Sandbox. The
prepared kit must include all three sealed corpus groups. Transfer keys are
unprotected only in memory and supplied to the guest; they are excluded from
the read-only input kit. Samples are unpacked only inside the guest and are
never launched natively. Static analysis and bounded virtual emulation run
through the shared scanner with every saved-signature channel disabled.

The controller exports bounded numeric status, scores and SHA-256 identities.
Research review warnings are separate from confirmed production detections,
classifier availability and full inspection coverage. Missing controls and
unsupported formats are retained explicitly. Historical Zoo samples may have
appeared in public model training; this is not an unknown-malware benchmark.

Before discarding the guest, run `python -m tools.evaluation.audit_learned_zoo
F:\SentinelAV-Work\evaluations\RUN\report.json` to preserve numeric diagnostics
and separate counts without changing the original report. Full guest reports
and plaintext specimens are destroyed when the disposable guest is stopped.

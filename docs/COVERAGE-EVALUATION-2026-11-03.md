# Broader safe evaluation — 2026-11-03

These runs exercise known-marker transformation coverage and presumed-benign
files. They do not measure unknown-malware detection or real-time prevention.
No files were executed, uploaded or acted on by SentinelAV response functions.

## Installed Windows files

The core scanner inspected 1,000 top-level System32 files twice against
1,164,912 hash signatures and the installed rules. Both passes had zero
detections, errors and skips. Elapsed scan times were 47.7548 and 44.1694 seconds;
sampled peak RSS was 54.62 MiB. Inventory fingerprints and postchecks matched.
These files are presumed benign, not independently labelled, and cached reads
are not a cold-start performance measurement. Advanced analysis was not enabled
for this run. Zero observed alerts is not a population false-positive estimate.

Evidence: `artifacts/evaluations/benign-20261103T145145Z-6beb4821/report.json`
and its HTML companion.

## Inert transformation suite

The original run included 15 positive marker transformations, nine generated
negative controls and one unsupported-format probe. Each file passed through
the actual isolated scanner with host AMSI disabled for this experiment only;
Windows protections were unchanged. Both profiles used archive inspection.

| Result | Baseline | Content/document analysis |
| --- | ---: | ---: |
| Positive fixtures with an alert | 6 | 14 |
| Of those, alerts with inspection gaps | 0 | 2 |
| No alert despite complete configured inspection | 8 | 0 |
| Positive fixture inconclusive | 1 | 1 |
| Unexpected negative-control alerts | 0 | 0 |
| Negative controls without alerts, inspection complete | 9 | 8 |
| Negative controls inconclusive | 0 | 1 |
| Unsupported-format probe reported a gap | 1 | 1 |

The baseline misses were Base64, Base64/UTF-16, double Base64, literal
concatenation, escaped literals, GZIP, PDF stream and HTML fixtures. Content
analysis observed all of these markers. PDF and HTML alerts retained partial
inspection warnings; no complete document interpreter is claimed. Ordinary HTML
also retained the bounded-parser warning without producing a detection.

Windows Defender removed the generated encoded RTF marker fixture, reporting
`Exploit:O97M/CVE-2017-11882.AP` (threat ID 2147741860). Its bytes were generated
as inert RTF text, with no exploit object or executable content. The host
intervention is recorded separately and does not establish malware ground truth
or a SentinelAV miss. The fixture was not restored, protection settings were
not changed, and that case was removed from future host fixture generation.
The original report retains it as inconclusive; future runs explicitly list
the exclusion and therefore have 24 on-disk cases rather than 25.

Evidence: `artifacts/evaluations/coverage-20261103T144957Z-2741fa2f/report.json`
and its HTML companion. The JSON includes declared expectations, SHA-256
inventory, options, per-file findings/omissions, definition provenance and the
external interference annotation. Expectations were declared before scanning.

## Repeat and interpret

From the project folder:

```powershell
.\.venv\Scripts\python.exe -m tools.evaluation.evaluate_coverage
.\.venv\Scripts\python.exe -m tools.evaluation.evaluate_benign --limit 1000 --repeats 2
```

The new harness separates partial detections, complete misses, inconclusive
results, negative-control alerts and explicit gap probes. Eight targeted
regression tests passed, including hash/path guards, accounting and HTML escaping.
No detection rule, hash or threshold was tuned to improve these results.

Next priorities: measure advanced analysis against broader benign files, review
which document warnings indicate inherent limits versus operational failures,
and evaluate behavioral protection using safe simulations. Representative real
malware evaluation remains separate from all results above.

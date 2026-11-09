# General static analysis

The scanner now calculates Shannon entropy, byte diversity and zero fraction,
per-section byte statistics, writable/executable permissions, entry point section
membership, overlapping raw section intervals and trailing byte count. It never
loads or executes the inspected file. Existing file-size and worker limits apply.

Structural review signals appear separately in scan results and JSON history.
Folder reports retain the first 100 review files plus the total count to bound
transport. Only single-file results retain full PE section metadata. Entropy,
section names and trailing bytes do not trigger a malware verdict. Structural
signals never enter the signature detections or automatic response pipeline.

This is a feature extractor, not a calibrated malware classifier. Its assessment
is review-only; signal count is not severity or probability. Writable/executable
sections and unusual layouts can be legitimate. Hashes and YARA remain useful
independent evidence. No sample-specific constants were added to this layer.

Next: collect feature vectors from representative, independently labelled benign
and malicious corpora, split by related family/build before tuning, and freeze a
holdout. Fit and evaluate a classifier or anomaly baseline using training data
only; report false positives and coverage omissions alongside detection results.
The small historical research corpus is insufficient for estimating reliability.
Bounded PE import/capability inspection has since been added; see
`DEFENDER-GAP-ANALYSIS.md`. Certificate validation and unpacking remain unimplemented
by this layer. The numeric feature schema is unchanged; API evidence is separate
and is not silently fed into the existing anomaly baseline.

## Offline calibration workflow

Scans now also retain a fixed numeric feature vector. It excludes sample names,
hash matches and YARA verdicts. The separate `calibrate_static` tool consumes
existing corpus-evaluation JSON; it never opens or runs sample files. Older
reports without these features must be regenerated through the existing lab
workflow. Malware stays inside the offline guest.

Create a reviewed assignments JSON with `schema: 1` and a `samples` object keyed
by sample SHA-256. Each entry must supply `label` (`benign` or `malware`),
`provenance`, `group` (related family/build lineage), and `split` (`train`,
`calibration`, or `test`). Labels must come from independent review, not from
SentinelAV's own detections. Put related builds/family variants into one group;
the tool cannot discover hidden relationships from hashes alone.

From the project root:

```powershell
.\.venv\Scripts\python.exe -m tools.evaluation.calibrate_static collect report.json assignments.json --output dataset.json
.\.venv\Scripts\python.exe -m tools.evaluation.calibrate_static fit dataset.json --output artifacts/evaluations/static-baseline --target-fpr 0.01
```

Both commands refuse to overwrite outputs. Collection retains omissions for
unassigned, incomplete, changed or unsupported files. It requires matching
inspection identities and successful post-scan checks. Duplicate hashes and
related groups spanning different splits are rejected. Multiple collected batches
can be combined into one dataset's `rows` and `omissions` before fitting; the
combined dataset is validated again. Preserve original reports and assignments.

The baseline fits a mean and standard deviation per dimension using benign
training rows only, then calculates the root mean square standardized distance.
Constant training dimensions are reported as novelty separately, without invented
scale factors. A quantile of independent benign calibration distances sets the
review threshold; test data never sets weights or thresholds. Output includes
per-feature contributions, test review fractions for each label, dataset digest,
and training/calibration sample hashes. Artifacts are plain JSON, never pickle.

The requested calibration false-positive fraction is an empirical target, not a
guarantee. For example, 20 calibration files provide only 5% resolution; they
cannot substantiate a 1% rate. Standardized distance assumes a useful benign
reference population and is sensitive to outliers and correlated dimensions.
No minimum row count establishes representative coverage. Very small synthetic
datasets are useful only for testing pipeline mechanics.

The tool does not install the model, change GUI verdicts, or enable automatic
response. Deployment remains deferred until independent evaluation supports it.

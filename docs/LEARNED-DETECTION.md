# Installed learned detectors — 0.15.0

Two learned inference paths are now integrated into the shared scanner:

1. **EMBER2024 routed gradient-boosted ensemble.** The original authors' Win32,
   Win64 and .NET specialists are combined with their general PE model by mean
   logit pooling. Features are extracted locally with the pinned EMBER v3
   extractor. Each prediction exposes both expert scores and its format. Models
   sharing static features remain correlated evidence, not separate independent
   confirmations. The small locally trained pilot has been superseded in the
   active profile by these published weights.
2. **MalConv2 global-channel-gating neural classifier.** The original authors'
   weights operate on byte sequences rather than handcrafted PE feature vectors.
   A bounded, two-pass NumPy implementation pools all stride-aligned convolution
   windows in the examined prefix. It reproduces the PyTorch layer equations
   within numerical tolerance and works alongside the feature ensemble inside
   the existing 1 GiB scanner worker. Runtime loading uses digest-pinned NPZ
   arrays with pickle disabled. No sample is loaded as executable code.

Both paths run on the CPU and upload no file contents. They operate when saved
hashes/YARA/AMSI/reputation are disabled. Learned analysis also reaches extracted
PE bytes, retaining parent/member identities and no physical response authority.
Member work is bounded to 50 unique members, 8 MiB per member and 32 MiB total.

MalConv2 examines at most 4,000,000 bytes, reports partial coverage for longer
files, and has not been locally calibrated for false-positive control. Its
published architecture is adapted for streaming exact max pooling rather than
the research training code's approximate winner-selection implementation.
Parity was checked against direct full PyTorch equations; this is not a claim
of identical output to every upstream approximation for large files.

## Installed status and measured result

The classifiers are enabled in the current user's inspection preferences.
Restart an already-open app/monitor to reload them. The Defense settings expose
separate signed-model and raw-byte neural switches. Model review warnings appear
in scan results and monitoring events with their scores.

The .NET ensemble threshold was fitted using 1,993 reserved public feature rows,
then evaluated on 4,000 separate rows: 1,783/2,000 malicious rows flagged
(89.15% recall), with 4/2,000 benign false positives (0.2%). The one-sided 95%
false-positive upper bound is approximately 0.457%. This fails the stricter
release false-positive target. It is a feature benchmark, not a raw-file or Zoo
test, and family-disjoint generalization is unestablished. Earlier pilot results
used a different split and cannot be compared as a controlled head-to-head test.

Win32/Win64 use their research review threshold until separately calibrated;
the .NET threshold is not transferred to those formats. High learned scores
produce review warnings. Neither classifier independently authorizes automatic
quarantine/deletion or becomes a release-validated detection merely by being
installed. The neural .99 review threshold is provisional research policy, not
a measured false-positive guarantee.

## Sources and reproducibility

- EMBER2024 authors: https://github.com/FutureComputing4AI/EMBER2024
- Paper: https://arxiv.org/abs/2506.05074
- Weights: joyce8/EMBER2024-benchmark-models at
  e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2 (Apache-2.0).
- MalConv2: https://github.com/FutureComputing4AI/MalConv2 at
  b5a865420e984b22a2474834bd1748318e84b553 (Apache-2.0).

`python -m tools.feeds.install_benchmark_models` downloads only the four pinned
classifier files, verifies digests, and installs a locally signed ensemble.
`python -m tools.feeds.install_neural_model` uses a weights-only PyTorch loader
for conversion to the pinned non-pickle runtime artifact.
`python -m tools.feeds.enable_learned_detection` enables the current profile.

Downloaded models, calibration data, original checkpoints, protected local
signing keys and evidence stay under F:\SentinelAV-Work. Only selected signed
public inference artifacts, public trust pins and license notices are bundled.
Local signing authenticates this reviewed installation, not an upstream vendor
signature. Training overlap with old public Zoo specimens is unknown, so a
future signature-free Zoo result must not be marketed as guaranteed hash-unseen
or training-unseen performance.

The 2026-11-04 selected Zoo evaluation
now measures the installed models on eight cached specimens. Six Windows files
crossed a threshold on complete model analysis; one additional Windows file
warned on a neural prefix. Nine eligible controls had no learned-model warnings,
with one separate structural review warning. Confirmed production detections
remained zero. These results do not pass the automatic-action release gates.

That evaluation also exposed an emulator initialization memory failure. Worker
startup now bounds native thread pools, and inference loads the exact pinned
feature source without importing the dataset/training entry points. The rebuilt
package runs both classifiers and reaches modeled APIs inside the original
1 GiB job. Unsupported APIs and execution faults remain visible coverage gaps.

# Selected Zoo evaluation — 2026-11-04

SentinelAV 0.15.0 was evaluated against eight cached, revision-pinned Zoo specimens: seven Windows PE files and one Linux Mirai file. This is a small historical selection. The full Zoo repository remains untested; training overlap with the public models is unknown.

## Results

| Measurement | Observed result |
| --- | --- |
| EMBER2024 feature ensemble | 6/7 Windows files crossed the review threshold |
| MalConv2, complete input coverage | 4/6 Windows files crossed the review threshold |
| MalConv2, partial input coverage | 1/1 additional warning |
| Either model, complete model analysis | 6/7 Windows files warned |
| Either model, including the partial warning | 7/7 Windows files warned |
| Linux Mirai | Independent classifiers unavailable for this format |
| Eligible Microsoft controls | 0/9 learned-model warnings |
| Omitted control | Notepad; control provenance/availability not established |
| Broader pipeline control warnings | 1/9; kernel32.dll structural evidence |
| Confirmed production detections | 0 |
| Automatic quarantine, blocking or removal | Not performed by this evaluation |

Warnings are research predictions and do not authorize automatic response. The models and thresholds remain unvalidated for release use. Zero learned warnings on nine controls is insufficient to establish a low false-positive rate.

| Specimen | Feature score | Neural score | Neural coverage | Emulation stop |
| --- | --- | --- | --- | --- |
| wannacry.bin | 0.9909 | 1.0000 | Complete | unsupported_api |
| emotet.bin | 0.9988 | 0.9964 | Complete | unsupported_api |
| zeusvm.bin | 0.9994 | 1.0000 | Complete | execution_fault |
| mirai.bin | Unavailable | Unavailable | Disabled | not_applicable |
| wannacryplus.bin | 0.9894 | 1.0000 | Partial | modeled_run_ended |
| gameover.bin | 0.9999 | 0.8151 | Complete | execution_fault |
| zeusbanking.bin | 0.9998 | 0.8732 | Complete | execution_fault |
| gameoveralt.bin | 0.9992 | 0.9986 | Complete | execution_fault |

Scores are uncalibrated model outputs rounded to 0.0001. WannaCry Plus examined 4,000,000 of 5,267,459 bytes; the prefix warning is not counted as complete neural coverage. The feature ensemble stayed below its unchanged 0.99 threshold for that file.

## Emulation and runtime correction

The initial run exposed UC_ERR_NOMEM failures when learned inference and Speakeasy shared the 1 GiB Windows job. The correction bounds native OpenMP/BLAS thread pools at worker startup and loads only the digest-pinned upstream EMBER feature module, avoiding unused training/download imports. Extractor semantics, model weights, thresholds and the 1 GiB job limit were preserved.

The failed run remains at F:/SentinelAV-Work/evaluations/zoo-learned-strict-7891d0ac09d64979813266c84b607d3b. It was not overwritten. A fresh offline guest reran the same specimen selection. All model scores were reproduced.

Final termination metadata: {'unsupported_api': 10, 'execution_fault': 4, 'not_applicable': 1, 'modeled_run_ended': 2}. No initialization backend_error remained. Full inspection coverage remains partial for all PE files. Unsupported APIs, execution faults and virtual run completion do not establish Windows-equivalent behavior analysis or safety. Zeus Banking recorded 10,001 resolution attempts; the final attempt needed a wider numeric metadata field and did not change the configured API budget.

## Boundary and verification

- Zoo revision: `48515e492013bc5bb2769249ea539436bb3e733f`.
- Kit: `565b49ae18ef4cabb3e5149a84b61fe7`; guest: `55de06f8-da2f-480c-86f8-121e91cae54a`.
- Networking, clipboard and device sharing disabled; a single read-only input share. Runtime checks verified guest identity, offline state, denied share writes and the harmless packaged baseline.
- Samples unpacked only in the disposable guest. Analysis was static/content inspection plus bounded virtual emulation. No native specimen execution or response actions occurred.
- All 17 imported rows retained pre/post identities and signature-free attestation: zero loaded malware hashes; YARA, test markers, AMSI and reputation disabled. SHA-256 served identity/integrity checks only.
- Fifteen focused source tests passed, including repeated combined-model/emulator scans within the worker budget. Updated metadata boundary regressions passed.
- The rebuilt package passed combined feature/neural/emulator checks and its normal protection self-test. Evidence: F:/SentinelAV-Work/evaluations/learned-package-acceptance-b08c67c5fb29450393072c02fe0826b9/report.json.
- The registered guest was discarded after evidence capture; see disposal.json. Plaintext specimens and full guest-local reports were destroyed with it. Only bounded metadata was exported.
- Exported metadata is guest-reported, not an externally attested measurement. No protection rate, training-unseen detection or Defender superiority is established.

## Evidence and next work

Host evidence directory: `F:/SentinelAV-Work/evaluations/zoo-learned-strict-058bd888bddd452795bd765f2b2f7096`. It contains the original report, diagnostic audit, control-review source flags, input manifest, boundary snapshot and disposal receipt. hashes.json records artifact identities.

Installer: `F:/SentinelAV-Work/builds/release/learned-memory-fixed/SentinelAV-Setup-0.15.0.exe`. Restart an existing SentinelAV app/engine after updating to load the runtime correction.

Next: reduce benign structural false alarms, improve the observed unsupported/faulting emulation paths, and calibrate/validate fusion on a much larger independent benign and malware corpus before enabling unfamiliar-threat automatic actions.

# EMBER2024 fine-tune: HANDOFF

Written 2026-11-13 by the fine-tune chat. Everything lives under `F:\SentinelAV-Work\finetune\`. The repository was not edited, nothing was committed, and the model is **not** wired into the product.

**Deliverable:**
- **`models/final-v2/`, the primary model and a drop-in replacement.** It has twice the new trees (made to fit by trimming text, §2), extra clean developer tools and OEM/system utilities, and EMBER's benign replay rows weighted ×2.
- **Recommended second stage: `models/final-v3/`** (§1b), which confirms final-v2's convictions. It cuts final-v2's false alarms on independent open-source tools by about two thirds for a 0.7-point detection cost.
- **The second stage needs a small product change**, described in §1b. Without it, final-v2 alone is the drop-in.

Earlier candidates are kept for comparison (§8).

**Important finding late in the work:** final-v2 convicts **72 of 725 (10%)** held-out winget packages: small, unsigned Go/Nim/Rust/Python tools from the Windows Package Manager community index. The original model convicts 36 (5%). This PC's clean files didn't show it. Read §1b before shipping final-v2 alone.

## 1. Recommendation: **YES, with conditions.** It passes all four acceptance tests. Confirm on bazaar-holdout before release.

| Acceptance test | Limit | Original | Fine-tuned (final-v2) | Result |
|---|---|---|---|---|
| 1a. Clean REPORT files at the proposed cut-offs | 0 | 0 | **0** | PASS |
| 1b. Clean REPORT files at ≥0.9 | ≤0.1% | 3 (0.065%) | **0 (0.000%)**, max 0.895 | PASS |
| 2. Dev detection at 0.98 | higher | 62.4% | **77.7%** | +15.3 points |
| 2. Dev detection at 0.9 | higher | 81.4% | **90.0%** | +8.6 points |
| 2. Dev detection at 0.5 | higher | 91.7% | **96.5%** | +4.8 points |
| 3. EMBER Dec-2024 AUC (Win32 / Win64 / .NET) | about the same | 0.99736 / 0.99840 / 0.99889 | 0.99735 / 0.99828 / 0.99886 | PASS |
| 3. EMBER Dec-2024 detection at 0.98 | about the same | 81.3 / 89.0 / 88.0% | 81.9 / 89.6 / 87.8% | PASS |
| 3. EMBER Dec-2024 false alarms at 0.98 | about the same | 0.047 / 0.080 / 0.160% | 0.040 / 0.120 / 0.200% | PASS (Win64 +0.04 points, .NET +0.04 points) |
| 3. EMBER Dec-2024 false alarms at 0.9 | about the same | 0.227 / 0.280 / 0.640% | 0.253 / 0.360 / 0.560% | PASS |
| 4. Per-type cut-offs from clean CALIBRATE data only | | | 0.98 / 0.98 / 0.98 | done (the floor binds) |

**Ship rule, fixed before the acceptance run.** final-v2 could replace the previous candidate final-dt only if:
- it passes tests 1a and 1b
- its dev detection at 0.98 is at least final-dt's (76.0%)
- its EMBER false alarms at 0.98 are no higher than final-dt's for each type (0.060 / 0.200 / 0.280%)

It met all three (77.7%; 0.040 / 0.120 / 0.200%).

**Conditions and risks, read before shipping:**

1. **The REPORT result is optimistic.** The REPORT half has been looked at five times:
   - v1: 8 files at ≥0.9
   - interim sweep-G: 4
   - `final`: 6 (a fail)
   - `final-dt`: 0
   - `final-v2`: 0

   The dev-tool data was added *because* the third look showed Git helpers, setuptools launchers and similar stubs near 0.9. Guards kept:
   - other download sources, versions not picked by looking at this PC
   - byte-identical REPORT files dropped (41 dev tools, 1 OEM)
   - all settings chosen on validation only
   - *held-out* dev-tool versions improved too (§5)

   0 at ≥0.9 is still partly a fitted result. **Treat the bazaar-holdout run and a fresh clean set, for example another PC, as the real sign-off.**
2. **Compressors and packers score high.** The held-out `zpaq.exe` (PeaZip's bundled compressor) scores 0.964, up from 0.83 with the original. It's under the 0.98 cut-off, but close. Archive and compression tools are the clean class most at risk.
3. **The dev set comes from the same months as training** (May–Nov 2026, the same campaigns), so dev gains overstate gains on future campaigns.
4. **Holdout timing:** the holdout must start at or after **2026-11-17 00:00 UTC**. The training window ends then, and the newest training sample was first seen 2026-11-10 23:36 UTC.
5. **Weak families, partly fixed:**
   - still below 0.98 on dev: wailsloader 8/8, overlordrat 4/5, snappyclient 4/4, valleyrat 5/9 (was 7/9), phorpiex 5/6
   - adware.offercore improved to 3/8 below (was 8/8)
   - the RMM tools (ConnectWise, FleetDeck, NetSupport, N-able) are unchanged on purpose: they were excluded from training to avoid false alarms on legitimate installs
   - final-v2's training malware is the 1,866 per-sample downloads. Later data (daily archives, plus 1,605 sealed but unextracted per-sample downloads) went only into final-v3 or is unused (§1b, §3).
6. **Size:** 16,608,146 of 16,777,216 chars, about 169 KB slack.
   - The model text uses a slimmed format: only the *new* trees drop the per-node training statistics (split_gain, internal_value, internal_weight, internal_count, leaf_weight, leaf_count), and the trailing feature_importances and parameters sections are gone.
   - Predictions are bit-identical, and the 500 original trees are byte-identical (`scripts/slim.py`).
   - Anything that needs those statistics on the new trees, such as SHAP via `pred_contrib`, gets less exact values for them. The product uses none of this (no `pred_contrib`, `feature_importance` or `dump_model` in `src/`).
7. **Clean Win32 data is still small:** 751 PC calibrate files, 97 installers, 432 dev-tool and 61 OEM files.
8. **Indie-software false alarms:** final-v2 alone convicts 10% of held-out winget packages at 0.98 (the original: 5%). Use the second stage in §1b, or expect review load from users of open-source tools.

## 1b. Second stage: final-v3 confirms final-v2's convictions (recommended)

**Why:**
- With the user's go-ahead, I added much more data:
  - 3,294 more MalwareBazaar samples from daily archives (training malware is now 5,160 samples)
  - 2,056 clean files from 1,200 winget packages (§3)
- A model trained on all of it, **final-v3**, has the fewest false alarms of any model: fewer than the original everywhere.
- But its dev detection at 0.98 is 70.1%, so under the rule fixed beforehand (`notes/v3-rules.md`) it does **not** replace final-v2 (77.7%).
- The user chose to keep final-v2 and add a second stage.

**Decision rule** (t chosen on validation only, by the rule written before any cascade number was computed):

```
s2 = final-v2 score (pe_ensemble.predict_vector with the final-v2 payload)
if s2 < 0.98: below review threshold (as today)
else:
    s3 = final-v3 score (same function, final-v3 payload)
    if s3 >= 0.64: Likely malicious (conviction)
    else:          Suspicious - review (flagged by the primary model, not confirmed; no conviction)
```

**t = 0.64** is the lowest t (the most detection) for which both of these hold on validation:
- held-out winget packages convicted ≤ 25 of 725
- EMBER val (2024-11-17) false alarms, per type, ≤ final-v2 alone

The full grid is in `notes/cascade-select.json`.

| Acceptance (one run) | final-v2 alone | **final-v2 + final-v3 check** | final-v3 alone |
|---|---|---|---|
| Clean REPORT convicted (4,603 files) | 0 | **0** | 0 |
| Dev convicted at 0.98 | 77.7% | **77.1%** (+0.7% to review) | 70.1% |
| Dev by type, Win32 / Win64 / .NET | 58.8 / 79.2 / 94.1% | 56.3 / 79.2 / 94.1% | |
| EMBER Dec-2024 false alarms (Win32 / Win64 / .NET) | 0.040 / 0.120 / 0.200% | **0.040 / 0.120 / 0.200%** | 0.013 / 0.020 / 0.160% |
| EMBER Dec-2024 detection | 81.9 / 89.6 / 87.8% | 81.7 / 89.5 / 87.8% | 79.1 / 83.4 / 85.5% |
| Held-out winget convicted (validation, not a test) | 72 of 725 (10%) | **25 of 725 (3.4%)** | 17 of 725 |

- **Dev samples downgraded to review:** 3 (families gh0strat, sliverfox, valleyrat). They are still shown as suspicious, not missed.
- **Results:** `notes/cascade-evaluation.json`.

**Product change needed (not made; repository is read-only):**
- `pe_ensemble.validate` and `predict_vector` work on one payload as they are.
- The product needs a second payload slot (`models/final-v3/ensemble-payload.json`, same format) and the 3-line rule above where the PE ensemble result is turned into a classification.
- Both payloads are within the loader's limits on their own.
- Cost: one more LightGBM evaluation, only for files final-v2 already flagged.

**final-v3 itself:**
- **Training data:** config W0 = final-v2's settings (w_mal 4, w_clean 25, lr 0.03, 220/320 new trees, benign replay ×2, slimmed), plus the daily-archive malware and winget clean data.
- **How it was chosen:** on validation among 6 weight settings (`notes/selection-v3.json`), where all six were eligible and W0 had the best detection.
- **Acceptance run:** clean REPORT 0 at ≥0.9 (max 0.758); dev 70.1% at 0.98 and 86.0% at 0.9; EMBER Dec-2024 false alarms below the original for every type.
- **Tables:** `models/final-v3/tables.md`.

## 2. Model files (drop-in replacement)

Folder: `F:\SentinelAV-Work\finetune\models\final-v2\`

| File | SHA-256 | Chars | Trees |
|---|---|---|---|
| EMBER2024_PE.model | 63b5c560cf90d1cb221dfd86cf7d97990edd60e457fb332adbf1a8deb4b598f5 | 4,308,531 | 820 (500 original + 320) |
| EMBER2024_Win32.model | c19925a1e022d1ff64aa7697a7e1923b8735a8706c545d573ba879259a81c3a0 | 4,111,467 | 720 (500 + 220) |
| EMBER2024_Win64.model | 194885955e58e8c5367cf6f2e9342a6e1109c0936d9cfb91269e04e2b32c2954 | 4,101,336 | 720 (500 + 220) |
| EMBER2024_Dot_Net.model | e671789dfb8342f0ad810a647ee75d222fb3344e9ff98068268e92120cd1aeee | 4,086,812 | 720 (500 + 220) |
| ensemble-payload.json | d3c4e3fe94ab794b6ce7515e5a9ce46d4ea849c62014dce813d571eb844761ee | | |

**Second stage, `models/final-v3/`** (same format, slimmed, validated and checked the same way by `package.py`):

| File | SHA-256 | Chars |
|---|---|---|
| EMBER2024_PE.model | 3e8ab7ebed27fc3c8844a0fe989012c4c721d718a4724165d57815d9b02e6119 | 4,307,128 |
| EMBER2024_Win32.model | ed488d740f6f9af659803e2f01d123c6cd8c2ba19f9e688f0bc2ba4ea398c589 | 4,110,714 |
| EMBER2024_Win64.model | a743ebdd6de5ec9be24c89a322ef76aeea153a76c44c718440e83ee08e6d7607 | 4,099,289 |
| EMBER2024_Dot_Net.model | 1600b1ca5cb5ce2b1abf4c454c6b9f8b98970da6c9cc3d80cad76da3c3238378 | 4,086,493 |
| ensemble-payload.json | 1d65ecb7af83efe5a6063da451507fcbecbb7036d934d44b7b2680c25b1a851b | |

The originals are in `F:\SentinelAV-Work\models\ember2024-published\`, with SHA-256:
- PE: 4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99
- Win32: b1e9fc174e4fcc6c0aba3ff29eb6d96ee9e240057f76940a8a1d6009ac0a4267
- Win64: 8eddddc26eb346d74810a0dfcc672342eca5709ece4da259934d6d3c77ca971b
- Dot_Net: cbd91b4a823d5dac3f56f38640a5599836501ccbd4fcce273d28c9aed0afc24c

**Format:**
- Each `.model` file is LightGBM model text, UTF-8 with `\n` line endings. It starts with `tree\n`, has 2568 features, and loads with `lightgbm.Booster(model_str=...)`.
- It is `model_to_string()` output slimmed by `scripts/slim.py` (§1, risk 6): the header's `tree_sizes` is recomputed, the original 500 trees are byte-identical to the published files, and predictions are bit-identical to the unslimmed text (checked on 5,458 rows).
- The SHA-256 of the file bytes equals the SHA-256 of the text, which is exactly what `pe_ensemble.validate` checks.

**`ensemble-payload.json`** is the unsigned `payload` object that `tools/feeds/install_benchmark_models.py` builds:
- `schema` 3, `algorithm` `lightgbm-pe-ensemble-v1`, `extractor` `ember2024-v3`, and `extractor_revision` = the repository's `FEATURE_REVISION`.
- `feature_count` 2568, and `members` {PE, Win32, Win64, Dot_Net}, each with {model_text, model_sha256, feature_count}.
- `review_threshold` 0.98 and `review_thresholds` {Win32: 0.98, Win64: 0.98, Dot_Net: 0.98}.
- `validated` false.

**Checks run by `scripts/package.py`:**
- The payload passes the repository's own `pe_ensemble.validate`.
- `pe_ensemble.predict_vector` scores 60 dev vectors **identically** (max difference 0.0) to the evaluation code.
- The total model text is ≤16,777,216 chars and each member is ≤5,242,880.

**Not done:** signing, putting it in an envelope, and activation. That is the product owner's step, normally done by adapting `install_benchmark_models.py` to read these four files. Its integrity check pins the original Hugging Face SHA-256s, so it needs a variant that pins the hashes above.

**Original trees untouched:** for every member, `predict(num_iteration=500, raw_score=True)` equals the original model's raw score exactly, checked in `train.py`. Routing and pooling are unchanged: the score is the sigmoid of the mean logit of (type specialist, PE).

## 3. Training data

All feature extraction from malware ran inside the offline Windows Sandbox. See section 6.

| Source | Rows used | Date range | Notes |
|---|---|---|---|
| MalwareBazaar Windows PE (exe, dll) | 1,866 samples: 1,683 fit + 183 validation | first seen 2026-05-01 01:41 → 2026-11-10 23:36 UTC | 341 family labels; Win32 513, Win64 970, Dot_Net 383 |
| EMBER2024 replay (train weeks) | Win32 45,000 / Win64 30,000 / Dot_Net 25,000 per specialist; PE uses 60% of each | 6 weeks: 2023-11-12, 2024-02-25, 2024-05-26, 2024-07-28, 2024-09-01, 2024-09-15 | about 50% malicious; from 72,000 / 40,002 / 60,000 rows extracted |
| This PC, clean CALIBRATE half | 4,855 fit rows (2,245 products) | | the 30% of products in the "threshold part" are held out for cut-offs only |
| Downloaded clean installers and tools | 240 fit rows (20 products); 259 extracted | downloaded 2026-11-12 | official vendor URLs and vendor GitHub releases; list in `data/clean-downloads/downloads.json` |
| Downloaded clean developer tools | 430 fit rows; 746 extracted (Win32 432, Win64 220, .NET 94); 316 held out | downloaded 2026-11-13 | see below |
| Downloaded clean OEM / system utilities | 476 fit rows; 615 extracted (Win32 61, Win64 72, .NET 482); 139 held out | downloaded 2026-11-13 | see below |
| *final-v3 only:* MalwareBazaar daily archives | 3,294 samples: 2,964 fit + 330 validation (Win32 697, Win64 1,614, .NET 983; 117 families) | 24 days, plus part of 2026-09-19/20, May–Sep 2026 | see below |
| *final-v3 only:* winget community packages | 1,331 fit rows; 2,056 extracted from 1,200 packages; 725 held out | downloaded 2026-11-13 | see below |

**Developer-tool sources:**
- python.org embeddable zips for 3.8.10, 3.9.13, 3.10.11, 3.11.9, 3.12.7 and 3.13.1 (amd64 + win32)
- PyPI wheels: setuptools 41.0.0 / 50.3.2 / 60.10.0 / 65.5.0 / 68.2.2 / 75.1.0; pip 20.3.4 / 22.3.1 / 23.3.2 / 24.2; distlib 0.3.1 / 0.3.6 / 0.3.8; virtualenv 20.0.35 / 20.26.6
- MinGit 2.30.2 / 2.39.2 / 2.45.2 (32 + 64-bit)
- Node.js 16.20.2 / 18.20.4 / 20.18.0 (x64 + x86)
- nuget.exe

All are listed in `data/clean-devtools/downloads.json`, 40 files and 485 MiB. Files byte-identical to any clean REPORT-half file were dropped (41). Held out for cut-offs (threshold part): mingit-2.30.2, python-3.10.11, python-3.11.9 and python-3.13.1.

**OEM / system-utility sources** (`data/clean-oem/downloads.json`, 21 files, 488 MiB):
- vendor URLs: Logitech G HUB, CPUID CPU-Z and HWMonitor, Lenovo System Update
- vendor GitHub releases: LibreHardwareMonitor, FanControl, System Informer, Ventoy, PowerShell 7 (x64 + x86), DriverStoreExplorer, Open-Shell, mRemoteNG, Greenshot, WinDirStat, PeaZip portable, Git Extensions portable
- byte-identical REPORT files dropped: 1
- held out: hwmonitor, greenshot, lenovo-system-update, librehardwaremonitor, peazip, systeminformer, windirstat
- deliberately left out: password-recovery and scripting tools often abused by malware (NirSoft, AutoHotkey)

**Training settings:** EMBER replay malicious rows weight 1, benign rows weight **2**; MalwareBazaar weight 4; clean weight 25 (all four clean sources); learning rate 0.03, 31 leaves. That's 220 new trees per specialist and 320 for PE. Config G plus the v2 settings were picked on validation data only (section 5).

**Daily archives (final-v3 only)** (`scripts/daily_*.py`, `scripts/sandbox_daily.py`, `guest/extract_daily.py`):
- **Source:** abuse.ch publishes one password-protected ZIP per day with every sample first seen that day (datalake.abuse.ch, 0.3–2.8 GB each). TLS is verified against the Windows certificate store.
- **Sealing:** each archive is sealed **while streaming**, in 16 MB AES-256-GCM records with per-day DPAPI-protected keys (the record's day, position and count are bound into the AAD). No plaintext byte reaches the host disk. Downloads use 6 parallel HTTP Range requests, one per record.
- **Extraction:** the offline Sandbox reads the sealed archive from a read-only mapped folder through a seekable reader that decrypts only the records it needs. It opens only members on the host's want-list and checks each one (MZ header, sha256 equal to its name). The reader was tested on the host with a *harmless* sealed ZIP of Windows system files, including tamper detection.
- **Selection** (`daily_select.py`, then `daily_replan.py`):
  - days chosen greedily by new samples per GiB to cut download time
  - families capped at 100, unlabeled at 2,000
  - dev hashes, RMM families and already-collected samples excluded
  - only days before 2026-11-17
  - plans: `data/daily/plan-v1.json`, `plan.json`, `done.json`
- **Bias:** busy campaign days are favoured, so 117 families appear in the daily set, against ~200 in a uniform plan.
- **Extra sealed samples:** a leftover collector, started on 13 Nov and stopped by me that afternoon, also sealed 1,605 more per-sample downloads into `data/bazaar-train`. They were **not** extracted or used (the user chose to train before that ~50-minute Sandbox job). On 2026-11-13 the user had all sealed samples deleted, so only their manifest entries remain.

**Winget (final-v3 only)** (`scripts/winget_collect.py`):
- **Source:** Microsoft's public package index (`cdn.winget.microsoft.com/cache/source.msix`); a seeded sample of packages, latest version each.
- **Installers:** one per package (x64 > x86); types exe, inno, nullsoft, burn, zip or portable only; ≤30 MB.
- **Checks:** every file must match the manifest's InstallerSha256 (52 mismatches discarded). Files byte-identical to REPORT-half files are dropped. Files are vectorized in memory and deleted; nothing is kept or executed.
- **Excluded from the cut-off pool:** winget held-out files are left out of the cut-off rule, because the pool's maximum is 1.0 even for the original model. They are reported separately as a false-alarm rate (`notes/v3-rules.md` addendum, written before any v3 result).

**Malware selection** (`scripts/collect.py`, seed 20261112):
- From the abuse.ch full export, Windows PE (exe, dll) first seen in [2026-05-01, 2026-11-17).
- At most 30 per family, 80 for the weak-spot families (adware.offercore, wailsloader, valleyrat, overlordrat, salatstealer, rustystealer, vshell, …), and 700 unlabeled.
- Target 3,500. MalwareBazaar answered HTTP 502 and then HTTP 429 to every download from 12 Nov onward, so 1,897 were sealed; 1,866 gave a valid PE vector.

**Exclusion lists:**
- Every sha256 in `F:\SentinelAV-Work\datasets\bazaar\dev\manifest.json` (entries + skipped, 1,000 hashes). Train rows whose PE member equals a dev member are also dropped (0 found).
- **bazaar-holdout:** never opened, listed or read.
- **RMM families, so they don't chase abused remote-access tools:** anydesk, atera, connectwise, fleetdeck, gotoassist, itarian, level, logmein, meshagent, meshcentral, netsupport, netsupportmanager, ninjarmm, pdqconnect, remotepc, remoteutilities, rustdesk, screenconnect, simplehelp, splashtop, supremo, syncro, tacticalrmm, teamviewer, zohoassist.
- **Clean REPORT half:** never trained on, and byte-identical downloads were removed. It was looked at five times (§1, risk 1).
- **No theZoo-derived data of any kind.**

**Validation sets** (used for choosing settings; not acceptance tests):
- the clean calibrate threshold part plus held-out downloads, dev tools and OEM utilities (2,715 files)
- the EMBER2024 test week 2024-11-17..23
- the 10% of MalwareBazaar training samples with `sha256('ft-val:'+sha) % 10 == 0`

## 4. Acceptance tables (original vs fine-tuned, models/final-v2)

### Cut-offs (from clean CALIBRATE threshold part + downloaded installers held out; floor 0.98)

| Type | Held-out clean files | Highest clean score, original | Highest clean score, fine-tuned | Proposed cut-off |
|---|---|---|---|---|
| Win32 | 389 | 0.840 | 0.794 | **0.98** |
| Win64 | 1305 | 0.865 | 0.964 | **0.98** |
| Dot_Net | 1021 | 0.834 | 0.621 | **0.98** |

### Test 1: clean REPORT half (4603 files; 4575 have a sha256 not in any training set)

| Files at or above | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | At proposed cut-offs | Max |
|---|---|---|---|---|---|---|---|---|
| original | 15 | 12 | 3 | 0 | 0 | 0 | 0 | 0.929 |
| finetuned | 14 | 10 | 0 | 0 | 0 | 0 | 0 | 0.895 |
| original, unseen sha256 only | 15 | 12 | 3 | 0 | 0 | 0 | | |
| finetuned, unseen sha256 only | 14 | 10 | 0 | 0 | 0 | 0 | | |

Rate at ≥0.9: original 0.065%, fine-tuned 0.000% (limit 0.1%).

Top 20 clean REPORT files, fine-tuned model:

| # | Score | Type | Product | Path | sha256 in training |
|---|---|---|---|---|---|
| 1 | 0.8950 | Win64 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\comfy_kitchen\backends\cuda\_C.abi3.pyd` | no |
| 2 | 0.8932 | Win64 | gigabyte | `C:\Program Files (x86)\Gigabyte\@BIOS\ChangeLogoWin64.exe` | no |
| 3 | 0.8621 | Win64 | git | `C:\Program Files\Git\usr\libexec\getprocaddr64.exe` | no |
| 4 | 0.8312 | Win64 | git | `C:\Program Files\Git\usr\bin\cygwin-console-helper.exe` | no |
| 5 | 0.8110 | Win32 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\setuptools\cli.exe` | no |
| 6 | 0.8019 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\PreRun.exe` | no |
| 7 | 0.7960 | Win32 | comfyui | `F:\ComfyUI-Installs\ComfyUI\ComfyUI\.venv\Lib\site-packages\setuptools\gui-32.exe` | no |
| 8 | 0.7915 | Win64 | git | `C:\Program Files\Git\usr\bin\ldh.exe` | no |
| 9 | 0.7307 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\AdjustService.exe` | no |
| 10 | 0.7045 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\UTHardwareMonitorCmd\yccV2.dll` | no |
| 11 | 0.5447 | Dot_Net | gigabyte | `C:\Program Files (x86)\Gigabyte\AppCenter\HTTP_LIB.dll` | no |
| 12 | 0.5149 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\AtiTool\tools_driver\remtool64.exe` | no |
| 13 | 0.5032 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\Sources\RPMRestoreCpl.exe` | no |
| 14 | 0.5004 | Win32 | gigabyte | `C:\Program Files (x86)\Gigabyte\RGBFusion\AtiTool\tools_driver\remtool.exe` | no |
| 15 | 0.4885 | Win64 | git | `C:\Program Files\Git\mingw64\bin\create-shortcut.exe` | no |
| 16 | 0.4657 | Win32 | git | `C:\Program Files\Git\usr\libexec\getprocaddr32.exe` | no |
| 17 | 0.4099 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\RPMExec.exe` | no |
| 18 | 0.3902 | Win64 | gigabyte | `C:\Program Files\Gigabyte\Smart Backup\RPMMgr.exe` | no |
| 19 | 0.3741 | Win64 | git | `C:\Program Files\Git\mingw64\bin\curl.exe` | no |
| 20 | 0.3700 | Win64 | comfyui | `F:\ComfyUI-Installs\ComfyUI\standalone-env\Lib\venv\scripts\nt\venvwlauncher.exe` | no |

### Test 2: MalwareBazaar dev (458 PE samples; detection = share at or above cut-off)

| Model | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | At proposed cut-offs |
|---|---|---|---|---|---|---|---|
| original | 91.7% | 88.4% | 81.4% | 76.4% | 62.4% | 55.0% | 62.4% |
| finetuned | 96.5% | 95.0% | 90.0% | 85.2% | 77.7% | 69.9% | 77.7% |

By type:

| Type | Model | n | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|---|---|
| Win32 | original | 119 | 84.9% | 77.3% | 70.6% | 67.2% | 43.7% | 32.8% |
| Win32 | finetuned | 119 | 94.1% | 91.6% | 79.8% | 72.3% | 58.8% | 45.4% |
| Win64 | original | 221 | 92.3% | 89.6% | 78.7% | 71.0% | 55.7% | 46.6% |
| Win64 | finetuned | 221 | 97.3% | 95.5% | 91.4% | 86.4% | 79.2% | 70.6% |
| Dot_Net | original | 118 | 97.5% | 97.5% | 97.5% | 95.8% | 94.1% | 93.2% |
| Dot_Net | finetuned | 118 | 97.5% | 97.5% | 97.5% | 95.8% | 94.1% | 93.2% |

Families with samples below 0.98 (fine-tuned; below / total):

wailsloader 8/8, connectwise 5/7, valleyrat 5/9, phorpiex 5/6, unlabeled-dll 5/7, gcleaner 4/7, overlordrat 4/5, snappyclient 4/4, aokigaharastealer 3/8, adware.offercore 3/8, fleetdeck 3/3, desktopstreamrat 2/4, unlabeled-exe 2/8, remusstealer 2/8, netsupport 2/3, inc 2/4, lummastealer 2/5, cloudhaze 2/4, masslogger 2/3, n-able 2/2, guloader 2/2, arkeistealer 1/2, spicerat 1/1, mopsstealer 1/3, rustystealer 1/9

Same list, original: wailsloader 8/8, adware.offercore 8/8, valleyrat 7/9, coinminer 7/9, remusstealer 7/8, gcleaner 6/7, vidar 6/8, unlabeled-exe 6/8, connectwise 5/7, phorpiex 5/6, aokigaharastealer 5/8, unlabeled-dll 5/7, overlordrat 4/5, lummastealer 4/5, snappyclient 4/4, cloudhaze 4/4, wardenstealer 3/12, wannacry 3/7, mmtwstealer 3/6, stealc 3/12, lunexloader 3/6, inc 3/4, fleetdeck 3/3, desktopstreamrat 2/4, mopsstealer 2/3

### Test 3: EMBER2024 newest test week (2024-12-08..14)

| Type | Model | AUC | Detection 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 | False alarms 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Win32 | original | 0.99736 | 96.8% | 95.1% | 89.9% | 86.3% | 81.3% | 77.4% | 2.080% | 0.993% | 0.227% | 0.127% | 0.047% | 0.007% |
| Win32 | finetuned | 0.99735 | 96.7% | 94.7% | 89.9% | 86.5% | 81.9% | 78.3% | 1.940% | 1.020% | 0.253% | 0.133% | 0.040% | 0.000% |
| Win64 | original | 0.99840 | 97.9% | 96.9% | 94.4% | 92.6% | 89.0% | 86.0% | 1.360% | 0.840% | 0.280% | 0.200% | 0.080% | 0.040% |
| Win64 | finetuned | 0.99828 | 97.8% | 96.8% | 94.7% | 92.9% | 89.6% | 86.7% | 1.340% | 0.820% | 0.360% | 0.240% | 0.120% | 0.080% |
| Dot_Net | original | 0.99889 | 98.6% | 97.4% | 94.8% | 92.2% | 88.0% | 83.4% | 1.520% | 1.040% | 0.640% | 0.400% | 0.160% | 0.120% |
| Dot_Net | finetuned | 0.99886 | 98.2% | 96.9% | 94.1% | 91.8% | 87.8% | 82.5% | 1.200% | 0.800% | 0.560% | 0.360% | 0.200% | 0.120% |

Rows per type: Win32 30000 malicious / 30000 benign, Win64 10000 malicious / 10000 benign, Dot_Net 5000 malicious / 5000 benign.

### Validation only (not an acceptance test): held-out 10% of training malware (183 rows)

| Model | 0.5 | 0.7 | 0.9 | 0.95 | 0.98 | 0.99 |
|---|---|---|---|---|---|---|
| original | 90.7% | 89.1% | 84.7% | 82.0% | 72.7% | 59.6% |
| finetuned | 95.6% | 94.5% | 89.1% | 85.8% | 80.3% | 73.2% |

## 5. How the cut-offs and settings were chosen

**Cut-offs** (`scripts/evaluate.py`, `pick_cutoffs`):
- Per type, cut-off = max(0.98, highest fine-tuned score on held-out clean calibration files of that type + 0.01), capped at 0.999.
- The held-out clean files are the 30% "threshold part" of this PC's CALIBRATE products (`sha256('ft-threshold:'+product)`), plus the downloaded installer, dev-tool and OEM products in the same part. They are never trained on.
- For final-v2, the highest held-out clean scores are 0.794 (Win32, 389 files), 0.964 (Win64, 1,305; PeaZip's `zpaq.exe`) and 0.621 (Dot_Net, 1,021). Each plus 0.01 stays below 0.98, so the 0.98 floor binds and all three cut-offs are **0.98**.
- None of these numbers came from dev, the REPORT half or the EMBER Dec-2024 week.
- The 0.98 floor is the conviction level the task named, and it equals the original's operating point, so detection gains are compared like for like.

**Training settings:**
- These stay fixed: init_model continuation, 31 leaves, min_data_in_leaf 50, feature_fraction 0.5, bagging 0.8, lambda_l2 1, deterministic, seed 20261112.
- The size budget allows about 500 new trees in total, given as 110 rounds per specialist and 160 for PE.
- I swept malware weight, clean weight and learning rate on validation data only (`scripts/select_config.py`, `notes/selection.json`):

| Config | w_mal / w_clean / lr | Held-out clean max | EMBER val FA@0.98 Win32 / Win64 / .NET | EMBER val FA@0.9 Win64 | Bazaar val det@0.98 / @0.9 |
|---|---|---|---|---|---|
| original | | 0.630 | 0.000 / 0.000 / 0.32% | 0.14% | 72.5% / 86.2% |
| A | 6 / 6 / 0.05 | 0.791 | 0.040 / 0.000 / 0.40% | 0.28% | 81.2% / 91.3% |
| C | 4 / 15 / 0.03 | 0.767 | 0.027 / 0.000 / 0.36% | 0.26% | 79.7% / 88.4% |
| E | 6 / 25 / 0.03 | 0.767 | 0.027 / 0.000 / 0.36% | 0.26% | 80.4% / 89.9% |
| **G** | **4 / 25 / 0.03** | **0.753** | **0.013 / 0.000 / 0.36%** | **0.22%** | **81.2% / 89.1%** |
| H | 4 / 40 / 0.03 | 0.813 | 0.013 / 0.000 / 0.36% | 0.26% | 79.7% / 88.4% |

- **G** had the lowest clean and EMBER false-alarm numbers, with detection equal to the best.
- The final model is G retrained on all 1,866 samples. On validation it scores det@0.98 81.4% and held-out clean max 0.754 (`notes/validation-final.json`).
- An earlier v1 run (6/6/0.05, without downloaded installers) had 8 REPORT files at ≥0.9. That result is why the clean weight was raised and installers were added.

**The dev-tool retrain (final-dt):**
- `models/final` failed 1b (6 REPORT files at ≥0.9). With the user's go-ahead, clean developer-tool packages were added (§3) with the **same settings** (G) and nothing re-tuned.
- Before the one acceptance run, it was compared on validation data only (`notes/validation-final-dt.json`):

| Model | Held-out clean ≥0.5 / max (2,576 files) | Held-out dev-tool versions ≥0.5 / max (316) | EMBER val FA@0.98 Win32 / Win64 / .NET | Bazaar val det@0.98 / @0.9 |
|---|---|---|---|---|
| original | 6 / 0.865 | 5 / 0.865 | 0.000 / 0.000 / 0.32% | 72.7% / 84.7% |
| final | 7 / 0.845 | 5 / 0.845 | 0.013 / 0.000 / 0.36% | 81.4% / 89.6% |
| **final-dt** | **2 / 0.777** | **1 / 0.777** | **0.013 / 0.000 / 0.36%** | **80.9% / 89.1%** |

- The held-out dev-tool versions (Python 3.10, 3.11 and 3.13, MinGit 2.30) were never trained on, and they improved as well. So the effect generalizes beyond the exact files added.
- Malware detection on validation cost about 0.5 points.

**The v2 sweep (final-v2)**, scored on validation only (`scripts/sweep_v2.py`, `notes/validation-v2.json`):
- **Fixed for every config:** config G, all four clean sources (now including OEM), and slimmed text.
- **Swept:** the number of new trees (110/160 or 220/320) × EMBER replay (benign weight 1 or 2; replay size ×1 or ×1.5).
- **Rule fixed before scoring:** bring EMBER validation false alarms back near the original's, and keep MalwareBazaar validation det@0.98 within 1 point of final-dt (≥79.9%).

| Config | Trees spec / PE | Replay ×, benign weight | EMBER val FA@0.98 Win32 / Win64 / .NET | EMBER val FA@0.9 Win32 / Win64 / .NET | Bazaar val det@0.98 / @0.9 |
|---|---|---|---|---|---|
| original | | | 0.000 / 0.000 / 0.32% | 0.08 / 0.14 / 0.96% | 72.7% / 84.7% |
| final-dt | 110 / 160 | 1, 1 | 0.013 / 0.000 / 0.36% | 0.11 / 0.22 / 1.00% | 80.9% / 89.1% |
| V0 | 110 / 160 | 1, 1 | 0.027 / 0.000 / 0.36% | 0.11 / 0.20 / 1.00% | 80.9% / 89.6% |
| V1 | 110 / 160 | 1, 2 | 0.000 / 0.000 / 0.24% | 0.05 / 0.14 / 0.76% | 76.0% / 86.9% |
| V2 | 110 / 160 | 1.5, 1 | 0.013 / 0.000 / 0.36% | 0.09 / 0.18 / 1.00% | 79.2% / 88.0% |
| V3 | 220 / 320 | 1, 1 | 0.040 / 0.020 / 0.40% | 0.11 / 0.24 / 1.08% | 81.4% / 90.7% |
| **V4 = final-v2** | **220 / 320** | **1, 2** | **0.027 / 0.000 / 0.32%** | **0.07 / 0.20 / 0.84%** | **80.3% / 89.1%** |
| V5 | 220 / 320 | 1.5, 2 | 0.013 / 0.000 / 0.24% | 0.04 / 0.18 / 0.80% | 79.2% / 88.0% |

V4 was the only config to meet both conditions (V0 and V3 keep detection but not the false alarms; V1, V2 and V5 lose more than 1 point). The MalwareBazaar validation set is small: 183 rows, so 1 sample ≈ 0.55 points.

## 6. Sandbox and safety notes

**How malware stayed sealed:**
- Malware was never run, unzipped or decrypted on the host.
- Each downloaded ZIP is stored sealed: AES-256-GCM with a DPAPI-protected corpus key, the same format as `zoo_inventory.seal`.
- For each Sandbox run, `scripts/sandbox_run.py` unseals in memory and re-seals with a fresh transfer key. That key is written to guest-local disk via `wsb exec`, never to a mapped folder.

**Sandbox configuration:**
- The guest config is the same as the repository's (networking, vGPU, clipboard, audio, video and printer disabled; ProtectedClient on; 4 GB).
- The guest checks that it is running as WDAGUtilityAccount and that no network adapter is up before it starts.
- `guest/extract_guest.py` opens the ZIP in memory inside the guest and writes only numeric feature rows.

**Deviation from the repository harness, approved by the user:**
- There is one **writable** mapped folder, `sandbox/out-<job>` → `C:\FT-Output`, which receives only JSON rows of 2568 floats.
- The host treats those rows as untrusted (`scripts/convert_bazaar.py` checks size, JSON, known sha256, 64-hex member hash, type, and 2568 finite floats).
- Inputs and the runtime are mapped read-only. No repository change was needed.

**Other rules followed:**
- Every run was checked first: no Sandbox running (`wsb list --raw`), no repository harness running, and C: had ≥10.5 GiB free.
- The lock `SANDBOX-IN-USE.txt` was held for the whole run and removed afterwards.
- Defender was not touched. The abuse.ch key was read only from the environment and never printed.
- TEMP, TMP and PIP_CACHE_DIR pointed under `finetune\tmp`.

**Guest runtime:** `guest/` is a copy of the repository's Python 3.12 and the needed site-packages. It was verified to give byte-identical vectors to the repository extractor (`scripts/check_runtime.py`, `compare_runtime.py`). EMBER features are thrember `features.py`, pinned by `FEATURE_SOURCE_SHA256`.

## 7. Reproduce

Interpreter: `C:\Users\pc\Downloads\sqlilab\sentinelav\.venv\Scripts\python.exe -I` (nothing was installed into it; LightGBM, numpy and pefile are already there). Run from `F:\SentinelAV-Work\finetune`, with TEMP and TMP set to `F:\SentinelAV-Work\finetune\tmp`.

```bash
# features
python -I scripts/extract_clean.py --split calibrate      # features/clean/clean-calibrate.npz (this PC)
python -I scripts/extract_clean.py --split report         # features/clean/clean-report.npz
python -I scripts/ember_replay.py --what replay             # features/ember/replay-*.npz
python -I scripts/ember_replay.py --what val             # features/ember/val-2024-11-17-*.npz
python -I scripts/ember_replay.py --what test             # features/ember/test-2024-12-08-*.npz
python -I scripts/download_clean.py                     # data/clean-downloads (internet)
python -I scripts/extract_downloads.py                  # features/clean/clean-downloads.npz
python -I scripts/download_devtools.py                  # data/clean-devtools (internet)
python -I scripts/extract_downloads.py clean-devtools devtools dev:   # features/clean/clean-devtools.npz (drops REPORT duplicates)
python -I scripts/download_oem.py                       # data/clean-oem (internet)
python -I scripts/extract_downloads.py clean-oem oem oem:            # features/clean/clean-oem.npz
python -I scripts/collect.py --workers 2 --delay 2      # data/bazaar-train (needs ABUSECH_AUTH_KEY; resumable)
python -I scripts/sandbox_run.py --corpora dev --job dev1
python -I scripts/sandbox_run.py --corpora train --job train1
python -I scripts/sandbox_run.py --corpora train --job train2 --skip-done train1
python -I scripts/convert_bazaar.py dev1 train1 train2  # features/bazaar/{train,dev}.npz
# settings sweep (validation only)
python -I scripts/select_config.py A C E G H
# v2 sweep (validation only); trains + slims models/v2-V0..V5
python -I scripts/sweep_v2.py
# final model = V4 (uses calibrate + downloads + devtools + oem clean data automatically when the npz files exist)
python -I scripts/train.py --run final-v2 --members Win32,Win64,Dot_Net --rounds 220 --w-mal 4 --w-clean 25 --lr 0.03 --w-replay-benign 2
python -I scripts/train.py --run final-v2 --members PE --rounds 320 --w-mal 4 --w-clean 25 --lr 0.03 --w-replay-benign 2
python -I scripts/slim.py final-v2                      # trims text; checks original trees and predictions unchanged
# acceptance tests, tables, drop-in payload
python -I scripts/evaluate.py --run final-v2            # models/final-v2/evaluation.json
python -I scripts/handoff_tables.py final-v2            # models/final-v2/tables.md
python -I scripts/package.py final-v2                   # ensemble-payload.json, SHA256SUMS.txt
```

**final-v3 and the second stage:**

```bash
python -I scripts/daily_select.py                       # data/daily/plan-v1.json (45 days, uniform)
python -I scripts/daily_replan.py --budget-gib 15       # data/daily/plan.json (efficiency-ranked days; needs data/daily/day-sizes.json)
python -I scripts/daily_pipeline.py --batch 3 --max-sealed 4   # download+seal (daily_fetch.py) and Sandbox extraction (sandbox_daily.py); resumable
python -I scripts/convert_daily.py dailysmoke daily1 daily2 daily3 daily4 daily5 daily6 daily7 daily8 daily9   # features/bazaar/daily.npz
python -I scripts/winget_collect.py --packages 1200 --workers 3   # features/clean/clean-winget.npz
python -I scripts/sweep_v3.py                           # trains + slims models/v3-W0..W5 (validation only)
python -I scripts/select_v3.py                          # applies notes/v3-rules.md -> W0
python -I scripts/train.py --run final-v3 --members Win32,Win64,Dot_Net --rounds 220 --w-mal 4 --w-clean 25 --lr 0.03 --w-replay-benign 2
python -I scripts/train.py --run final-v3 --members PE --rounds 320 --w-mal 4 --w-clean 25 --lr 0.03 --w-replay-benign 2
python -I scripts/slim.py final-v3
python -I scripts/evaluate.py --run final-v3 && python -I scripts/handoff_tables.py final-v3 && python -I scripts/package.py final-v3
python -I scripts/cascade.py select                     # t on validation -> notes/cascade-select.json (t = 0.64)
python -I scripts/cascade.py evaluate                   # one acceptance run -> notes/cascade-evaluation.json
```

Reproducing final-v2 *after* the new data exists needs `--no-daily --no-winget` on its two `train.py` lines. `features/bazaar/train.npz` (1,866 samples) is the per-sample training set it used; `data/bazaar-train/manifest.json` now also lists the 1,605 unused sealed samples.

**Earlier candidates:**
- `models/final-dt`: `--run final-dt --rounds 110` (specialists) / `160` (PE), `--no-oem`, no `--w-replay-benign`, no slimming.
- `models/final`: the same as final-dt, plus `--no-devtools`.

(final-v2 was produced as `models/v2-V4` by the sweep and copied; the commands above are equivalent.)

LightGBM runs with `deterministic=True` and a fixed seed, so a rerun on the same feature files gives the same trees.

**Bit-exact reproduction needs the MalwareBazaar feature rows.** Their file names list depends on what MalwareBazaar served before it blocked us, and is recorded in `data/bazaar-train/manifest.json`.

## 8. What is left on disk

| Path | What it is |
|---|---|
| `models/final-v2/` | **the deliverable**, primary model (4 models, payload, SHA256SUMS, evaluation.json, tables.md, train-log.json) |
| `models/final-v3/` | **the second stage** (§1b), same contents |
| `notes/v3-rules.md`, `selection-v3.json`, `cascade-*.json` | v3 and cascade rules (written before results) and their results |
| `data/daily/`, `data/winget/` | plans and logs only (no archives or installers kept) |
| `models/final-dt/` | previous candidate (passes, but more old-data false alarms; dev 76.0% at 0.98) |
| `models/final/` | the same settings without dev tools (fails 1b; kept for comparison) |
| `models/sweep-G/` | the interim model |
| `features/` | all feature matrices (no malware bytes) |
| `data/bazaar-train/` | `manifest.json` only (SHA-256, family and date of all 3,502 collected samples; 1,605 were never extracted). The sealed samples and their key were deleted on the user's request on 2026-11-13 |
| `data/clean-downloads/`, `clean-devtools/`, `clean-oem/` | `downloads.json` only (URL + SHA-256 per file); the installers were deleted after feature extraction |
| `guest/` | the Sandbox runtime |
| `scripts/`, `logs/`, `notes/` | code, logs, selection results |

**Deleted:**
- the other sweep models (A, C, E, H, v1, v2-V0..V5, v3-W0..W5) and the `.full` pre-slim copies
- the Sandbox kit folders and every sealed daily archive with its key
- the downloaded installers and scratch arrays in `tmp/`

`sandbox/out-*` keeps the raw feature rows from the guest. All sealed malware (per-sample and daily) has been deleted; the features needed to retrain are all in `features/`. The folder is about 3.9 GB.

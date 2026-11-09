# SentinelAV 0.17.0 evaluation: 9 November 2026

## Results

**On 172 malware archives from families never used for tuning, the full product flagged 68.0%. With no hashes or family rules, it flagged 64.0%.** It flagged none of 3,201 legitimate files from separate products, and 25 of 54,801 files on a real development PC.

| Measurement | Result |
| --- | --- |
| Malware archives flagged, full product | **117/172 (68.0%)**, of which 88 (51.2%) rated Malicious |
| Malware archives flagged, generalized (no hashes or family rules) | **110/172 (64.0%)**, of which 58 (33.7%) rated Malicious |
| Malware archives flagged, heuristics and generic rules only | **49/172 (28.5%)**, of which 21 (12.2%) rated Malicious |
| Windows programs flagged, generalized | **288/367 (78.5%)**, of which 97 rated Malicious |
| Legitimate files flagged | **0/3,201** (95% upper bound 0.094%) |
| Automatic quarantine candidates among legitimate files | **0/3,201** |
| Legitimate files flagged on a real development PC | **25/54,801 (0.05%)**: 3 Malicious, 22 Suspicious |
| Quarantine, restore and delete cycles on real samples | **24/24** |
| Real-time checks on real samples | **12/12 detected**, median 2.3 s; 7 automatically quarantined, in 1.5 to 6.7 s |

No sample was executed. No Zoo sample name, hash or result is used in detection logic, and a test enforces this.

These numbers come from a small public corpus of mostly old malware. They are not a measure of protection against current threats, and they do not show SentinelAV can replace commercial antivirus.

## How to read these numbers

- **Flagged is not the same as acted on.** Flagged includes Suspicious, which only alerts a person. Automatic action needs Malicious with a score of 85 or more and High confidence, so most unfamiliar threats are reported rather than removed automatically.
- **The archive rate is the main measure.** The sample rate (40.9% in the generalized arm) is distorted. One archive, AndroRat, contributed 257 of the 801 samples, all of them unreadable because of a password mismatch in the harness. All 257 count as not detected.
- **Learned models do most of the generalized work.** Removing them drops the archive rate from 64.0% to 28.5%. Their training data may overlap these samples, and that overlap is unknown, so the generalized rate may be optimistic. The heuristics-only arm has no such overlap.
- **Hashes and family rules added 7 archives** beyond generalized detection. The hash database comes from MalwareBazaar, an independent feed, and may contain Zoo samples for that legitimate reason.
- **The false-positive sample is skewed.** See [False positives](#false-positives).

## Method

**Malware corpus:** [theZoo](https://github.com/ytisf/theZoo) at commit `48515e492013bc5bb2769249ea539436bb3e733f`.

**Isolation:**
- Each batch ran in a fresh, offline Windows Sandbox that was discarded afterwards.
- Archives stayed on the host only as Git objects and AES-256-GCM ciphertext, and were decrypted only in the guest.
- Evidence left the guest through a one-way channel of process exit codes, with no writable host share.
- Host antivirus was never disabled or given exclusions.

**Tuning separation:**
- Families were split by a hash of their name: 30% for tuning (dev) and 70% for holdout. Families examined in earlier work were forced into dev.
- A family is never on both sides, though grouping is by folder name, so aliases of one family could still be split.
- Rules and thresholds were tuned on dev only. Holdout results were read once, after the code was frozen, and nothing was tuned afterwards.

**Three arms from one scan:** each file's evidence is tagged by source and re-scored for the full product, for generalized detection, and for heuristics alone.

**Counting:** files that could not be assessed stay in the denominator as not detected. Archives holding only inert content, such as images, are excluded.

**False positives:** whole products were assigned to a calibration half or a report half by a hash of the product name, and sampled per product and file type. Personal folders are refused.

## Detection by platform

Holdout archives flagged. Platforms are taken from folder names, so this grouping is approximate.

| Platform | Archives | Full product | Generalized | Heuristics only |
| --- | ---: | ---: | ---: | ---: |
| Windows | 81 | 67 | 64 | 22 |
| Unlabeled (mostly Windows and DOS) | 60 | 35 | 32 | 13 |
| Office macro | 9 | 4 | 4 | 4 |
| Script | 8 | 4 | 4 | 4 |
| macOS | 6 | 2 | 1 | 1 |
| Linux | 4 | 1 | 1 | 1 |
| Android | 3 | 3 | 3 | 3 |
| Other | 1 | 1 | 1 | 1 |

Small rows are only indicative. Source-code archives are reported separately because they hold text rather than programs: 32/70 flagged by the full product, 30/70 generalized and 22/70 by heuristics alone.

## What it missed

The full product missed 55 of 172 archives.

| Cause | Archives | Examples of the type |
| --- | ---: | --- |
| No analyzer for the file type | 15 | Boot-sector and disk images, unknown binary data |
| Windows program with too little static evidence | 10 | Targeted implants with ordinary-looking structure |
| Could not open or inspect | 4 | Password mismatch, damaged archives |
| Old DOS programs | 6 | Little structure to analyze |
| Word 6 macro viruses | 4 | Scored 28; the legacy trigger alone stays below Suspicious |
| HTML with scripts | 4 | Behavior not matched by rules |
| Nested archives with nothing flagged inside | 4 | |
| macOS and other data files | 4 | |
| Java | 2 | Few static signals |
| Other single cases | 2 | Batch, Linux |

## False positives

**Report half (never used for tuning), commit `3040509`:**

| Group | Flagged | 95% upper bound |
| --- | ---: | ---: |
| All files | 0/3,201 | 0.094% |
| Signed executables | 0/2,844 | 0.105% |
| Unsigned executables | 0/113 | 2.616% |

Four files over the size limit were omitted. The scan took 39 minutes, with a median of 0.28 s per file.

**This sample flatters the product:**
- 77% of the files come from System32, and most executables are signed by large vendors.
- It holds only 2 PDFs, 8 RTF files and 3 Office files.
- Unsigned software, where false alarms are most likely, has a much wider bound: up to 2.6%.
- Files are presumed benign, not independently verified.

**A more realistic check found more:** see [Real Quick scan](#real-quick-scan).

## Removal and real-time protection

Run on real detected samples inside the guest:
- **Removal:** each of 24 cycles quarantined a sample, confirmed the original was gone and no plaintext sample bytes were in the vault, restored it with a matching hash, quarantined it again and deleted it.
- **Real-time:** a sample was dropped into a watched folder 12 times. All 12 were detected, and the 7 that met the automatic policy were quarantined. The other 5 alerted only, as designed.

On harmless fixtures, with nothing mocked, `verify_protection_cycle` passes 17 of 17 checks and `verify_proposal_items` passes 16 of 16.

## Real Quick scan

A read-only Quick scan of this development PC, on the frozen detection code, is the most realistic false-positive check here, because it covers everyday downloads, temporary files and developer tools. It inspected 54,801 files in 36 minutes without a crash or cutoff, but it comes from one machine, and that machine holds unusual security tooling.

**25 legitimate files were flagged (0.05%): 3 Malicious and 22 Suspicious.** Another 176 findings were this project's own harmless test fixtures, and they were flagged correctly.

| Files | Verdict | Why |
| --- | --- | --- |
| `generic_techniques.yar`, SentinelAV's own rule file | Malicious, 99 | It contains the patterns it looks for |
| Compiled copy of SentinelAV's string rules | Malicious, 74 | Same reason |
| Inno Setup `whatsnew.htm`, a changelog | Malicious, 70 | **Rule weakness:** text describing downloads and Startup reads like a script |
| 7 Inno Setup uninstaller and setup stubs | Suspicious, 45 | They embed a program and use autorun and self-copy, as droppers do |
| 5 other compiled Python files, including SentinelAV's rules and analysis libraries | Suspicious, 37 to 55 | Their text mentions the behaviors they detect or handle |
| 4 Python `setuptools` launcher stubs | Suspicious, 35 | The model gives an elevated score |
| 2 browser translation packs | Suspicious, 35 | The ransom-wording rule matches ordinary strings |
| An unpackaged SentinelAV build | Suspicious, 51 | Model score plus a large overlay |
| qBittorrent installer temp copy | Suspicious, 40 | Autorun and mail-protocol strings |
| A course PDF and a ZIP of course PDFs | Suspicious, 38 to 46 | They do contain JavaScript set to run on open, so the description is accurate |

**One of these met the automatic quarantine score:** the rule file, with score 99 and High confidence. It was protected only because response actions refuse the project folder. **A copy of these rules, or of similar security research text, in a watched folder could be quarantined automatically.** It can be restored, but people who keep such files should exclude that folder.

None of these were tuned away, because the code was already frozen. They are known weaknesses of this version.

## Disclosures

**The holdout was started three times.** Each earlier attempt was stopped and fixed without any detection results being read, and is marked `ABANDONED.txt` in its log folder:
1. The first batch crashed on a corrupt archive member. This exposed a real evasion bug, now fixed: one damaged member could hide the rest of an archive.
2. The next attempt was stopped when a real Quick scan showed ordinary PDFs being flagged. A rule was searching compressed bytes. The same pass fixed Word's template name being treated as macro replication, and sampling that had included almost no documents.

**The measured code was frozen at `3040509`,** tagged `eval-freeze-holdout`, for both the holdout and the report-half scan.

**One later change is in the shipped code:** commit `5285b71` reports an unavailable model once per scan rather than as an error on every file. It changes only reporting when a model is missing, and verdicts are unchanged when one is present, as in these runs. The installer verification ran on this final build.

**Two hashes were removed.** An earlier pass had added ZeusVM and Gameover hashes taken from theZoo itself. They were revoked before these runs.

**The benign tuning loop used the same machine.** Calibration products are separate from report products, but they share this PC's software mix.

**Tuning-set results, for comparison:** on the final dev run, before the last PDF and macro fixes, the full product flagged 79.5%, generalized 71.6% and heuristics alone 42.0%. The drop to holdout is what tuning on known data looks like, which is why only the holdout is reported as the result.

## Limits

- **Old corpus:** much of theZoo is years or decades old, so it says little about current threats. It also holds malware that public hash feeds know well.
- **Static analysis only:** behavior that appears only at runtime is invisible to file scanning. Behavior monitoring reports suspicion, not proof.
- **No blocking before execution:** files are checked right after they are written. Blocking first would need a signed kernel driver.
- **Not covered:** boot-sector and disk images, CAB, ISO, and RAR unless an `unrar` tool is installed.
- **Weak areas:** macOS, Linux and Java have few rules and no learned model. Old DOS and Word 6 viruses have little to analyze.
- **Signed malware:** a valid signature holds heuristic-only files below Suspicious, so malware with a stolen certificate can pass unless a model objects.
- **Model expiry:** the signed PE model expires around February 2027. Model detection then stops, with a visible warning, until a newer signed model is installed.
- **Tamper resistance:** same-account malware or an administrator can interfere with the vault and the app.
- **Speed:** a Quick scan of 54,801 files took 36 minutes, so a Full scan can take hours.
- **False positives on security text:** files that describe malware behavior, including rule files and analysis tools, can be flagged, and a few can reach the automatic quarantine score.

## Reproduce

Evidence is on this machine, because logs and evaluation output are not in Git:

| Run | Location |
| --- | --- |
| Holdout | `logs/2026-11-09_18-02-33-fdd12bdf8792` |
| Final tuning run | `logs/2026-11-09_15-33-00-9301ae75a3c0` |
| False positives, report half | `F:\SentinelAV-Work\evaluations\benign-report-b41ea8fdedac4d04a8088af8f6c54c1d` |

To repeat the runs, follow [Evaluating against theZoo](../README.md#evaluating-against-thezoo). Holdout results are only meaningful once per frozen rule set, because reading them and then tuning turns them into tuning data.

# Real-sample static comparison — 2026-11-03

**Finding: detection in this selected corpus depends heavily on exact hashes.**
Normal definitions produced detections for all six samples. Disabling all exact
hash signatures left one detection, with inspection omissions, and five misses.
This does not establish unknown-malware protection.

| Repository-labelled sample | Normal definitions | All exact hashes disabled |
| --- | --- | --- |
| WannaCry | Detection with omissions; hash and YARA | Detection with omissions; YARA |
| Emotet | Hash detection | Not detected |
| ZeusVM | Hash detection | Not detected |
| Linux Mirai | Hash detection | Not detected |
| WannaCry Plus | Hash detection | Not detected |
| Zeus Gameover | Hash detection | Not detected |

The two additional samples are named `holdout` in existing tools, but were used
in earlier project evaluations. They are not an independently unseen holdout.
Mirai is a Linux sample; its static result should not be treated as a test of
Windows runtime protection. The small historical corpus is not representative
of the malware population, so these counts are not a product detection rate.

## Method

The already-acquired pinned archives from theZoo revision
`48515e492013bc5bb2769249ea539436bb3e733f` stayed AES-GCM sealed on the host.
Only the verified offline Windows Sandbox guest decrypted and unpacked selected
members. Archive/member identities were verified before inspection; scanned
sample fingerprints were unchanged afterwards. No new sample was downloaded.

Both passes used identical YARA/content/document settings. Emulation, model,
reputation and host AMSI integration were disabled. The second pass pointed to
a separate empty signature directory with no SQLite feed. Every scanned row
had an index count of zero: outer and derived-content exact hashes were both
disabled. No trust exclusion, installed-definition edit, new rule or threshold
change was used. Two harmless regression cases verify the ablation removes
exact matches while preserving actual content/YARA inspection.

The guest-image plan included ten Windows controls per corpus run. Nine eligible
signed controls produced no detections in either pass; the planned Notepad
control was unavailable. Those repeated runs do not constitute twenty distinct
benign controls. Unavailable results were not counted as clean.

## Isolation and evidence

The evaluated guest passed VM identity, kit checksums, packaged self-tests,
offline-adapter and denied host-share-write checks. Networking, clipboard and
device sharing were disabled; the only host mapping was read-only. Inspected
malware samples were never launched natively. This was static inspection, not a
behavioral prevention or emulator evaluation.

Only bounded outcome flags and SHA-256 metadata returned to the host. The guest
containing unpacked samples was discarded. A replacement guest passed the fresh
offline baseline; the evaluated guest ID differs from the replacement ID.
No Windows security policy was weakened and no sample was restored around an
antivirus block. A verified configuration is not a guarantee against VM escape.

Combined evidence:
`artifacts/evaluations/real-static-comparison-20261103.json`

Per-file host metadata:
`artifacts/evaluations/before-emulation-static-corpus-result.json` and
`artifacts/evaluations/before-emulation-static-holdout-result.json`.

Guest disposal evidence:
`artifacts/evaluations/real-corpus-disposal.log` and
`artifacts/lab/windows-sandbox/reset-validation.json`.

Ten targeted corpus/ablation tests passed. The current application was rebuilt
and passed the guest bootstrap checks. The release installer was not published.

## What this means

The exact-hash layer is useful for these known samples, but the tested
static/content pipeline missed five when their hashes were unavailable.
Behavioral detection and bounded emulation were not tested here and cannot be
credited with preventing those misses. Next: evaluate bounded emulation against
the missed samples with hashes still disabled, retaining unsupported-API and
unpacking omissions rather than promoting heuristic review signals to detections.

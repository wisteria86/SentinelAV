# SentinelAV

Windows malware detection, protection and removal, version 0.17.0. It is not a replacement for
Microsoft Defender or commercial antivirus; see [how it detects threats and its limits](docs/DETECTION.md).

Repository: [wisteria86/SentinelAV](https://github.com/wisteria86/SentinelAV).

Start here: [module interaction diagrams](map.md).
For the folder layout, see [project structure](docs/PROJECT-STRUCTURE.md).
First-party code files are at most 250 lines and start with purpose/collaborator
comments. Run `.\.venv\Scripts\python.exe tools/maintenance/check_structure.py`
to check those conventions; `test.ps1` also runs the check.
Browse the [documentation index](docs/README.md) for the other guides.
Read the [evaluation report](docs/EVALUATION-2026-11-09.md) for measured detection and false-positive rates.
See the [proposal audit](docs/PROPOSAL-AUDIT.md) for the current requirement map,
validation evidence, and remaining effectiveness limits.
The historical [first-iteration contract](docs/FIRST-ITERATION.md) records earlier
user paths, dependencies and supported limits.
For capabilities and unfinished protections, read [defense status](docs/DEFENSE-IMPLEMENTATION.md).

## Run

For critical product evaluation, double-click **Run-SentinelAV-Tests.cmd**.
Read the [evaluation guide](docs/CRITICAL-EVALUATION.md) for corpus approval,
guest telemetry, dedicated VM enrollment, blocked qualification and report limits.
Reports are written under `logs`; heavy lab material remains on F:.

For a fresh checkout:

```powershell
git clone https://github.com/wisteria86/SentinelAV.git
cd SentinelAV
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements/requirements.txt
```

Open PowerShell in this folder and run:

```powershell
.\start.ps1
```

The existing desktop BAT still uses the root `app.py` launcher. The virtual
environment remains in `.venv`. Application history, preferences, and quarantine
remain in the existing Windows user-data directory; reorganizing source does
not move or reset them.

The repository includes source, reviewed YARA rules/licenses, and the small
hash overlay. Full downloaded feeds/databases, build tools, installers, local
reports, original reference attachments, and signing certificates/private keys
are local-only and excluded from Git. Import a full feed separately using
[the hash-import guide](docs/HASH-IMPORT.md). Local feed-count/build-validation
records describe this development machine, not a fresh clone.

## Folder guide

| Folder | Contents |
| --- | --- |
| `native/amsi/` | Native x64 AMSI provider and harmless local harness |
| `src/sentinelav/` | Application code, grouped by responsibility |
| `resources/` | Rules, signature database, assets, trust configuration, runtime PowerShell helper |
| `tests/` | Unit, UI, and packaged integration checks |
| `scripts/` | Hash download and service deployment/installer verification scripts |
| `tools/` | Feed/evaluation command-line tools and local build-tool binaries |
| `docs/` | Architecture, feature guides, limitations, and release notes |
| `requirements/` | Runtime, pinned, and build dependencies |
| `packaging/` | PyInstaller and Inno Setup definitions |
| `data/` | Downloaded hash-feed candidates and rule-review material |
| `artifacts/` | Builds, installers, logs, screenshots, evaluations, and migration backup |

## Test and build

```powershell
.\test.ps1          # Structure and hardcoding guards, then unit tests
.\test.ps1 -UI      # Those, plus all UI checks
.\build.ps1 -Installer
```

End-to-end checks on harmless files, with nothing mocked. Run them with `PYTHONPATH` set to
`src;.` and `TEMP` on the work drive, because response actions refuse paths inside the project:

```powershell
.\.venv\Scripts\python.exe -m tests.integration.verify_protection_cycle
.\.venv\Scripts\python.exe -m tests.integration.verify_proposal_items
```

Scan from the command line with `app.py --scan quick`, `--scan full` or `--scan "<path>"`.

The packaged app is in `F:\SentinelAV-Work\builds\dist\SentinelAV\`. Installers are in
`F:\SentinelAV-Work\builds\release\`. Tests use F: for temporary fixtures
(`test.ps1 -TempRoot <absolute path>` overrides this explicitly). Run hash download from the project root with
`.\scripts\Download-Hashes.ps1`, or use
`.\.venv\Scripts\python.exe -m tools.feeds.download_hashes --help`.

See [the detailed feature guide](docs/FEATURES.md),
[hash imports](docs/HASH-IMPORT.md), and
[release notes](docs/RELEASE-NOTES.txt).

Native AMSI development: [implementation and test commands](docs/AMSI-PROVIDER.md). The provider remains unregistered.

Guest-only AMSI/service integration, reset, removal and rollback results:
[validation guide](docs/GUEST-AMSI-VALIDATION.md). Host deployment remains inactive.
## Evaluating against theZoo

All of this runs in a fresh, offline Windows Sandbox for each batch. Samples are never
launched and are never decrypted on the host. The host holds them only as Git objects and
as AES-256-GCM ciphertext while staging, and evidence leaves the guest through a one-way
channel. Do not disable or add exclusions to your antivirus for this.

You need a bare clone at `F:\SentinelAV-Work\datasets\theZoo.git` containing commit
`48515e492013bc5bb2769249ea539436bb3e733f`, and at least 10 GiB free on the system drive.

```powershell
git clone --bare https://github.com/ytisf/theZoo.git F:\SentinelAV-Work\datasets\theZoo.git
.\.venv\Scripts\python.exe -m tools.evaluation.critical_harness --profile zoo-quick --headless
.\.venv\Scripts\python.exe -m tools.evaluation.critical_harness --profile zoo-dev --headless
.\.venv\Scripts\python.exe -m tools.evaluation.critical_harness --profile zoo-holdout --headless
```

Set `PYTHONPATH` to `src;.` first when running these from a terminal.

| Profile | Use |
| --- | --- |
| `zoo-quick` | Four cached specimens, to prove the pipeline works |
| `zoo-dev` | Families used for tuning general rules |
| `zoo-holdout` | Families never used for tuning. Run it once, after freezing the code; only this gives a reportable rate |
| `zoo-static` | Everything |

Families are split deterministically by name, and a family is never on both sides. Each
result is reported three ways: the full product, generalized detection with no hashes or
family rules, and heuristics alone without the learned models. Files that could not be
inspected stay in the denominator and count as not detected.

Reports are written under `logs`. Resume an interrupted run with `--resume "<run folder>"`.

`tools/maintenance/check_no_zoo_hardcoding.py`, which `test.ps1` also runs, fails if a Zoo
sample name or blob identity appears in detection logic.

## Measuring false positives

```powershell
.\.venv\Scripts\python.exe -m tools.evaluation.evaluate_false_positives --split calibrate
.\.venv\Scripts\python.exe -m tools.evaluation.evaluate_false_positives --split report
```

This reads installed software without running it. Whole products are assigned to one half,
so rules tuned on `calibrate` are measured on products they have never seen. It refuses
personal folders such as Documents and Desktop.

# SentinelAV

Windows desktop endpoint-protection research prototype, version 0.16.0.

Repository: [wisteria86/SentinelAV](https://github.com/wisteria86/SentinelAV).

Start here: [module interaction diagrams](map.md).
For the folder layout, see [project structure](docs/PROJECT-STRUCTURE.md).
First-party code files are at most 250 lines and start with purpose/collaborator
comments. Run `.\.venv\Scripts\python.exe tools/maintenance/check_structure.py`
to check those conventions; `test.ps1` also runs the check.
Browse the [documentation index](docs/README.md) for the other guides.
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
.\test.ps1          # Unit tests
.\test.ps1 -UI      # Unit tests and all UI checks
.\build.ps1 -Installer
```

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
## Zoo static evaluation

Double-click **Run-SentinelAV-Quick-Zoo.cmd** for one offline Sandbox run using
four pinned, cached Zoo specimens. It saves its own report under `logs` and
ends after that batch. The first run after source changes may rebuild SentinelAV.

Start the profile with `.\Run-SentinelAV-Tests.cmd --profile zoo-static`.
The profile expects a local bare checkout of theZoo at `F:\SentinelAV-Work\datasets\theZoo.git`
containing commit `48515e492013bc5bb2769249ea539436bb3e733f`. The harness reads that
commit's pinned Git tree inventory, freezes it in the run manifest, and stages encrypted ZIP
blobs in batches of four. It has no automatic download step.

Each batch uses a fresh offline Windows Sandbox. The guest decodes members under inert
generated names and invokes the inspection worker with all signature sources and emulation
disabled. The report and JSONL ledger record the outcome for each inspected member.
The scanner covers Windows PE and supported active content. Other formats, corrupt or
unsupported archives, and inputs above the bounded archive or member limits are recorded
separately. The current limits are 64 MiB per archive, 24 members per archive, and 64 MiB
per member. If members cannot be enumerated within those limits, the ledger records the
archive-level failure.

Resume an interrupted run with `--profile zoo-static --resume "<run folder>"`.
The queue preserves completed batches and restarts an interrupted batch in a fresh guest.

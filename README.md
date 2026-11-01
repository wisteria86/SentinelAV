# SentinelAV

Windows desktop endpoint-protection research prototype, version 0.12.0.

Repository: [wisteria86/SentinelAV](https://github.com/wisteria86/SentinelAV).

Start here: [project map and reading order](docs/PROJECT-STRUCTURE.md).
Browse the [documentation index](docs/README.md) for the other guides.
For capabilities and unfinished protections, read [defense status](docs/DEFENSE-IMPLEMENTATION.md).

## Run

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

The packaged app is in `artifacts/dist/SentinelAV/`. Installers are in
`artifacts/release/`. Run hash download from the project root with
`.\scripts\Download-Hashes.ps1`, or use
`.\.venv\Scripts\python.exe -m tools.feeds.download_hashes --help`.

See [the detailed feature guide](docs/FEATURES.md),
[hash imports](docs/HASH-IMPORT.md), and
[release notes](docs/RELEASE-NOTES.txt).

Native AMSI development: [implementation and test commands](docs/AMSI-PROVIDER.md). The provider remains unregistered.

# Project map

Follow [map.md](../map.md) for runtime interactions and module import diagrams.
First-party code files are limited to 250 lines. Each starts with purpose and
collaborator comments; `test.ps1` enforces the size/header check.

All SentinelAV application files live in this project folder. The SQL injection
lab in the parent directory is a separate project.

```text
sentinelav/
├── README.md                  Start here
├── app.py                     Stable source launcher (also used by desktop BAT)
├── start.ps1                  Start the desktop app
├── test.ps1                   Run checks
├── build.ps1                  Build executable / installer
├── pyproject.toml             Python package metadata
├── src/sentinelav/
│   ├── entrypoint.py          GUI, worker, service and scheduled execution modes
│   ├── paths.py               Shared source / packaged resource paths
│   ├── ui/                    Windows, page mixins, styling and Qt workers
│   ├── detection/             Hash/YARA scanning, archives, formats, isolated worker, memory
│   ├── monitoring/            Filesystem/process monitoring, behavior and background host
│   ├── response/              Quarantine, restore, process response and policy
│   ├── platform/              Windows integration, AMSI consumer, service, ACLs, identity
│   ├── updates/               Definition maintenance and CSV ZIP import
│   ├── data/                  SQLite storage and report rendering
│   └── lab/                   Built-in harmless simulations
├── resources/
│   ├── assets/               Icons and SVGs
│   ├── rules/                File rules, memory candidate rules, catalogs and licenses
│   ├── signature-data/       Versioned hash databases and active manifest
│   ├── signatures.json       Small hash overlay
│   ├── trusted-update-keys.json
│   └── scripts/              Runtime process-event helper
├── tests/{unit,ui,integration}/
├── tools/{feeds,evaluation,vendor}/
├── scripts/                   Maintenance and deployment PowerShell
├── packaging/                 Build definitions
├── requirements/              Dependency lists
├── docs/                      Human-readable guides
├── data/{hash-feeds,rule-review}/
├── artifacts/
│   ├── dist/                 Runnable packaged application
│   ├── release/              Installers, checksums and validation record
│   ├── build/                PyInstaller intermediates
│   ├── release-test/         Isolated installer test fixtures
│   ├── logs/                 Build and regression logs
│   ├── screenshots/          UI previews
│   ├── evaluations/          Evaluation output when explicitly run
│   └── archive/              Pre-reorganization source backup and move manifest
└── .venv/                     Existing local Python environment
```

## Reading order

1. Read `README.md` for commands and `DEFENSE-IMPLEMENTATION.md` for actual scope.
2. Open `src/sentinelav/entrypoint.py` to see how execution modes are selected.
3. Read `ui/application.py` for the main window and page composition, then the relevant UI mixin.
4. Read `detection/engine.py` for scanning and `detection/inspection.py` for worker transport and limits.
5. Read `monitoring/monitoring.py` and `monitoring/background.py` for continuous monitoring.
6. Read `response/response.py` and `updates/definition_updates.py` for response and updates.
7. Look in the corresponding `tests/` folder for usage examples and regressions.

## Where data belongs

`resources/` contains application inputs. `data/` contains downloaded candidates
and review material. `artifacts/` contains generated output. They are separate
from the SQLite history, preferences, and quarantine under
`%LOCALAPPDATA%/SentinelAV`, which retain their existing location.

Source mode resolves resources relative to this project; packaged mode uses
the PyInstaller resource directory. Workers and scheduled launches use the
stable root launcher. Changing the shell's working directory does not change
which rules or signatures the application reads.

The original proposal is copied into `docs/references/`. The supplied full
hash-feed ZIP is copied into `data/hash-feeds/source-archives/`; its original
download is preserved. This ZIP contains hash-feed CSV data, not malware
samples. Historical UI screenshots are in `artifacts/screenshots/`.

Run Python checks as modules from the project root, for example:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.unit.test_engine
.\.venv\Scripts\python.exe -m tests.ui.verify_defense_ui
.\.venv\Scripts\python.exe -m tools.feeds.import_hash_archive --help
.\.venv\Scripts\python.exe -m tests.integration.verify_background_package artifacts/dist/SentinelAV/SentinelAV.exe
```

The deployment script remains manual and administrator-only; reorganizing the
project does not install a service or enable protection policies.

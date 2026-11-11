# Purpose: Locate ClamAV programs and every downloaded definition set without falling back to an unexpected drive.
# Works with: detection.clamav_engine, detection.rule_packs, paths
# Used by: detection.clamav_engine, detection.rule_packs, updates.definition_feeds, ui.updates_ui

"""Locate ClamAV programs and every downloaded definition set.

Programs: SENTINELAV_CLAMAV_HOME, a `clamav` folder beside the installed
application, then the developer tool area on the work drive.
Definitions (ClamAV signatures, rule packs, feeds): SENTINELAV_DEFINITIONS or
SENTINELAV_CLAMAV_DB, the work drive when present, then the per-user
SentinelAV data folder.
"""
import os
from pathlib import Path
from sentinelav.paths import PROJECT_ROOT

PROGRAMS = ('clamd', 'freshclam', 'clamscan')


def _work_root():
    root = Path(os.environ.get('SENTINELAV_WORK_ROOT', 'F:/SentinelAV-Work'))
    return root if root.is_dir() else None


def _candidates():
    if os.environ.get('SENTINELAV_CLAMAV_HOME'):
        yield Path(os.environ['SENTINELAV_CLAMAV_HOME'])
    yield PROJECT_ROOT / 'clamav'
    root = _work_root()
    if root and (root / 'tools').is_dir():
        yield from sorted((root / 'tools').glob('clamav-*'), reverse=True)


def binaries(home=None):
    """Return paths to clamd, freshclam and clamscan in one folder, or None."""
    for folder in ([Path(home)] if home else _candidates()):
        found = {name: folder / (name + '.exe') for name in PROGRAMS}
        if all(path.is_file() for path in found.values()):
            return dict(home=folder, **found)
    return None


def _base():
    if _work_root():
        return _work_root()
    return Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'SentinelAV'


def definitions_dir(name):
    """A named definition area, such as 'yara-forge' or 'feeds'."""
    root = Path(os.environ['SENTINELAV_DEFINITIONS']) if os.environ.get('SENTINELAV_DEFINITIONS') else _base() / 'definitions'
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def signature_data_dir(resource_root):
    """The hash database folder: the definitions area once it holds an active feed, else the bundled resources."""
    root = Path(os.environ['SENTINELAV_DEFINITIONS']) if os.environ.get('SENTINELAV_DEFINITIONS') else _base() / 'definitions'
    moved = root / 'signature-data'
    return moved if (moved / 'active.json').is_file() else Path(resource_root) / 'signature-data'


def database_dir():
    path = Path(os.environ['SENTINELAV_CLAMAV_DB']) if os.environ.get('SENTINELAV_CLAMAV_DB') else _base() / 'clamav-db'
    path.mkdir(parents=True, exist_ok=True)
    return path

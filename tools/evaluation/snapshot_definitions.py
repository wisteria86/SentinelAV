# Purpose: Freeze the active definitions (ClamAV, rule packs, hash lists, certificate blocklist) into a hashed snapshot.
# Works with: detection.helpers.definition_paths, detection.core.rule_packs, workspace
# Used by: evaluation runs that map the snapshot read-only into Windows Sandbox

"""Freeze the active definitions into a hashed, read-only snapshot.

An evaluation must use definitions that existed before its samples were first
seen. This copies exactly what scans use today and records every file's SHA-256
and the source versions, so a report can name the snapshot it was measured with.
"""

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from sentinelav.detection.helpers.definition_paths import (
    binaries,
    database_dir,
    definitions_dir,
)  # noqa: E402
from sentinelav.workspace import Workspace  # noqa: E402
from sentinelav.paths import RESOURCE_ROOT  # noqa: E402


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def cvd_version(path):
    header = path.read_bytes()[:512].decode('ascii', 'replace').split(':')
    return dict(
        file=path.name,
        built=header[1].strip() if len(header) > 1 else '',
        version=header[2] if len(header) > 2 else '',
        signatures=header[3] if len(header) > 3 else '',
    )


def active_files(folder, pointer_key):
    pointer = folder / 'active.json'
    if not pointer.is_file():
        return []
    return [pointer, folder / json.loads(pointer.read_text(encoding='utf-8'))[pointer_key]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name', help='Snapshot name, for example eval-freeze-90')
    args = parser.parse_args()
    from sentinelav.detection.core.rule_packs import load_packs

    packs, problems = load_packs()  # Compiles and records the compiled form before copying.
    if problems:
        raise SystemExit('Rule pack problem: ' + '; '.join(problems))
    target = Workspace().area('snapshots') / args.name
    if target.exists():
        raise SystemExit(f'Snapshot {target} already exists; snapshots are never overwritten')
    plan = []
    for name, key in (('signature-data', 'database'), ('md5-feed', 'database')):
        plan += [
            (path, Path('definitions') / name / path.name)
            for path in active_files(definitions_dir(name), key)
        ]
    for pack in packs:
        folder = pack.folder
        compiled = sorted(folder.glob(f"compiled-{pack.manifest['sha256'][:16]}.yarc"))
        plan += [
            (path, Path('definitions') / pack.name / path.name)
            for path in [folder / 'pack.json', folder / pack.manifest['file'], *compiled]
        ]
    # The learned models live outside git, so the freeze records exactly which ones were active.
    models = RESOURCE_ROOT / 'analysis-data'
    if (models / 'active.json').is_file():
        index = json.loads((models / 'active.json').read_text(encoding='utf-8'))
        plan += [(models / 'active.json', Path('models/active.json'))]
        plan += [
            (models / entry['file'], Path('models') / entry['file']) for entry in index.values()
        ]
    blocklist = definitions_dir('cert-blocklist') / 'cscb.csv'
    if blocklist.is_file():
        plan.append((blocklist, Path('definitions/cert-blocklist/cscb.csv')))
    clam_db = database_dir()
    signatures = sorted(
        item for item in clam_db.iterdir() if item.suffix in ('.cvd', '.cld', '.cud')
    )
    plan += [(path, Path('clamav-db') / path.name) for path in signatures]
    tools = binaries()
    if tools:
        plan += [
            (path, Path('clamav') / path.relative_to(tools['home']))
            for path in tools['home'].rglob('*')
            if path.is_file() and path.suffix.lower() not in ('.pdb', '.lib')
        ]
    target.mkdir(parents=True)
    files = {}
    for source, relative in plan:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        files[relative.as_posix()] = dict(
            sha256=sha256(destination), bytes=destination.stat().st_size
        )
    snapshot = dict(
        schema=1,
        name=args.name,
        created_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        clamav=[cvd_version(path) for path in signatures],
        clamav_program=tools['home'].name if tools else None,
        rule_packs=[pack.summary() for pack in packs],
        files=files,
    )
    for name in ('signature-data', 'md5-feed'):
        pointer = definitions_dir(name) / 'active.json'
        if pointer.is_file():
            data = json.loads(pointer.read_text(encoding='utf-8'))
            snapshot[name] = {
                key: data.get(key)
                for key in (
                    'database',
                    'unique_sha256',
                    'unique_md5',
                    'imported_utc',
                    'built_utc',
                    'rows',
                )
                if key in data
            }
    (target / 'snapshot.json').write_text(json.dumps(snapshot, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in snapshot.items() if key != 'files'}, indent=2))
    print(
        f'{len(files)} files, {sum(item["bytes"] for item in files.values()) / 1024**3:.2f} GiB in {target}'
    )


if __name__ == '__main__':
    main()

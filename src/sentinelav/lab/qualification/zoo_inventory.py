# Purpose: Freeze Zoo Git tree metadata and stage only pinned encrypted archives.
# Works with: lab.qualification.runner, backend_sandbox, zoo_guest.

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

from sentinelav.lab.static_pilot import REVISION
from sentinelav.paths import PROJECT_ROOT
from sentinelav.workspace import unlinked
from .contracts import CaseDefinition, digest

BATCH_SIZE = 4
MAX_ARCHIVE = 64 * 1024**2
SHA1 = re.compile(r'[a-f0-9]{40}')
TREE_SHA256 = 'e370aa35ef82a8217840d210dfcf55405ce69fcfbf3ea80ee52ea7894389778c'
PASSWORD_SUFFIXES = {'.pass', '.password', '.pas'}
SIDECARS = PASSWORD_SUFFIXES | {'.md5', '.sha256', '.sha', '.sha1', '.shasum', '.sha267'}


def git(repo, *args):
    return subprocess.check_output(
        ['git', '--no-replace-objects', '--git-dir', str(repo), *args], timeout=60,
        env=dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0'),
    )


def repository(work):
    path = unlinked(work / 'datasets/theZoo.git')
    if not path.is_dir():
        raise FileNotFoundError(f'Place a local bare theZoo repository at {path}')
    if git(path, 'rev-parse', '--is-bare-repository').strip() != b'true':
        raise ValueError('Zoo payload source must be a bare Git repository')
    if git(path, 'rev-parse', REVISION + '^{commit}').strip() != REVISION.encode():
        raise ValueError('Pinned Zoo commit unavailable')
    return path


def tree_entries():
    tree = json.loads((PROJECT_ROOT / 'resources/zoo-tree.json').read_bytes())
    if digest(tree) != TREE_SHA256:
        raise ValueError('Pinned Zoo tree metadata changed')
    if tree['schema'] != 1 or tree['revision'] != REVISION:
        raise ValueError('Unexpected Zoo tree metadata revision')
    return tree['entries']


def cases():
    entries = []
    passwords = {}
    folders = {}
    for record in tree_entries():
        mode, kind, blob, size = (record[key] for key in ('mode','type','oid','size'))
        path = record['path']
        suffix = Path(path).suffix.lower()
        if suffix in PASSWORD_SUFFIXES and kind == 'blob' and type(size) is int and 0 < size <= 1024:
            passwords[path.rsplit('.', 1)[0].casefold()] = blob
            folders.setdefault(path.rsplit('/', 1)[0], []).append(blob)
        if suffix in SIDECARS:
            continue
        if len(path) > 300 or any(ord(ch) < 32 for ch in path):
            raise ValueError('Invalid Zoo tree path')
        entry = dict(path=path, blob=blob, bytes=size)
        if mode != '100644' and mode != '100755' or kind != 'blob' or suffix != '.zip':
            entry['unsupported'] = True
        entries.append(entry)
    if not entries:
        raise ValueError('Empty Zoo inventory')
    for item in entries:
        siblings = folders.get(item['path'].rsplit('/', 1)[0], [])
        password = passwords.get(item['path'].rsplit('.', 1)[0].casefold())
        if not password and len(siblings) == 1:
            password = siblings[0]
        if password:
            item['password_blob'] = password
    return [asdict(CaseDefinition(
        f'zoo-{offset // BATCH_SIZE:04}', 'raw_detection', 'sandbox', 'zoo_static',
        mode='signature_free', seconds=900,
        parameters=dict(revision=REVISION, entries=entries[offset:offset+BATCH_SIZE]),
        expected=dict(zoo_accounted=True),
    )) for offset in range(0, len(entries), BATCH_SIZE)]


def quick_cases():
    from sentinelav.lab.static_corpus import SPECS
    entries = [dict(path=spec['family'], blob=spec['blob'], fixture=spec['id']) for spec in SPECS]
    return [asdict(CaseDefinition('zoo-quick', 'raw_detection', 'sandbox', 'zoo_static',
        mode='signature_free', seconds=900, parameters=dict(revision=REVISION, entries=entries, group='base'),
        expected=dict(zoo_accounted=True)))]


def blob_identity(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def stage(work, parameters, output):
    if parameters['revision'] != REVISION:
        raise ValueError('Unexpected Zoo revision')
    repo = repository(work)
    staged = []
    for entry in parameters['entries']:
        item = dict(entry)
        staged.append(item)
        if item.get('unsupported'):
            continue
        blob = item['blob']
        if not SHA1.fullmatch(blob):
            raise ValueError('Invalid pinned Zoo blob')
        try:
            size = int(git(repo, 'cat-file', '-s', blob))
            if size != item['bytes'] or not 0 < size <= MAX_ARCHIVE:
                raise ValueError('Archive size mismatch or exceeds 64 MiB')
            data = git(repo, 'cat-file', 'blob', blob)
            if len(data) != size or blob_identity(data) != blob:
                raise ValueError('Archive Git identity mismatch')
            archive = output / (blob + '.zip')
            if not archive.exists():
                from io import BytesIO
                with zipfile.ZipFile(BytesIO(data)) as source:
                    members = [row for row in source.infolist() if not row.is_dir()]
                    if not members or any(not row.flag_bits & 1 for row in members):
                        raise ValueError('Archive contains unencrypted members or is empty')
                archive.write_bytes(data)
            password_blob = item.get('password_blob')
            if password_blob:
                import base64
                if not SHA1.fullmatch(password_blob) or int(git(repo, 'cat-file', '-s', password_blob)) > 1024:
                    raise ValueError('Invalid pinned archive password blob')
                password = git(repo, 'cat-file', 'blob', password_blob)
                if blob_identity(password) != password_blob:
                    raise ValueError('Archive password identity mismatch')
                item['password_b64'] = base64.b64encode(password.strip()).decode()
        except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
            item['stage_error'] = type(error).__name__
    return dict(revision=REVISION, entries=staged)

# Purpose: Select, download and seal MalwareBazaar samples by first-seen date, and stage them for Sandbox batches.
# Works with: lab.qualification.zoo_inventory, zoo_guest, backend_sandbox, runner; response.response_files (DPAPI)
# Used by: lab.qualification.runner, lab.qualification.backend_sandbox, tools.evaluation.bazaar_collect

"""Select, download and seal MalwareBazaar samples, then stage them for Sandbox batches.

Samples arrive as the provider's password-protected ZIP and are sealed with
AES-256-GCM before anything touches disk, so no plaintext sample or readable
archive is ever stored on the host. Only the offline guest opens them.
Selection is by first-seen date: a holdout uses only samples first seen after
the code and definitions were frozen.
"""
from dataclasses import asdict
import base64
import csv
import io
import json
import os
import random
import time
import zipfile
from pathlib import Path

from .contracts import CaseDefinition
from .zoo_inventory import BATCH_SECONDS, MAX_ARCHIVE, SHA1, blob_identity, seal, unseal

API = 'https://mb-api.abuse.ch/api/v1/'
PASSWORD = b'infected'
PER_FAMILY = 20


def auth_key():
    value = os.environ.get('ABUSECH_AUTH_KEY')
    if not value and os.name == 'nt':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
                value = winreg.QueryValueEx(key, 'ABUSECH_AUTH_KEY')[0]
        except OSError:
            value = None
    if not value:
        raise RuntimeError('Set ABUSECH_AUTH_KEY to your abuse.ch Auth-Key first')
    return value


def corpus_root(name, create=True):
    from sentinelav.workspace import Workspace
    if not name.isidentifier():
        raise ValueError('Corpus names are simple identifiers')
    root = Workspace().area('datasets') / 'bazaar' / name
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def corpus_key(root):
    """A per-corpus AES key, protected by DPAPI for this Windows account."""
    from sentinelav.response.response_files import dpapi
    path = root / 'key.dpapi'
    if path.is_file():
        return dpapi(path.read_bytes(), decrypt=True)
    key = os.urandom(32)
    path.write_bytes(dpapi(key))
    return key


# SentinelAV protects Windows, so evaluations leave out formats that only run on other systems.
NON_WINDOWS_TYPES = frozenset({'elf', 'macho', 'apk', 'dex', 'dmg', 'sh', 'zsh', 'bash', 'php', 'pl'})


def windows_target(file_type):
    return (file_type or '').casefold() not in NON_WINDOWS_TYPES


def family_of(row):
    signature = (row.get('signature') or '').strip()
    return signature.casefold() if signature and signature.casefold() != 'n/a' else 'unlabeled-' + (row.get('file_type_guess') or 'unknown')


def candidates(full_zip, start, end):
    """Rows of the MalwareBazaar full export first seen in [start, end), as 'YYYY-MM-DD HH:MM:SS' strings."""
    with zipfile.ZipFile(full_zip) as archive, archive.open('full.csv') as raw:
        header = None
        for line in io.TextIOWrapper(raw, encoding='utf-8-sig', errors='replace'):
            if line.lstrip().startswith('#'):
                if 'sha256_hash' in line:
                    header = [item.strip().strip('"') for item in line.lstrip().lstrip('#').split(',')]
                continue
            if header is None:
                continue
            try:
                values = next(csv.reader([line], skipinitialspace=True))
            except csv.Error:
                continue
            if len(values) != len(header):
                continue
            row = dict(zip(header, (value.strip() for value in values)))
            if start <= row['first_seen_utc'] < end and windows_target(row.get('file_type_guess')):
                yield row


def select(rows, count, seed, per_family=PER_FAMILY):
    """Cap each family so a few prolific families cannot dominate, then draw a seeded sample."""
    generator = random.Random(seed)
    families = {}
    for row in rows:
        families.setdefault(family_of(row), []).append(row)
    pool = []
    for name in sorted(families):
        members = sorted(families[name], key=lambda row: row['sha256_hash'])
        generator.shuffle(members)
        pool += members[:per_family]
    generator.shuffle(pool)
    return pool[:count]


def _download(sha256, key):
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlencode
    from urllib.request import Request, urlopen
    request = Request(API, data=urlencode(dict(query='get_file', sha256_hash=sha256)).encode(),
        headers={'Auth-Key': key, 'User-Agent': 'sentinelav-research'})
    try:
        with urlopen(request, timeout=120) as response:
            content = response.read(MAX_ARCHIVE + 1)
    except HTTPError as error:
        return None, f'HTTP {error.code}'
    except (URLError, OSError) as error:
        return None, type(error).__name__
    if not content.startswith(b'PK'):
        return None, content[:120].decode('utf-8', 'replace')
    return content, None


def build(name, full_zip, start, end, count, seed, delay=1.0, progress=print):
    """Download and seal a corpus. Resumable: samples already sealed are kept."""
    root = corpus_root(name)
    manifest_path = root / 'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8')) if manifest_path.is_file() else dict(
        schema=1, name=name, window=[start, end], seed=seed, created_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), entries=[], skipped=[])
    if manifest['window'] != [start, end] or manifest['seed'] != seed:
        raise ValueError('An existing corpus with this name used a different window or seed')
    chosen = select(candidates(full_zip, start, end), count, seed)
    done = {entry['sha256'] for entry in manifest['entries']} | {entry['sha256'] for entry in manifest['skipped']}
    key, secret = corpus_key(root), auth_key()
    for index, row in enumerate(chosen, 1):
        sha = row['sha256_hash']
        if sha in done:
            continue
        data, problem = _download(sha, secret)
        if data is None or len(data) > MAX_ARCHIVE:
            manifest['skipped'].append(dict(sha256=sha, reason=problem or 'Archive over 64 MiB'))
        else:
            blob = blob_identity(data)
            (root / (blob + '.sealed')).write_bytes(seal(data, key, blob))
            manifest['entries'].append(dict(sha256=sha, blob=blob, bytes=len(data), family=family_of(row),
                file_type=row.get('file_type_guess', ''), first_seen=row['first_seen_utc']))
        if index % 10 == 0 or index == len(chosen):
            manifest_path.write_text(json.dumps(manifest, indent=1), encoding='utf-8')
            progress(f'{index}/{len(chosen)} processed; {len(manifest["entries"])} sealed, {len(manifest["skipped"])} skipped')
        time.sleep(delay)
    manifest_path.write_text(json.dumps(manifest, indent=1), encoding='utf-8')
    return manifest


# Each batch pays about 7 minutes of fixed Sandbox setup and teardown, while scanning costs seconds per sample,
# so these single-file batches are much larger than theZoo's multi-member archive batches.
BATCH_SIZE = 64  # Prepare-TestEnvironment.ps1 stages at most 64 sealed archives per guest
BATCH_BYTES = 384 * 1024**2

def cases(name, definitions=None):
    manifest = json.loads((corpus_root(name, create=False) / 'manifest.json').read_text(encoding='utf-8'))
    password = base64.b64encode(PASSWORD).decode()
    entries = [dict(path=f"bazaar/{name}/{item['family']}/{item['sha256']}.zip", blob=item['blob'], bytes=item['bytes'],
        family=item['family'], split=name, sha256=item['sha256'], password_b64=password) for item in manifest['entries']
        if windows_target(item.get('file_type'))]
    batches, current = [], []
    for entry in entries:
        if current and (len(current) >= BATCH_SIZE or sum(row['bytes'] for row in current) + entry['bytes'] > BATCH_BYTES):
            batches.append(current)
            current = []
        current.append(entry)
    if current:
        batches.append(current)
    extra = dict(definitions=str(definitions)) if definitions else {}
    return [asdict(CaseDefinition(f'bazaar-{name}-{index:04}', 'raw_detection', 'sandbox', 'zoo_static', mode='normal',
        seconds=BATCH_SECONDS, parameters=dict(revision='bazaar:' + name, corpus=name, entries=batch, **extra),
        expected=dict(zoo_accounted=True))) for index, batch in enumerate(batches)]


def profile_cases(profile, cases_so_far):
    """Cases for a bazaar profile, plus the frozen definitions snapshot named by SENTINELAV_EVAL_SNAPSHOT."""
    if profile in ('bazaar-dev', 'bazaar-holdout'):
        cases_so_far = cases(profile.split('-')[1])
    snapshot = os.environ.get('SENTINELAV_EVAL_SNAPSHOT')
    if cases_so_far and snapshot:
        if not (Path(snapshot) / 'snapshot.json').is_file():
            raise ValueError('SENTINELAV_EVAL_SNAPSHOT does not name a definitions snapshot')
        for case in cases_so_far:
            case['parameters']['definitions'] = str(Path(snapshot).resolve())
    return cases_so_far


def stage(parameters, output):
    """Re-seal a batch with a fresh transfer key for one guest; the plaintext ZIP exists only in memory here."""
    name = parameters['corpus']
    root = corpus_root(name, create=False)
    key, transfer = corpus_key(root), os.urandom(32)
    staged = []
    for entry in parameters['entries']:
        item = dict(entry)
        staged.append(item)
        try:
            if not SHA1.fullmatch(item['blob']):
                raise ValueError('Invalid sample identity')
            data = unseal((root / (item['blob'] + '.sealed')).read_bytes(), key, item['blob'])
            if blob_identity(data) != item['blob'] or len(data) != item['bytes']:
                raise ValueError('Sample identity mismatch')
            (Path(output) / (item['blob'] + '.sealed')).write_bytes(seal(data, transfer, item['blob']))
        except (OSError, ValueError) as error:
            item['stage_error'] = type(error).__name__
    return dict(revision=parameters['revision'], entries=staged, transfer_key=base64.b64encode(transfer).decode())

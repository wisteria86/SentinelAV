# Purpose: Inspect pinned Zoo ZIP members inside an offline guest without launching them.
# Works with: lab.qualification.guest, zoo_inventory, zoo_response, detection.inspection.

import base64
import hashlib
from io import BytesIO
from pathlib import Path
import re
import time
import zipfile

from .zoo_inventory import MAX_ARCHIVE, REVISION, SHA1, blob_identity

OUTCOMES = ('malicious', 'suspicious', 'miss', 'unsupported', 'not_applicable', 'blocked_by_other_av', 'inspection_failure')
MAX_MEMBER = 64 * 1024**2
MAX_MEMBERS = 256
SAFE_SUFFIX = re.compile(r'\.[a-z0-9]{1,8}')
# Generalized detection as it ships. Emulation stays off, so nothing from a sample ever runs, even virtually.
SETTINGS = dict(signature_free=False, advanced=True, model=True, neural_gray=True, neural=False, emulation=False, amsi=False, reputation=False)
RESPONSE_CYCLES_PER_BATCH = 2
REALTIME_CHECKS_PER_BATCH = 1


def verdict(scan):
    """A file that could not be fully inspected is never reported as a clean miss."""
    errors = scan.get('errors') or []
    if scan.get('scanned') != 1 or not scan.get('assessment'):
        if any('Read blocked' in str(error) for error in errors):
            return 'blocked_by_other_av', 'Another security product blocked the read'
        return 'inspection_failure', 'Scanner did not assess exactly one file'
    assessment = scan['assessment']
    result = assessment['arms']['full']['verdict']
    if result == 'Malicious':
        return 'malicious', ''
    if result == 'Suspicious':
        return 'suspicious', ''
    if assessment.get('inert'):
        return 'not_applicable', 'Content with no executable behavior'
    if not assessment.get('analyzed'):
        return 'unsupported', 'No analyzer for this file type: ' + str(assessment.get('file_kind'))
    if errors or scan.get('status') != 'Complete':
        return 'inspection_failure', 'Inspection incomplete'
    return 'miss', ''


def fixture_suffix(name):
    suffix = Path(str(name)).suffix.lower()
    return suffix if SAFE_SUFFIX.fullmatch(suffix) else '.bin'


def describe(scan):
    """Bounded metadata only: the sample itself and its strings never leave the guest."""
    assessment = scan.get('assessment') or {}
    return dict(kind=assessment.get('file_kind'), platform=assessment.get('platform'), score=assessment.get('score'),
                confidence=assessment.get('confidence'), threat=str(assessment.get('threat_name', ''))[:80],
                arms={name: [value['score'], value['verdict']] for name, value in (assessment.get('arms') or {}).items()},
                codes=[item['code'] for item in (assessment.get('indicators') or [])[:8]],
                automatic=assessment.get('automatic_response_eligible'))


def scan_member(archive, info, password, root, scanner, state):
    if not info.flag_bits & 1:
        return dict(outcome='inspection_failure', reason='Unencrypted member rejected')
    if info.file_size > MAX_MEMBER:
        return dict(outcome='inspection_failure', reason='Member exceeds 64 MiB scan budget')
    with archive.open(info, pwd=password) as stream:
        raw = stream.read(MAX_MEMBER + 1)
    if len(raw) != info.file_size or len(raw) > MAX_MEMBER:
        raise ValueError('Archive member size mismatch')
    identity = hashlib.sha256(raw).hexdigest()
    suffix = fixture_suffix(info.filename)
    fixture = root / ('member' + suffix)
    try:
        with fixture.open('xb') as stream:
            stream.write(raw)
    except OSError:
        return dict(outcome='blocked_by_other_av', reason='Another security product blocked the write', sha256=identity)
    try:
        scan = scanner.scan([fixture], lambda: False, lambda *args: None)
        if fixture.exists() and hashlib.sha256(fixture.read_bytes()).hexdigest() != identity:
            raise ValueError('Specimen changed during inspection')
        outcome, reason = verdict(scan)
        row = dict(outcome=outcome, reason=reason, sha256=identity, coverage_complete=scan.get('status') == 'Complete' and not scan.get('errors'), **describe(scan))
    finally:
        fixture.unlink(missing_ok=True)
    if outcome == 'malicious':
        from .zoo_response import realtime_check, response_cycle
        if state['response'] < RESPONSE_CYCLES_PER_BATCH:
            state['response'] += 1
            row['response_cycle'] = response_cycle(raw, suffix, root, SETTINGS)
        if state['realtime'] < REALTIME_CHECKS_PER_BATCH:
            state['realtime'] += 1
            row['realtime'] = realtime_check(raw, suffix, root, SETTINGS)
    return row


def inspect_archive(entry, root, scanner, state):
    if entry.get('unsupported'):
        return [dict(outcome='unsupported', reason='Repository entry is outside encrypted ZIP scope')]
    if entry.get('stage_error'):
        return [dict(outcome='inspection_failure', reason='Archive staging failed: ' + entry['stage_error'])]
    blob = entry['blob']
    if not SHA1.fullmatch(blob):
        raise ValueError('Invalid pinned archive identity')
    from sentinelav.workspace import unlinked
    path = unlinked(Path('C:/SentinelAV-Input/Zoo') / (blob + '.zip'))
    if path.stat().st_size != entry['bytes'] or path.stat().st_size > MAX_ARCHIVE:
        raise ValueError('Archive size mismatch')
    raw = path.read_bytes()
    if blob_identity(raw) != blob:
        raise ValueError('Archive Git identity mismatch')
    password = base64.b64decode(entry['password_b64'], validate=True) if entry.get('password_b64') else b'infected'
    return inspect_members(raw, password, root, scanner, state)


def inspect_members(raw, password, root, scanner, state):
    rows = []
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if not members:
            return [dict(outcome='inspection_failure', reason='Archive has no members')]
        for index, info in enumerate(members[:MAX_MEMBERS]):
            if time.monotonic() > state['deadline']:
                rows.append(dict(member_index=index, member=info.filename[:160], outcome='inspection_failure', reason='Batch time budget reached'))
                continue
            try:
                row = scan_member(archive, info, password, root, scanner, state)
            except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
                row = dict(outcome='inspection_failure', reason=type(error).__name__)
            # Names are metadata only. They are never used as filesystem paths.
            rows.append(dict(member_index=index, member=info.filename[:160], **row))
        if len(members) > MAX_MEMBERS:
            rows.append(dict(member_index=MAX_MEMBERS, member='', outcome='inspection_failure', reason=f'{len(members)-MAX_MEMBERS} further members not inspected'))
    return rows


def inspect_cached(entry, root, scanner, key, files, state):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from sentinelav.lab.static_corpus import AAD, SPECS, validate_archive
    from sentinelav.workspace import unlinked
    spec = next((item for item in SPECS if item['id'] == entry['fixture'] and item['blob'] == entry['blob']), None)
    if spec is None:
        raise ValueError('Unknown pinned fixture')
    name = 'corpus-' + spec['id'] + '.sealed'
    path = unlinked(Path('C:/SentinelAV-Input') / name)
    if path.stat().st_size != spec['size'] + 28:
        raise ValueError('Cached fixture size mismatch')
    sealed = path.read_bytes()
    if hashlib.sha256(sealed).hexdigest() != files.get(name):
        raise ValueError('Cached fixture digest mismatch')
    raw = AESGCM(key).decrypt(sealed[:12], sealed[12:], AAD + spec['id'].encode())
    validate_archive(raw, spec)
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        row = scan_member(archive, archive.getinfo(spec['member']), b'infected', root, scanner, state)
    return [dict(member_index=0, member=spec['member'], **row)]


def execute(context, root):
    import json
    from cryptography.exceptions import InvalidTag
    from sentinelav.detection.inspection import IsolatedScanner
    from sentinelav.paths import RESOURCE_ROOT
    case = context['case']
    quick = case['id'] == 'zoo-quick'
    batch = case['parameters'] if quick else context['zoo_input']
    if context['backend'] != 'sandbox' or batch['revision'] != REVISION:
        raise ValueError('Zoo scans require Windows Sandbox and the pinned revision')
    if not 1 <= len(batch['entries']) <= 64:
        raise ValueError('Invalid Zoo batch size')
    scanner = IsolatedScanner(RESOURCE_ROOT/'signatures.json', RESOURCE_ROOT/'rules', max_mb=64, options=dict(SETTINGS), persistent=True)
    state = dict(response=0, realtime=0, deadline=time.monotonic()+max(60, case['seconds']-120))
    groups = []
    try:
        if quick:
            key = base64.b64decode(context['transfer_key'], validate=True)
            if len(key) != 32:
                raise ValueError('Invalid fixture transfer key')
            files = json.loads(Path('C:/SentinelAV-Input/manifest.json').read_text(encoding='utf-8-sig'))['files']
        for entry in batch['entries']:
            try:
                rows = inspect_cached(entry, root, scanner, key, files, state) if quick else inspect_archive(entry, root, scanner, state)
            except (OSError, ValueError, RuntimeError, NotImplementedError, InvalidTag, zipfile.BadZipFile) as error:
                rows = [dict(outcome='inspection_failure', reason=type(error).__name__)]
            groups.append(dict(blob=entry['blob'], rows=rows))
    finally:
        scanner.close()
    return dict(zoo_accounted=True, zoo_revision=REVISION, zoo_groups=groups, sample_execution=False)

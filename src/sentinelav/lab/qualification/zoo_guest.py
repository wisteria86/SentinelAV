# Purpose: Inspect pinned Zoo ZIP members inside an offline guest without launching them.
# Works with: lab.qualification.guest, zoo_inventory, detection.inspection.

import base64
import hashlib
from io import BytesIO
from pathlib import Path
import zipfile

from .zoo_inventory import MAX_ARCHIVE, REVISION, SHA1, blob_identity

OUTCOMES = ('confirmed_detection', 'warning', 'miss', 'unsupported_format', 'inspection_failure')
MAX_MEMBER = 64 * 1024**2
MAX_MEMBERS = 24
SCRIPT_SUFFIXES = {'.bat', '.cmd', '.js', '.ps1', '.vbs', '.wsf', '.hta', '.html', '.docm', '.xlsm'}


def verdict(scan):
    policy = scan.get('signature_policy', {})
    if policy.get('signature_free') is not True or any(
        policy.get(key) is not False for key in ('hashes', 'yara', 'test_markers', 'amsi', 'reputation')
    ):
        return 'inspection_failure', 'Signature-free policy missing or inconsistent'
    if scan.get('scanned') != 1:
        return 'inspection_failure', 'Scanner did not inspect exactly one file'
    decision = scan.get('analysis_result', {}).get('verdict')
    if scan.get('detections') or decision == 'Detected':
        return 'confirmed_detection', ''
    if decision == 'Review' or scan.get('advanced_review_total') or scan.get('structural_review_total'):
        return 'warning', ''
    if scan.get('errors') or scan.get('status') != 'Complete':
        return 'inspection_failure', 'Inspection incomplete'
    return 'miss', ''


def scan_member(archive, info, password, root, scanner):
    if not info.flag_bits & 1:
        return dict(outcome='inspection_failure', reason='Unencrypted member rejected')
    if info.file_size > MAX_MEMBER:
        return dict(outcome='inspection_failure', reason='Member exceeds 64 MiB scan budget')
    with archive.open(info, pwd=password) as stream:
        raw = stream.read(MAX_MEMBER + 1)
    if len(raw) != info.file_size or len(raw) > MAX_MEMBER:
        raise ValueError('Archive member size mismatch')
    identity = hashlib.sha256(raw).hexdigest()
    suffix = Path(info.filename).suffix.lower()
    if not raw.startswith(b'MZ') and suffix not in SCRIPT_SUFFIXES:
        return dict(outcome='unsupported_format', reason='Outside Windows PE and supported active-content scope',
                    sha256=identity)
    fixture = root / ('member' + (suffix if suffix in SCRIPT_SUFFIXES else '.bin'))
    with fixture.open('xb') as stream:
        stream.write(raw)
    try:
        scan = scanner.scan([fixture], lambda: False, lambda *args: None)
        if hashlib.sha256(fixture.read_bytes()).hexdigest() != identity:
            raise ValueError('Specimen changed during inspection')
        outcome, reason = verdict(scan)
        return dict(outcome=outcome, reason=reason, sha256=identity,
                    coverage_complete=scan.get('status') == 'Complete' and not scan.get('errors'),
                    signature_policy=scan.get('signature_policy', {}))
    finally:
        fixture.unlink(missing_ok=True)


def inspect_archive(entry, root, scanner):
    if entry.get('unsupported'):
        return [dict(outcome='unsupported_format', reason='Repository entry is outside encrypted ZIP scope')]
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
    rows = []
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if not 1 <= len(members) <= MAX_MEMBERS:
            return [dict(outcome='inspection_failure', reason='Archive member count outside batch budget',
                         uninspected_members=len(members))]
        for index, info in enumerate(members):
            try:
                row = scan_member(archive, info, password, root, scanner)
            except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
                row = dict(outcome='inspection_failure', reason=type(error).__name__)
            # Names are metadata only. They are never used as filesystem paths.
            rows.append(dict(member_index=index, member=info.filename[:160], **row))
    return rows


def inspect_cached(entry, root, scanner, key, files):
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
        row = scan_member(archive, archive.getinfo(spec['member']), b'infected', root, scanner)
    return [dict(member_index=0, member=spec['member'], **row)]


def execute(context, root):
    import json
    from cryptography.exceptions import InvalidTag
    from sentinelav.detection.inspection import IsolatedScanner
    from sentinelav.paths import RESOURCE_ROOT
    from .guest_context import options
    case = context['case']
    quick = case['id'] == 'zoo-quick'
    batch = case['parameters'] if quick else context['zoo_input']
    if context['backend'] != 'sandbox' or case['mode'] != 'signature_free' or batch['revision'] != REVISION:
        raise ValueError('Zoo scans require signature-free Windows Sandbox')
    if not 1 <= len(batch['entries']) <= 4:
        raise ValueError('Invalid Zoo batch size')
    settings = dict(options('signature_free'), emulation=False)
    scanner = IsolatedScanner(RESOURCE_ROOT/'signatures.json', RESOURCE_ROOT/'rules',
                              max_mb=64, options=settings, persistent=True)
    groups = []
    try:
        if quick:
            key = base64.b64decode(context['transfer_key'], validate=True)
            if len(key) != 32:
                raise ValueError('Invalid fixture transfer key')
            files = json.loads(Path('C:/SentinelAV-Input/manifest.json').read_text(encoding='utf-8-sig'))['files']
        for entry in batch['entries']:
            try:
                rows = inspect_cached(entry, root, scanner, key, files) if quick else inspect_archive(entry, root, scanner)
            except (OSError, ValueError, RuntimeError, NotImplementedError, InvalidTag, zipfile.BadZipFile) as error:
                rows = [dict(outcome='inspection_failure', reason=type(error).__name__)]
            groups.append(dict(blob=entry['blob'], rows=rows))
    finally:
        scanner.close()
    return dict(zoo_accounted=True, zoo_revision=REVISION, zoo_groups=groups, sample_execution=False)

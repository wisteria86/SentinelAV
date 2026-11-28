# Purpose: Inspect pinned Zoo ZIP members inside an offline guest without launching them.
# Works with: lab.qualification.guest, zoo_inventory, zoo_response, detection.inspection.

import base64
import hashlib
import json
from io import BytesIO
from pathlib import Path
import re
import time
import zipfile

from .zoo_inventory import MAX_ARCHIVE, REVISION, SHA1, blob_identity, unseal

OUTCOMES = (
    'malicious',
    'suspicious',
    'miss',
    'unsupported',
    'not_applicable',
    'blocked_by_other_av',
    'inspection_failure',
)
MAX_MEMBER = 64 * 1024**2
MAX_MEMBERS = 256
SAFE_SUFFIX = re.compile(r'\.[a-z0-9]{1,8}')
# Generalized detection as it ships. Emulation stays off, so nothing from a sample ever runs, even virtually.
SETTINGS = dict(
    signature_free=False,
    advanced=True,
    model=True,
    neural_gray=True,
    neural=False,
    emulation=False,
    amsi=False,
    reputation=False,
    clamav=True,
    score_all=True,
    capa=True,
    capa_memory=True,
)
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
    """Return a safe file extension for a member name (letters and digits only), or '.bin'."""
    suffix = Path(str(name)).suffix.lower()
    return suffix if SAFE_SUFFIX.fullmatch(suffix) else '.bin'


def describe(scan):
    """Bounded metadata only: the sample itself and its strings never leave the guest."""
    assessment = scan.get('assessment') or {}
    return dict(
        kind=assessment.get('file_kind'),
        platform=assessment.get('platform'),
        score=assessment.get('score'),
        confidence=assessment.get('confidence'),
        threat=str(assessment.get('threat_name', ''))[:48],
        arms={
            name: [value['score'], value['verdict']]
            for name, value in (assessment.get('arms') or {}).items()
        },
        codes=[item['code'] for item in (assessment.get('indicators') or [])[:6]],
        model_scores=assessment.get('model_scores') or {},
        notes=[str(error).rsplit(': ', 1)[-1][:100] for error in (scan.get('errors') or [])[:2]],
    )


def read_member(archive, info, password):
    """Try the sidecar password first, then the standard sharing passwords, and keep the one that works."""
    from sentinelav.detection.archive_formats import SHARING_PASSWORDS

    candidates = [password[0]] + [item for item in SHARING_PASSWORDS if item != password[0]]
    error = None
    for candidate in candidates:
        try:
            with archive.open(info, pwd=candidate) as stream:
                raw = stream.read(MAX_MEMBER + 1)
        except RuntimeError as failure:  # Wrong password
            error = failure
            continue
        password[0] = candidate
        return raw
    raise error


def scan_member(archive, info, password, root, scanner, state):
    """Decrypt one archive member, scan it under a fixed name, and return a result row.

    For the first malicious samples in a batch it also exercises the quarantine/restore/delete cycle
    and a real-time detection check.
    """
    if not info.flag_bits & 1:
        return dict(outcome='inspection_failure', reason='Unencrypted member rejected')
    if info.file_size > MAX_MEMBER:
        return dict(outcome='inspection_failure', reason='Member exceeds 64 MiB scan budget')
    raw = read_member(archive, info, password)
    if len(raw) != info.file_size or len(raw) > MAX_MEMBER:
        raise ValueError('Archive member size mismatch')
    identity = hashlib.sha256(raw).hexdigest()
    suffix = fixture_suffix(info.filename)
    fixture = root / ('member' + suffix)
    try:
        with fixture.open('xb') as stream:
            stream.write(raw)
    except OSError:
        return dict(
            outcome='blocked_by_other_av',
            reason='Another security product blocked the write',
            sha256=identity,
        )
    try:
        scan = scanner.scan([fixture], lambda: False, lambda *args: None)
        if fixture.exists() and hashlib.sha256(fixture.read_bytes()).hexdigest() != identity:
            raise ValueError('Specimen changed during inspection')
        outcome, reason = verdict(scan)
        row = dict(
            outcome=outcome,
            sha256=identity,
            coverage_complete=scan.get('status') == 'Complete' and not scan.get('errors'),
            **describe(scan),
        )
        if reason:
            row['reason'] = reason
        if outcome == 'inspection_failure' and scan.get('errors'):
            # The first cause, without the guest path, so a systematic failure is visible in the report.
            row['detail'] = str(scan['errors'][0]).split(': ', 1)[-1][:90]
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


def inspect_archive(entry, root, scanner, state, key):
    """Unseal one corpus archive inside the guest, verify its identity, and scan its members."""
    if entry.get('unsupported'):
        return [
            dict(outcome='unsupported', reason='Repository entry is outside encrypted ZIP scope')
        ]
    if entry.get('stage_error'):
        return [
            dict(
                outcome='inspection_failure',
                reason='Archive staging failed: ' + entry['stage_error'],
            )
        ]
    blob = entry['blob']
    if not SHA1.fullmatch(blob):
        raise ValueError('Invalid pinned archive identity')
    from sentinelav.workspace import unlinked

    path = unlinked(Path('C:/SentinelAV-Input/Zoo') / (blob + '.sealed'))
    if path.stat().st_size != entry['bytes'] + 28 or entry['bytes'] > MAX_ARCHIVE:
        raise ValueError('Archive size mismatch')
    raw = unseal(path.read_bytes(), key, blob)
    if blob_identity(raw) != blob:
        raise ValueError('Archive Git identity mismatch')
    password = (
        base64.b64decode(entry['password_b64'], validate=True)
        if entry.get('password_b64')
        else b'infected'
    )
    return inspect_members(raw, [password], root, scanner, state)


def inspect_members(raw, password, root, scanner, state):
    """Scan each member of an archive (up to MAX_MEMBERS), counting inert files rather than listing
    them and noting any that ran out of time.
    """
    from sentinelav.detection.archive_formats import open_zip

    rows = []
    inert = 0
    with open_zip(raw) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if not members:
            return [dict(outcome='inspection_failure', reason='Archive has no members')]
        for index, info in enumerate(members[:MAX_MEMBERS]):
            if time.monotonic() > state['deadline']:
                rows.append(
                    dict(
                        member_index=len(rows),
                        member=info.filename[:48],
                        outcome='inspection_failure',
                        reason='Batch time budget reached',
                    )
                )
                continue
            # One unreadable member costs that member, not the batch. It stays in the denominator as not detected.
            try:
                row = scan_member(archive, info, password, root, scanner, state)
            except Exception as error:
                row = dict(
                    outcome='inspection_failure',
                    reason=type(error).__name__,
                    detail=str(error)[:90],
                )
            # Images, text and the like carry no behavior, so they are counted rather than listed.
            if row['outcome'] == 'not_applicable':
                inert += 1
                continue
            # Names are metadata only. They are never used as filesystem paths.
            rows.append(dict(member_index=len(rows), member=info.filename[:48], **row))
        if inert:
            rows.append(
                dict(
                    member_index=len(rows), member='', outcome='not_applicable', inert_members=inert
                )
            )
        if len(members) > MAX_MEMBERS:
            rows.append(
                dict(
                    member_index=len(rows),
                    member='',
                    outcome='inspection_failure',
                    reason=f'{len(members)-MAX_MEMBERS} further members not inspected',
                )
            )
    return rows


def inspect_cached(entry, root, scanner, key, files, state):
    """Scan the pinned member of one of the fixed quick-test fixtures from its sealed copy."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from sentinelav.lab.static_corpus import AAD, SPECS, validate_archive
    from sentinelav.workspace import unlinked

    spec = next(
        (
            item
            for item in SPECS
            if item['id'] == entry['fixture'] and item['blob'] == entry['blob']
        ),
        None,
    )
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
        row = scan_member(
            archive, archive.getinfo(spec['member']), b'infected', root, scanner, state
        )
    return [dict(member_index=0, member=spec['member'], **row)]


SNAPSHOT = Path('C:/SentinelAV-Definitions')


def use_snapshot():
    """Point every definition lookup at the frozen, read-only snapshot mapped into the guest."""
    if not (SNAPSHOT / 'snapshot.json').is_file():
        return None
    import os

    os.environ.update(
        SENTINELAV_DEFINITIONS=str(SNAPSHOT / 'definitions'),
        SENTINELAV_CLAMAV_DB=str(SNAPSHOT / 'clamav-db'),
        SENTINELAV_CLAMAV_HOME=str(SNAPSHOT / 'clamav'),
        SENTINELAV_CLAMAV_RUNTIME='C:/SentinelAV-Work/clamd',
    )
    return json.loads((SNAPSHOT / 'snapshot.json').read_text(encoding='utf-8'))['name']


def execute(context, root):
    """Run one corpus batch inside the Windows Sandbox: start ClamAV, scan every archive in the batch
    with the shipping settings, and return per-member outcomes.
    """
    import json
    from cryptography.exceptions import InvalidTag
    from sentinelav.detection.inspection import IsolatedScanner
    from sentinelav.paths import RESOURCE_ROOT

    case = context['case']
    quick = case['id'] == 'zoo-quick'
    batch = case['parameters'] if quick else context['zoo_input']
    if context['backend'] != 'sandbox' or not (
        batch['revision'] == REVISION or str(batch['revision']).startswith('bazaar:')
    ):
        raise ValueError('Zoo scans require Windows Sandbox and the pinned revision')
    if not 1 <= len(batch['entries']) <= 64:
        raise ValueError('Invalid Zoo batch size')
    snapshot = use_snapshot()
    from sentinelav.detection.clamav_engine import ensure_service

    clamd, clamd_problem = ensure_service()
    scanner = IsolatedScanner(
        RESOURCE_ROOT / 'signatures.json',
        RESOURCE_ROOT / 'rules',
        max_mb=64,
        options=dict(SETTINGS),
        persistent=True,
    )
    state = dict(response=0, realtime=0, deadline=time.monotonic() + max(60, case['seconds'] - 120))
    groups = []
    try:
        key = base64.b64decode(
            context['transfer_key'] if quick else batch['transfer_key'], validate=True
        )
        if len(key) != 32:
            raise ValueError('Invalid fixture transfer key')
        if quick:
            files = json.loads(
                Path('C:/SentinelAV-Input/manifest.json').read_text(encoding='utf-8-sig')
            )['files']
        for entry in batch['entries']:
            try:
                rows = (
                    inspect_cached(entry, root, scanner, key, files, state)
                    if quick
                    else inspect_archive(entry, root, scanner, state, key)
                )
            except Exception as error:
                rows = [
                    dict(
                        outcome='inspection_failure',
                        reason=type(error).__name__,
                        detail=str(error)[:90],
                    )
                ]
            groups.append(dict(blob=entry['blob'], rows=rows))
    finally:
        scanner.close()
        if clamd:
            clamd.stop()
    return dict(
        zoo_accounted=True,
        zoo_revision=batch['revision'],
        zoo_groups=groups,
        sample_execution=False,
        definitions_snapshot=snapshot,
        clamav='running' if clamd else (clamd_problem or 'disabled')[:120],
    )

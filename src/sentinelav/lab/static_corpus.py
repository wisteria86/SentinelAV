# Purpose: Fixed four-family static corpus. No arbitrary acquisition or execution.
# Works with: lab.corpus_evaluation, lab.emulation_evaluation, lab.static_pilot
# Used by: entrypoint, lab.qualification.guest_support, tests.unit.test_static_corpus,
#   tools.evaluation.acquire_corpus

"""Fixed four-family static corpus. No arbitrary acquisition or execution."""

import base64
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import uuid
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sentinelav.lab.corpus_evaluation import (
    evaluate,
    render,
    unlinked,
    verified_offline_guest,
    MAX_BYTES,
    fingerprint,
)
from sentinelav.lab.static_pilot import REVISION

AAD = b'SentinelAV-static-corpus-v1'
SPECS = (
    dict(
        id='wannacry',
        family='Ransomware.WannaCry',
        size=3481589,
        blob='4a7b532e7fc6d51033a0e97e7cf1f4192528d686',
        published='ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
        member='ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe',
        algorithm='sha256',
        member_hash='ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
    ),
    dict(
        id='emotet',
        family='Win32.Emotet',
        size=63758,
        blob='87fe4afba72149c9ebce74312001877992d1ccf9',
        published='5b5bc00b4763c0bc089f0c747147b0845332be961d9839e75a60ef5db2382bb6',
        member='29D6161522C7F7F21B35401907C702BDDB05ED47.bin',
        algorithm='sha1',
        member_hash='29d6161522c7f7f21b35401907c702bddb05ed47',
    ),
    dict(
        id='zeusvm',
        family='Win32.ZeusVM',
        size=426970,
        blob='7a8a5b076c6edf860c5e17be4b1999a5e147e728',
        published='7a981d743a601ca2ae40f78547430bcd404f93520b0ba78e2ca53edf8a0f31f0',
        member='8a0c95be8a40ae5419f7d97bb3e91b2b',
        algorithm='md5',
        member_hash='8a0c95be8a40ae5419f7d97bb3e91b2b',
    ),
    dict(
        id='mirai',
        family='Linux.Mirai.B',
        size=182620,
        blob='96dfc5679a27ffe98cbea76db4b5e2102c4c64fc',
        published='b50681094c040883f3da8fe697bd3a9e35e62d1672f59d9f14e0db494f9d41c2',
        member='03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d',
        algorithm='sha256',
        member_hash='03254e6240c35f7d787ca5175ffc36818185e62bdfc4d88d5b342451a747156d',
    ),
)
BENIGN_NAMES = (
    'cmd.exe',
    'whoami.exe',
    'notepad.exe',
    'kernel32.dll',
    'user32.dll',
    'advapi32.dll',
    'crypt32.dll',
    'ntdll.dll',
    'gdi32.dll',
    'WindowsPowerShell/v1.0/powershell.exe',
)
HOLDOUT_SPECS = (
    dict(
        id='wannacryplus',
        family='Ransomware.WannaCry_Plus',
        size=2402668,
        blob='b1693e62c738e853f49088ce171c8dcba3568bf2',
        published='2027a053de21bd5c783c3f823ed1d36966780ed4',
        published_algorithm='sha1',
        member='Win32.Wannacry.exe',
        algorithm='sha1',
        member_hash='2027a053de21bd5c783c3f823ed1d36966780ed4',
    ),
    dict(
        id='gameover',
        family='ZeusGameover_Feb2014',
        size=830608,
        blob='60181bdecaccec956c9d2aca6aa956432fe88623',
        published='626422ae68865a9a124792ed667b723bdbe6cd182d184c137355c33ab1360f0f',
        member='eqig.ex_',
        algorithm='sha256',
        member_hash=None,
    ),
)
ZEUS_VALIDATION_SPECS = (
    dict(
        id='zeusbanking',
        family='ZeusBankingVersion_26Nov2013',
        size=175338,
        blob='6ffc5f93eaa8bab3b85132b5cfdb57a6b8b8db48',
        published='4644b5fb10fb84c0d47bec4b5a48d5e60165e8ae2130fca5c055633aaad73162',
        member='invoice_2318362983713_823931342io.pdf.exe',
        algorithm='sha256',
        member_hash=None,
    ),
    dict(
        id='gameoveralt',
        family='ZeusGameover_Feb2014',
        size=830608,
        blob='60181bdecaccec956c9d2aca6aa956432fe88623',
        published='626422ae68865a9a124792ed667b723bdbe6cd182d184c137355c33ab1360f0f',
        member='output.1301364.old',
        algorithm='sha256',
        member_hash=None,
    ),
)


def validate_archive(raw, spec):
    """Check that a downloaded sample archive is exactly the pinned one (size and Git blob hash) and
    that it holds a small number of encrypted members, including the expected one.
    """
    if (
        len(raw) != spec['size']
        or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != spec['blob']
    ):
        raise ValueError('Pinned archive identity mismatch')
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        files = [i for i in archive.infolist() if not i.is_dir()]
        if not 1 <= len(files) <= 4 or any(not i.flag_bits & 1 for i in files):
            raise ValueError('Expected bounded encrypted members')
        selected = [i for i in files if i.filename == spec['member']]
        if len(selected) != 1:
            raise ValueError('Pinned member missing or duplicated')
        item = selected[0]
        if sum(i.file_size for i in files) > MAX_BYTES or any(
            i.file_size / max(1, i.compress_size) > 100 for i in files
        ):
            raise ValueError('Archive expansion limit exceeded')
        return dict(
            member_bytes=item.file_size,
            archive_sha256=hashlib.sha256(raw).hexdigest(),
            auxiliary_members_not_selected=len(files) - 1,
        )


def decode_archive(raw, spec):
    """Decrypt the pinned member from a sample archive and verify its checksum against the published
    value. Returns (content bytes, metadata).
    """
    metadata = validate_archive(raw, spec)
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        info = archive.getinfo(spec['member'])
        with archive.open(info, pwd=b'infected') as stream:
            content = stream.read(MAX_BYTES + 1)
    if len(content) != metadata['member_bytes'] or len(content) > MAX_BYTES:
        raise ValueError('Expanded size mismatch')
    digest = hashlib.sha256(content).hexdigest()
    if (
        spec['member_hash']
        and hashlib.new(spec['algorithm'], content).hexdigest() != spec['member_hash']
    ):
        raise ValueError('Pinned member checksum mismatch')
    published_sample = hashlib.new(spec.get('published_algorithm', 'sha256'), content).hexdigest()
    archive_verified = (
        spec.get('published_algorithm', 'sha256') == 'sha256'
        and spec['published'] == metadata['archive_sha256']
    )
    if spec['published'] != published_sample and not archive_verified:
        raise ValueError('Published checksum matches neither pinned archive nor decoded member')
    if not spec['member_hash'] and not archive_verified:
        raise ValueError('Unpinned member identity')
    return content, dict(
        **metadata,
        sample_sha256=digest,
        published_digest_scope='sample' if published_sample == spec['published'] else 'archive',
    )


def main(key_text, holdout=False, zeus_validation=False, signature_free=False, prepare_only=False):
    """Build and evaluate the fixed static test corpus inside the offline guest.

    The sealed (AES-encrypted) sample archives are decrypted with the transfer key, each pinned
    sample is extracted under a fixed harmless name, and a set of signed Windows system files is
    added as benign controls. Depending on the options it then runs the normal evaluation plus hash-
    disabled and emulation variants, or a strict signature-free evaluation, and writes the reports.
    """
    if not verified_offline_guest():
        raise ValueError('Offline Windows test guest required')
    if holdout and zeus_validation:
        raise ValueError('Choose one fixed corpus profile')
    root = Path('C:/SentinelAV-Test')
    inputs = Path('C:/SentinelAV-Input')
    for path in (root, inputs):
        unlinked(path)
    preflight = json.loads((root / 'preflight.json').read_text())
    inventory = json.loads((inputs / 'manifest.json').read_text(encoding='utf-8-sig'))
    if preflight['kit_id'] != inventory['kit_id']:
        raise ValueError('Guest kit mismatch')
    key = base64.b64decode(key_text, validate=True)
    if len(key) != 32:
        raise ValueError('Invalid transfer key')
    area = root / ('StaticCorpus-' + uuid.uuid4().hex)
    area.mkdir(exist_ok=False)
    corpus = area / 'corpus'
    corpus.mkdir()
    specs = ZEUS_VALIDATION_SPECS if zeus_validation else HOLDOUT_SPECS if holdout else SPECS
    entries = []
    imports = []
    failures = []
    for spec in specs:
        try:
            name = 'corpus-' + spec['id'] + '.sealed'
            path = inputs / name
            unlinked(path)
            if path.stat().st_size != spec['size'] + 28:
                raise ValueError('Sealed size mismatch')
            sealed = path.read_bytes()
            if hashlib.sha256(sealed).hexdigest() != inventory['files'][name]:
                raise ValueError('Sealed input hash mismatch')
            raw = AESGCM(key).decrypt(sealed[:12], sealed[12:], AAD + spec['id'].encode())
            content, metadata = decode_archive(raw, spec)
            # Names from the archive are never used as paths or shell arguments.
            name = spec['id'] + '.bin'
            with (corpus / name).open('xb') as stream:
                stream.write(content)
            entries.append(
                dict(
                    path=name,
                    sha256=metadata['sample_sha256'],
                    label='malware',
                    provenance=spec['family']
                    + '; theZoo revision '
                    + REVISION
                    + '; archive blob '
                    + spec['blob'],
                )
            )
            imports.append(dict(id=spec['id'], family=spec['family'], **metadata))
        except Exception as error:
            failures.append(dict(id=spec['id'], family=spec['family'], error=str(error)[:1000]))
    benign = json.loads((root / 'benign-provenance.json').read_text(encoding='utf-8-sig'))
    if len(benign) != len(BENIGN_NAMES) or {r['name'] for r in benign} != set(BENIGN_NAMES):
        raise ValueError('Benign selection differs from fixed plan')
    benign_omitted = []
    for item in ([] if signature_free and (holdout or zeus_validation) else benign):
        try:
            if item.get('signature_status') != 'Valid' or 'Microsoft' not in item.get('signer', ''):
                raise ValueError('Valid Microsoft signature not established')
            source = Path(os.environ['WINDIR']) / 'System32' / item['name']
            unlinked(source)
            if fingerprint(source) != item['sha256']:
                raise ValueError('Benign source changed after signature check')
            content = source.read_bytes()
            if len(content) > MAX_BYTES or hashlib.sha256(content).hexdigest() != item['sha256']:
                raise ValueError('Benign source changed/oversized')
            name = 'benign-' + item['name'].replace('/', '-') + '.bin'
            with (corpus / name).open('xb') as stream:
                stream.write(content)
            entries.append(
                dict(
                    path=name,
                    sha256=item['sha256'],
                    label='benign',
                    provenance='Guest Windows image; valid Microsoft Authenticode signature: '
                    + item['signer'],
                )
            )
        except Exception as error:
            benign_omitted.append(dict(name=item['name'], error=str(error)[:1000]))
    if not entries:
        raise ValueError('No eligible files')
    manifest = corpus / 'manifest.json'
    manifest.write_text(json.dumps(dict(schema=1, files=entries), indent=2), encoding='utf-8')
    if prepare_only:
        report = dict(
            schema=1,
            corpus_plan=dict(
                imports=imports, import_failures=failures, benign_omissions=benign_omitted
            ),
            sample_execution=False,
        )
        (area / 'report.json').write_text(json.dumps(report), encoding='utf-8')
        (root / 'static-corpus-latest.json').write_text(
            json.dumps(dict(report=str(area / 'report.json'))), encoding='utf-8'
        )
        return manifest
    if signature_free:
        options = dict(
            signature_free=True,
            advanced=True,
            content=True,
            documents=True,
            emulation=True,
            model=True,
            neural=True,
            reputation=False,
            amsi=False,
            emulation_profile='lab',
        )
        report = evaluate(manifest, options=options)
        report['corpus_plan'] = dict(
            revision=REVISION,
            imports=imports,
            import_failures=failures,
            benign_omissions=benign_omitted,
            host_storage='AES-256-GCM ciphertext',
            guest_only_unpacking=True,
            selection_before_scanning=True,
            interpretation='Fixed selected historical specimens, not the entire Zoo repository or a training-unseen benchmark',
        )
        report['inspection_options'] = options
        if failures or benign_omitted:
            report['status'] = 'Incomplete / review omissions'
        (area / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        (root / 'static-corpus-latest.json').write_text(
            json.dumps(dict(report=str(area / 'report.json'))), encoding='utf-8'
        )
        return 0
    # Identical inspection settings in both passes. An isolated empty signature
    # directory disables exact hashes for outer AND derived content, without
    # adding trust exclusions or modifying installed definitions.
    options = dict(
        advanced=True, content=True, documents=True, emulation=False, model=False, reputation=False
    )
    report = evaluate(manifest, options=options)
    empty = area / 'hash-disabled' / 'signatures.json'
    empty.parent.mkdir()
    empty.write_text('{}', encoding='utf-8')
    ablation = evaluate(manifest, options=options, signature_path=empty)
    if any(
        row.get('definitions', {}).get('count') != 0 for row in ablation['rows'] if 'scan' in row
    ):
        raise ValueError('Exact-hash ablation did not establish an empty signature index')
    ablation['hash_signatures_disabled'] = True
    ablation['inspection_options'] = options
    report['hash_ablation'] = ablation
    emulated = evaluate(manifest, options={**options, 'emulation': True}, signature_path=empty)
    if any(
        row.get('definitions', {}).get('count') != 0 for row in emulated['rows'] if 'scan' in row
    ):
        raise ValueError('Emulator hash ablation did not establish an empty signature index')
    from sentinelav.lab.emulation_evaluation import metrics

    for row in emulated['rows']:
        row['emulation_metrics'] = metrics(row)
    emulated['hash_signatures_disabled'] = True
    emulated['inspection_options'] = {**options, 'emulation': True}
    emulated['native_sample_execution'] = False
    report['hash_disabled_emulation'] = emulated
    report['inspection_options'] = options
    report['comparison_limit'] = (
        'Historical samples: no-hash detection is not proof of unknown-malware coverage; rules may recognize these families.'
    )
    report['corpus_plan'] = dict(
        revision=REVISION,
        families=[s['family'] for s in specs],
        holdout=holdout,
        zeus_validation=zeus_validation,
        imports=imports,
        import_failures=failures,
        benign_provenance=benign,
        benign_omissions=benign_omitted,
        selection_before_scanning=True,
        host_storage='AES-256-GCM ciphertext',
        guest_only_unpacking=True,
    )
    if failures or benign_omitted:
        report['status'] = 'Incomplete / review omissions'
    (area / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (area / 'report.html').write_text(render(report), encoding='utf-8')
    (root / 'static-corpus-latest.json').write_text(
        json.dumps(dict(report=str(area / 'report.json'))), encoding='utf-8'
    )
    return 0

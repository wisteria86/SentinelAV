# Purpose: One pinned research sample, guest-only decoding and static inspection.
# Works with: lab.corpus_evaluation
# Used by: entrypoint, lab.static_corpus, tests.unit.test_static_pilot, tools.evaluation.acquire_pilot

"""One pinned research sample, guest-only decoding and static inspection."""
import base64
import hashlib
from io import BytesIO
import json
from pathlib import Path
import uuid
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sentinelav.lab.corpus_evaluation import evaluate,render,unlinked,verified_offline_guest,MAX_BYTES

REVISION='48515e492013bc5bb2769249ea539436bb3e733f'
ARCHIVE_BYTES=3481589
ARCHIVE_BLOB='4a7b532e7fc6d51033a0e97e7cf1f4192528d686'
SAMPLE_SHA256='ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa'
AAD=b'SentinelAV-static-pilot-v1'


def validate_archive(raw):
    if len(raw)!=ARCHIVE_BYTES or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=ARCHIVE_BLOB:
        raise ValueError('Pinned archive identity mismatch')
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        files=[i for i in archive.infolist() if not i.is_dir()]
        if not 1<=len(files)<=4 or any(not i.flag_bits&1 for i in files):
            raise ValueError('Expected a bounded encrypted archive')
        if sum(i.file_size for i in files)>MAX_BYTES or any(i.file_size/max(1,i.compress_size)>100 for i in files):
            raise ValueError('Archive expansion limit exceeded')
        return [{'bytes':i.file_size,'encrypted':bool(i.flag_bits&1)} for i in files]


def decode_sample(raw):
    validate_archive(raw)
    found=None
    total=0
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        for info in archive.infolist():
            if info.is_dir(): continue
            with archive.open(info,pwd=b'infected') as stream:
                content=stream.read(MAX_BYTES+1)
            total+=len(content)
            if len(content)!=info.file_size or total>MAX_BYTES: raise ValueError('Decoded size limit/mismatch')
            if hashlib.sha256(content).hexdigest()==SAMPLE_SHA256:
                if found is not None: raise ValueError('Duplicate pinned sample')
                found=content
    if found is None: raise ValueError('Published sample SHA-256 not found')
    return found


def main(key_text):
    if not verified_offline_guest(): raise ValueError('Offline Windows test guest required')
    root=Path('C:/SentinelAV-Test')
    input_root=Path('C:/SentinelAV-Input')
    for p in (root,input_root): unlinked(p)
    preflight=json.loads((root/'preflight.json').read_text())
    inventory=json.loads((input_root/'manifest.json').read_text(encoding='utf-8-sig'))
    if preflight['kit_id']!=inventory['kit_id']: raise ValueError('Guest kit mismatch')
    sealed_path=input_root/'pilot.sealed'
    unlinked(sealed_path)
    if sealed_path.stat().st_size!=ARCHIVE_BYTES+28: raise ValueError('Sealed archive size mismatch')
    sealed=sealed_path.read_bytes()
    if hashlib.sha256(sealed).hexdigest()!=inventory['files']['pilot.sealed']: raise ValueError('Sealed input digest mismatch')
    key=base64.b64decode(key_text,validate=True)
    if len(key)!=32: raise ValueError('Invalid transfer key length')
    raw=AESGCM(key).decrypt(sealed[:12],sealed[12:],AAD)
    content=decode_sample(raw)
    area=root/('StaticPilot-'+uuid.uuid4().hex)
    area.mkdir(exist_ok=False)
    corpus=area/'corpus'
    corpus.mkdir()
    # Ignore all archive filenames: only the hash-verified bytes get a fixed
    # inert filename, with no shell invocation, loader or file association.
    with (corpus/'sample.bin').open('xb') as stream: stream.write(content)
    manifest=corpus/'manifest.json'
    manifest.write_text(json.dumps(dict(schema=1,files=[dict(path='sample.bin',sha256=SAMPLE_SHA256,label='malware',
        provenance='ytisf/theZoo Ransomware.WannaCry, revision '+REVISION+'; pinned Git archive blob '+ARCHIVE_BLOB+'; published sample SHA-256 verified')]),indent=2),encoding='utf-8')
    report=evaluate(manifest)
    report['pilot']=dict(repository_revision=REVISION,archive_blob_sha1=ARCHIVE_BLOB,sample_sha256=SAMPLE_SHA256,
                         guest_only_sample_unpacking=True,archive_decrypted_in_guest=True,host_storage='AES-256-GCM ciphertext',sample_executed=False)
    (area/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (area/'report.html').write_text(render(report),encoding='utf-8')
    (root/'static-pilot-latest.json').write_text(json.dumps(dict(report=str(area/'report.json'),sample_sha256=SAMPLE_SHA256)),encoding='utf-8')
    return 0

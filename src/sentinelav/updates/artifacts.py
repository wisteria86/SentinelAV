# Purpose: Signed JSON model/reputation/policy distribution with explicit activation.
# Works with: detection.classifier, detection.fusion, detection.reputation
# Used by: detection.advanced_pipeline, entrypoint, lab.qualification.features, lab.qualification.inventories

"""Signed JSON model/reputation/policy distribution with explicit activation."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.request
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from PySide6.QtCore import QLockFile

KINDS={'model','reputation','policy'}
LIMIT=16*1024*1024


def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def bounded_json(path,limit=LIMIT):
    path=Path(path)
    if any(p.is_symlink() or p.is_junction() for p in (path,*path.parents)): raise ValueError('Linked artifact path')
    with path.open('rb') as stream: raw=stream.read(limit+1)
    if len(raw)>limit: raise ValueError('Artifact size exceeded')
    return json.loads(raw)


def verify(envelope,trust,kind,now=None):
    if not isinstance(envelope,dict) or not isinstance(trust,dict) or not isinstance(trust.get('keys'),dict): raise ValueError('Invalid artifact/trust object')
    if kind not in KINDS or envelope.get('schema')!=1: raise ValueError('Unsupported artifact')
    manifest=envelope['manifest']
    if not isinstance(manifest,dict) or set(manifest)!={'kind','key_id','revision','issued','expires','payload_sha256'} or manifest['kind']!=kind:
        raise ValueError('Artifact manifest mismatch')
    if type(manifest['revision']) is not int or manifest['revision']<1: raise ValueError('Invalid revision')
    if not isinstance(manifest['key_id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',manifest['key_id']): raise ValueError('Invalid publisher ID')
    now=time.time() if now is None else now
    if any(type(manifest[k]) is not int for k in ('issued','expires')) or not manifest['issued']<=now<manifest['expires']:
        raise ValueError('Artifact outside validity interval')
    public=trust.get('keys',{}).get(manifest['key_id'])
    if not isinstance(public,str) or not re.fullmatch('[0-9a-fA-F]{64}',public): raise ValueError('Publisher key is not pinned')
    payload=envelope['payload']
    if not isinstance(payload,dict): raise ValueError('Artifact payload must be a JSON object')
    if hashlib.sha256(canonical(payload)).hexdigest()!=manifest['payload_sha256']: raise ValueError('Artifact digest mismatch')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(base64.b64decode(envelope['signature'],validate=True),canonical(manifest))
    if kind=='model':
        from sentinelav.detection.classifier import validate_model
        validate_model(payload)
    elif kind=='reputation':
        from sentinelav.detection.reputation import ReputationIndex
        ReputationIndex(payload,manifest)
    elif kind=='policy':
        from sentinelav.detection.fusion import validate_policy
        validate_policy(payload)
    return payload


def active(folder,trust_path,kind):
    folder=Path(folder)
    index=bounded_json(folder/'active.json',65536)
    name=index[kind]['file']
    if not re.fullmatch(kind+r'-[0-9a-f]{32}\.json',name): raise ValueError('Invalid active artifact name')
    envelope=bounded_json(folder/name)
    payload=verify(envelope,bounded_json(trust_path,65536),kind)
    if envelope['manifest']['revision']!=index[kind]['revision']: raise ValueError('Artifact revision mismatch')
    return payload,envelope['manifest']


def activate(envelope_path,folder,trust_path,kind):
    envelope=bounded_json(envelope_path)
    verify(envelope,bounded_json(trust_path,65536),kind)
    folder=Path(folder).absolute()
    if any(p.is_symlink() or p.is_junction() for p in (folder,*folder.parents)): raise ValueError('Linked artifact store')
    folder.mkdir(parents=True,exist_ok=True)
    lock=QLockFile(str(folder/'activation.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(0): raise ValueError('Artifact activation already running')
    try:
        index=bounded_json(folder/'active.json',65536) if (folder/'active.json').exists() else {}
        revision=envelope['manifest']['revision']
        if revision<=index.get(kind,{}).get('revision',0): raise ValueError('Artifact rollback/replay rejected')
        name=kind+'-'+uuid.uuid4().hex+'.json'
        with (folder/name).open('xb') as stream:
            stream.write(canonical(envelope)); stream.flush(); os.fsync(stream.fileno())
        index[kind]=dict(file=name,revision=revision)
        pending=folder/('active-'+uuid.uuid4().hex+'.pending')
        with pending.open('xb') as stream:
            stream.write(canonical(index)); stream.flush(); os.fsync(stream.fileno())
        os.replace(pending,folder/'active.json')
        return index[kind]
    finally: lock.unlock()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Update redirects refused')


def download(url,destination):
    from urllib.parse import urlsplit
    parsed=urlsplit(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Updates require a configured HTTPS URL without credentials/fragments')
    opener=urllib.request.build_opener(NoRedirect())
    deadline=time.monotonic()+20
    raw=bytearray()
    with opener.open(urllib.request.Request(url,headers={'User-Agent':'SentinelAV-artifact-updater/1'}),timeout=5) as response:
        while len(raw)<=LIMIT:
            if time.monotonic()>deadline: raise TimeoutError('Artifact download wall-clock budget exceeded')
            block=response.read(min(16384,LIMIT+1-len(raw)))
            if not block: break
            raw.extend(block)
    if len(raw)>LIMIT: raise ValueError('Update download limit exceeded')
    with Path(destination).open('xb') as stream: stream.write(raw)
    return destination

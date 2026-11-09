# Purpose: Parse and validate signed update payloads and bounded change records.
# Works with: paths, updates.hash_archive
# Used by: updates.definition_updates, updates.hash_snapshots

"""Versioned definition updates, reviewed corrections, and explicit rollback.

Local imports are not publisher-authenticated. Signed deltas require a pinned
Ed25519 key and bind payload, base snapshot, revision, and validity interval.
All operations leave old immutable snapshots available to existing readers.
"""
from sentinelav.paths import RESOURCE_ROOT
from datetime import datetime,timezone,timedelta
import hashlib
import io
import json
from pathlib import Path
import re
from zipfile import ZipFile
from sentinelav.updates.hash_archive import records

ROOT=RESOURCE_ROOT
MAX_PAYLOAD=32*1024*1024


def unique_object(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError('Duplicate JSON field')
        value[key]=item
    return value


def read_json(path,limit=16384):
    path=Path(path)
    if path.is_symlink() or path.is_junction() or path.stat().st_size>limit:
        raise ValueError('Linked or oversized update metadata rejected')
    return json.loads(path.read_bytes(),object_pairs_hook=unique_object)


def changes_from_csv(path):
    path=Path(path)
    if not 0<path.stat().st_size<=MAX_PAYLOAD:
        raise ValueError('Recent CSV exceeds size limit')
    raw=path.read_bytes()
    entries={}
    for digest,label,seen,file_type in records(io.StringIO(raw.decode('utf-8-sig'))):
        item=entries.setdefault(digest.hex(),dict(sha256=digest.hex(),labels=[],first_seen=seen,file_type=file_type))
        if label not in item['labels']: item['labels'].append(label)
        if len(entries)>100000: raise ValueError('Recent CSV exceeds record limit')
    changes=dict(upserts=list(entries.values()),removals=[])
    validate_changes(changes)
    return changes,hashlib.sha256(raw).hexdigest()


def validate_changes(changes):
    if not isinstance(changes,dict) or set(changes)!={'upserts','removals'}:
        raise ValueError('Expected upserts and removals')
    upserts,removals=changes['upserts'],changes['removals']
    if (not isinstance(upserts,list) or not isinstance(removals,list) or len(upserts)>100000
            or len(removals)>100000 or not (upserts or removals)):
        raise ValueError('Invalid delta sizes')
    seen=set()
    for item in upserts:
        if not isinstance(item,dict) or set(item)-{'sha256','labels','first_seen','file_type'}:
            raise ValueError('Unsupported delta fields')
        digest=item.get('sha256')
        labels=item.get('labels')
        if (not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest) or digest in seen
                or not isinstance(labels,list) or not 1<=len(labels)<=16):
            raise ValueError('Invalid or duplicate upsert')
        seen.add(digest)
        for label in labels:
            if not isinstance(label,str) or not 1<=len(label)<=200 or any(ord(c)<32 for c in label):
                raise ValueError('Invalid label')
        for field in ('first_seen','file_type'):
            value=item.get(field,'')
            if not isinstance(value,str) or len(value)>64 or any(ord(c)<32 for c in value):
                raise ValueError('Invalid delta metadata')
    for digest in removals:
        if not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest) or digest in seen:
            raise ValueError('Duplicate, conflicting, or invalid removal')
        seen.add(digest)
    return changes


def verify_package(path,trust_path,now=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    now=now or datetime.now(timezone.utc)
    with ZipFile(path) as zipped:
        infos=zipped.infolist()
        expected={'manifest.json','changes.json','signature.ed25519'}
        if len(infos)!=3 or {i.filename for i in infos}!=expected or any(i.flag_bits&1 for i in infos):
            raise ValueError('Unsupported update archive members')
        limits={'manifest.json':16384,'changes.json':MAX_PAYLOAD,'signature.ed25519':64}
        if any(i.file_size>limits[i.filename] for i in infos): raise ValueError('Update package exceeds size limits')
        raw=zipped.read('manifest.json')
        manifest=json.loads(raw,object_pairs_hook=unique_object)
        required={'format','channel','key_id','revision','issued_utc','expires_utc','base_database_sha256','changes_sha256'}
        if (not isinstance(manifest,dict) or set(manifest)!=required or type(manifest['format']) is not int
                or manifest['format']!=1 or manifest['channel']!='stable'
                or type(manifest['revision']) is not int or not 1<=manifest['revision']<=2**53
                or not isinstance(manifest['key_id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',manifest['key_id'])):
            raise ValueError('Invalid signed manifest')
        trust=read_json(trust_path)
        if not isinstance(trust,dict) or trust.get('schema')!=1 or not isinstance(trust.get('keys'),dict):
            raise ValueError('Invalid publisher trust store')
        public=trust['keys'].get(manifest['key_id'])
        if not isinstance(public,str) or not re.fullmatch(r'[0-9a-f]{64}',public):
            raise ValueError('Update publisher is not trusted; no key was imported from this package')
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(zipped.read('signature.ed25519'),raw)
        except (InvalidSignature,ValueError): raise ValueError('Publisher signature verification failed') from None
        try:
            issued=datetime.fromisoformat(manifest['issued_utc'])
            expires=datetime.fromisoformat(manifest['expires_utc'])
            if issued.tzinfo is None or expires.tzinfo is None: raise ValueError()
        except (TypeError,ValueError): raise ValueError('Invalid package validity timestamps') from None
        if issued>now+timedelta(minutes=5) or expires<=now or not timedelta(0)<expires-issued<=timedelta(days=14):
            raise ValueError('Update expired, not yet valid, or has excessive validity')
        payload=zipped.read('changes.json')
        if hashlib.sha256(payload).hexdigest()!=manifest['changes_sha256']:
            raise ValueError('Signed update payload checksum failed')
        if not re.fullmatch(r'[0-9a-f]{64}',str(manifest['base_database_sha256'])):
            raise ValueError('Invalid base snapshot hash')
        changes=validate_changes(json.loads(payload,object_pairs_hook=unique_object))
    return changes,manifest

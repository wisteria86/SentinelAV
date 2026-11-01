"""Versioned definition updates, reviewed corrections, and explicit rollback.

Local imports are not publisher-authenticated. Signed deltas require a pinned
Ed25519 key and bind payload, base snapshot, revision, and validity interval.
All operations leave old immutable snapshots available to existing readers.
"""
from sentinelav.paths import RESOURCE_ROOT
import argparse
from contextlib import contextmanager
from datetime import datetime,timezone,timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import uuid
from zipfile import ZipFile
from PySide6.QtCore import QLockFile
from sentinelav.updates.hash_archive import checksum,records

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


def ensure_directory(folder):
    folder=Path(folder).absolute()
    for part in [folder,*folder.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError('Update directory cannot contain links')
    folder.mkdir(parents=True,exist_ok=True)
    return folder


@contextmanager
def update_lock(folder):
    folder=ensure_directory(folder)
    lock=QLockFile(str(folder/'update.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        raise ValueError('Another definition update is in progress')
    try: yield folder
    finally: lock.unlock()


def load_active(folder,verify=False):
    folder=Path(folder)
    metadata=read_json(folder/'active.json')
    if not isinstance(metadata,dict): raise ValueError('Invalid active manifest')
    name=metadata.get('database','')
    if (type(metadata.get('schema')) is not int or metadata['schema']!=1
            or not isinstance(name,str) or not re.fullmatch(r'hashes-[0-9a-f]{32}\.sqlite',name)
            or type(metadata.get('unique_sha256')) is not int or metadata['unique_sha256']<1
            or not re.fullmatch(r'[0-9a-f]{64}',str(metadata.get('database_sha256','')))):
        raise ValueError('Invalid active definition metadata')
    db=folder/name
    if db.is_symlink() or db.is_junction() or not db.is_file():
        raise ValueError('Definition snapshot missing or linked')
    if verify and checksum(db)!=metadata['database_sha256']:
        raise ValueError('Definition snapshot checksum failed')
    return metadata


def activate_snapshot(folder,metadata):
    """Caller must hold update_lock. Commit history and pointer atomically."""
    folder=Path(folder)
    metadata=dict(metadata)
    previous=folder/'active.json'
    identity=uuid.uuid4().hex
    high=metadata.get('highest_signed_revision',0)
    if previous.exists():
        current=load_active(folder)
        high=max(high,current.get('highest_signed_revision',0))
        backup=folder/f'previous-{identity}.json'
        with backup.open('xb') as stream:
            stream.write(previous.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        metadata['previous_manifest']=backup.name
    metadata['highest_signed_revision']=high
    metadata['activated_utc']=datetime.now(timezone.utc).isoformat()
    temporary=folder/f'activate-{identity}.tmp'
    try:
        with temporary.open('xb') as stream:
            stream.write(json.dumps(metadata,indent=2).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,previous)
    finally:
        if temporary.exists(): temporary.unlink()
    return metadata


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


def apply_changes(folder,changes,provenance,package=None,restore_revoked=True):
    validate_changes(changes)
    with update_lock(folder) as folder:
        current=load_active(folder,verify=True)
        if package is not None:
            if package['base_database_sha256']!=current['database_sha256']:
                raise ValueError('Signed update targets a different base snapshot')
            if package['revision']<=current.get('highest_signed_revision',0):
                raise ValueError('Signed update revision is a replay or downgrade')
        identity=uuid.uuid4().hex
        target=folder/f'hashes-{identity}.sqlite'
        source=sqlite3.connect((folder/current['database']).resolve().as_uri()+'?mode=ro&immutable=1',uri=True)
        db=sqlite3.connect(target)
        complete=False
        try:
            source.backup(db)
            source.close()
            db.execute('CREATE TABLE IF NOT EXISTS revocations(sha256 BLOB PRIMARY KEY,reason TEXT NOT NULL) WITHOUT ROWID')
            added=corrected=removed=ignored_revoked=0
            for item in changes['upserts']:
                digest=bytes.fromhex(item['sha256'])
                if not restore_revoked and db.execute('SELECT 1 FROM revocations WHERE sha256=?',(digest,)).fetchone():
                    ignored_revoked+=1
                    continue
                exists=db.execute('SELECT 1 FROM hashes WHERE sha256=?',(digest,)).fetchone()
                added+=not bool(exists)
                corrected+=bool(exists)
                db.execute('INSERT OR REPLACE INTO hashes VALUES (?,?,?)',(digest,item.get('first_seen',''),item.get('file_type','')))
                db.execute('DELETE FROM labels WHERE sha256=?',(digest,))
                db.executemany('INSERT OR IGNORE INTO labels VALUES (?,?)',((digest,label) for label in item['labels']))
                db.execute('DELETE FROM revocations WHERE sha256=?',(digest,))
            for hex_digest in changes['removals']:
                digest=bytes.fromhex(hex_digest)
                removed+=bool(db.execute('SELECT 1 FROM hashes WHERE sha256=?',(digest,)).fetchone())
                db.execute('DELETE FROM hashes WHERE sha256=?',(digest,))
                db.execute('DELETE FROM labels WHERE sha256=?',(digest,))
                db.execute('INSERT OR REPLACE INTO revocations VALUES (?,?)',(digest,'Explicit reviewed source correction'))
            count=db.execute('SELECT COUNT(*) FROM hashes').fetchone()[0]
            if count<1: raise ValueError('Refusing an update that removes every hash')
            metadata=dict(current)
            for field in ('previous_manifest','database_sha256','activated_utc','skipped_physical_lines'):
                metadata.pop(field,None)
            if package is None:
                for field in ('publisher_key_id','package_issued_utc','package_expires_utc'):
                    metadata.pop(field,None)
            metadata.update(database=target.name,unique_sha256=count,imported_utc=datetime.now(timezone.utc).isoformat(),
                update_method=provenance,base_database_sha256=current['database_sha256'],
                delta=dict(added=added,reclassified=corrected,removed=removed,explicit_removal_requests=len(changes['removals']),ignored_revoked=ignored_revoked))
            metadata['definition_updated_utc']=(metadata['imported_utc'] if changes['upserts'] else current.get('definition_updated_utc',current['imported_utc']))
            if package:
                metadata.update(highest_signed_revision=package['revision'],publisher_key_id=package['key_id'],
                                package_issued_utc=package['issued_utc'],package_expires_utc=package['expires_utc'])
            db.execute('DELETE FROM metadata')
            db.executemany('INSERT INTO metadata VALUES (?,?)',((k,json.dumps(v)) for k,v in metadata.items()))
            db.commit()
            if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('Updated database failed integrity check')
            db.close()
            db=None
            metadata['database_sha256']=checksum(target)
            (folder/f'candidate-{identity}.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
            complete=True
            return activate_snapshot(folder,metadata)
        finally:
            source.close()
            if db is not None: db.close()
            if not complete and target.exists(): target.unlink()


def import_recent(folder,path):
    changes,digest=changes_from_csv(path)
    return apply_changes(folder,changes,'Manual recent CSV import; payload SHA-256 '+digest,restore_revoked=False)


def apply_signed(folder,path,trust_path):
    changes,package=verify_package(path,trust_path)
    return apply_changes(folder,changes,'Verified Ed25519 publisher package',package)


def rollback(folder):
    with update_lock(folder) as folder:
        current=load_active(folder,verify=True)
        name=current.get('previous_manifest','')
        if not isinstance(name,str) or not re.fullmatch(r'previous-[0-9a-f]{32}\.json',name):
            raise ValueError('No previous snapshot is available')
        previous=read_json(folder/name)
        # Validate the exact prior snapshot without replacing the active pointer.
        database=previous.get('database','')
        if not isinstance(database,str) or not re.fullmatch(r'hashes-[0-9a-f]{32}\.sqlite',database):
            raise ValueError('Invalid rollback manifest')
        target=folder/database
        if target.is_symlink() or checksum(target)!=previous.get('database_sha256'):
            raise ValueError('Rollback snapshot checksum failed')
        previous['update_method']='Explicit user rollback; previous definition age retained'
        return activate_snapshot(folder,previous)


def freshness(metadata,now=None):
    now=now or datetime.now(timezone.utc)
    try:
        stamp=datetime.fromisoformat(metadata.get('definition_updated_utc',metadata.get('imported_utc','')))
        if stamp.tzinfo is None: raise ValueError()
        hours=(now-stamp).total_seconds()/3600
        if hours<-.1: return 'Clock mismatch',None
        return ('Stale' if hours>48 else 'Recent import'),round(max(0,hours),1)
    except (KeyError,TypeError,ValueError): return 'Age unknown',None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['status','recent','signed','corrections','rollback'])
    parser.add_argument('file',nargs='?',type=Path)
    args=parser.parse_args()
    folder=ROOT/'signature-data'
    if args.action in ('recent','signed','corrections') and args.file is None: parser.error('A file is required')
    if args.action=='recent': value=import_recent(folder,args.file)
    elif args.action=='signed': value=apply_signed(folder,args.file,ROOT/'trusted-update-keys.json')
    elif args.action=='corrections': value=apply_changes(folder,read_json(args.file,MAX_PAYLOAD),'Manual explicit corrections; not publisher-authenticated')
    elif args.action=='rollback': value=rollback(folder)
    else: value=load_active(folder)
    print(json.dumps(dict(metadata=value,freshness=freshness(value)),indent=2))


if __name__=='__main__': main()

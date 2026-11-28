# Purpose: Versioned definition updates, reviewed corrections, and explicit rollback.
# Works with: paths, updates.hash_archive, updates.hash_snapshots, updates.update_envelope
# Used by: ui.updates_ui, updates.hash_archive, tests.ui.verify_updates_ui, tests.unit.test_definition_updates

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


from .update_envelope import unique_object, read_json, changes_from_csv, validate_changes, verify_package
from .hash_snapshots import ensure_directory, update_lock, load_active, activate_snapshot


def apply_changes(folder,changes,provenance,package=None,restore_revoked=True):
    """Create a new hash-database snapshot with the given additions and removals, then make it active.

    The current database is copied, the changes are applied (removed hashes are remembered as
    revocations so later imports do not bring them back), the result is integrity-checked, and the
    active pointer is switched atomically. For a signed package, it must target the current snapshot
    and have a higher revision.
    """
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
    """Import a 'recent additions' CSV export into a new snapshot. Not publisher-authenticated."""
    changes,digest=changes_from_csv(path)
    return apply_changes(folder,changes,'Manual recent CSV import; payload SHA-256 '+digest,restore_revoked=False)


def apply_signed(folder,path,trust_path):
    """Verify a signed update package with the pinned publisher key and apply it."""
    changes,package=verify_package(path,trust_path)
    return apply_changes(folder,changes,'Verified Ed25519 publisher package',package)


def rollback(folder):
    """Switch back to the previous snapshot after checking its checksum."""
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
    """Describe how old the definitions are: 'Recent import' (48 hours or less), 'Stale', 'Clock
    mismatch' or 'Age unknown', plus the age in hours.
    """
    now=now or datetime.now(timezone.utc)
    try:
        stamp=datetime.fromisoformat(metadata.get('definition_updated_utc',metadata.get('imported_utc','')))
        if stamp.tzinfo is None: raise ValueError()
        hours=(now-stamp).total_seconds()/3600
        if hours<-.1: return 'Clock mismatch',None
        return ('Stale' if hours>48 else 'Recent import'),round(max(0,hours),1)
    except (KeyError,TypeError,ValueError): return 'Age unknown',None


def main():
    """Command-line tool for definition updates: status, recent, signed, corrections or rollback."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['status','recent','signed','corrections','rollback'])
    parser.add_argument('file',nargs='?',type=Path)
    args=parser.parse_args()
    from sentinelav.detection.definition_paths import signature_data_dir
    folder=signature_data_dir(ROOT)
    if args.action in ('recent','signed','corrections') and args.file is None: parser.error('A file is required')
    if args.action=='recent': value=import_recent(folder,args.file)
    elif args.action=='signed': value=apply_signed(folder,args.file,ROOT/'trusted-update-keys.json')
    elif args.action=='corrections': value=apply_changes(folder,read_json(args.file,MAX_PAYLOAD),'Manual explicit corrections; not publisher-authenticated')
    elif args.action=='rollback': value=rollback(folder)
    else: value=load_active(folder)
    print(json.dumps(dict(metadata=value,freshness=freshness(value)),indent=2))


if __name__=='__main__': main()

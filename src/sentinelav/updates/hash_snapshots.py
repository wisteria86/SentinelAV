# Purpose: Lock and atomically activate verified hash-database snapshots.
# Works with: paths, updates.hash_archive, updates.update_envelope
# Used by: updates.definition_updates

"""Versioned definition updates, reviewed corrections, and explicit rollback.

Local imports are not publisher-authenticated. Signed deltas require a pinned
Ed25519 key and bind payload, base snapshot, revision, and validity interval.
All operations leave old immutable snapshots available to existing readers.
"""
from sentinelav.paths import RESOURCE_ROOT
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import uuid
from PySide6.QtCore import QLockFile
from sentinelav.updates.hash_archive import checksum

ROOT=RESOURCE_ROOT
MAX_PAYLOAD=32*1024*1024
from .update_envelope import read_json


def ensure_directory(folder):
    """Create the update folder if needed, refusing any linked part of the path."""
    folder=Path(folder).absolute()
    for part in [folder,*folder.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError('Update directory cannot contain links')
    folder.mkdir(parents=True,exist_ok=True)
    return folder


@contextmanager
def update_lock(folder):
    """Hold the definition-update lock for the duration of a `with` block; raises ValueError if another
    update is running.
    """
    folder=ensure_directory(folder)
    lock=QLockFile(str(folder/'update.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        raise ValueError('Another definition update is in progress')
    try: yield folder
    finally: lock.unlock()


def load_active(folder,verify=False):
    """Read and validate the active definition manifest. With verify=True the database file's checksum
    is checked too.
    """
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

# Purpose: Explicit per-user publisher pinning, separate from OS and definition trust.
# Works with: updates.artifacts
# Used by: ui.helpers.defense_settings, tests.unit.test_analysis_artifacts, tools.feeds.enable_learned_detection,
#   tools.feeds.install_benchmark_models

"""Explicit per-user publisher pinning, separate from OS and definition trust."""

import hashlib
import os
from pathlib import Path
import re
import uuid
from PySide6.QtCore import QLockFile
from sentinelav.updates.artifacts import bounded_json, canonical


def fingerprint(public):
    """Return the SHA-256 of an Ed25519 public key given in hex, after checking its format."""
    if not isinstance(public, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', public):
        raise ValueError('Expected 32-byte Ed25519 public key in hex')
    return hashlib.sha256(bytes.fromhex(public)).hexdigest()


def update_pin(path, key_id, public=None):
    """Add (public given) or remove (public=None) a trusted publisher key in the trust file, then save
    it atomically.

    Replacing an existing key under the same id is refused; the old pin must be removed explicitly
    first.
    """
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', key_id):
        raise ValueError('Invalid publisher key ID')
    path = Path(path).absolute()
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError('Linked trust path')
    if public is not None:
        fingerprint(public)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(path) + '.lock')
    lock.setStaleLockTime(0)
    if not lock.tryLock(0):
        raise ValueError('Trust update is already running')
    try:
        value = bounded_json(path, 65536) if path.exists() else dict(schema=1, keys={})
        if value.get('schema') != 1 or not isinstance(value.get('keys'), dict):
            raise ValueError('Invalid analysis trust store')
        if public is None:
            if key_id not in value['keys']:
                raise ValueError('Publisher is not pinned')
            del value['keys'][key_id]
        else:
            if key_id in value['keys'] and value['keys'][key_id] != public.lower():
                raise ValueError('Remove the old pin explicitly before replacing a key ID')
            if len(value['keys']) >= 32 and key_id not in value['keys']:
                raise ValueError('Publisher pin limit')
            value['keys'][key_id] = public.lower()
        pending = path.with_name(path.name + '.' + uuid.uuid4().hex + '.pending')
        with pending.open('xb') as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        return value
    finally:
        lock.unlock()

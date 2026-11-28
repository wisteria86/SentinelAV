# Purpose: Streaming authenticated quarantine format; older whole-file DPAPI items stay readable.
# Works with: response.response_files
# Used by: response.response, tests.unit.test_vault

"""Streaming authenticated quarantine format; older whole-file DPAPI items stay readable.

Each chunk is AES-256-GCM with a per-item key wrapped by Windows DPAPI. The chunk index
and a final-chunk flag are authenticated, so reordering or truncation fails verification.
"""

import hashlib
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .response_files import dpapi

MAGIC = b'SAVC1\n'
CHUNK = 1024 * 1024
VAULT_LIMIT = 4 * 1024**3
TAG_OVERHEAD = 12 + 16 + 5


def _associated(identity, index, final):
    """Build the extra authenticated data for one chunk: the item id, the chunk number and whether it
    is the last chunk.
    """
    return identity + struct.pack('<IB', index, int(final))


def encrypt_stream(source, output, identity):
    """Encrypt source into output and return the plaintext SHA-256 and byte count."""
    # A fresh random key per item, which is itself encrypted with DPAPI and stored at the start of
    # the file.
    key = os.urandom(32)
    cipher = AESGCM(key)
    wrapped = dpapi(key)
    output.write(MAGIC + struct.pack('<I', len(wrapped)) + wrapped)
    digest = hashlib.sha256()
    total = 0
    index = 0
    current = source.read(CHUNK)
    while True:
        following = source.read(CHUNK)
        final = not following
        digest.update(current)
        total += len(current)
        if total > VAULT_LIMIT:
            raise ValueError('File exceeds the 4 GiB quarantine limit')
        nonce = os.urandom(12)
        sealed = cipher.encrypt(nonce, current, _associated(identity, index, final))
        output.write(struct.pack('<IB', len(sealed), int(final)) + nonce + sealed)
        if final:
            break
        current = following
        index += 1
    return digest.hexdigest(), total


def read_plain(path, identity):
    """Yield verified plaintext chunks. Any tampering raises ValueError."""
    with open(path, 'rb') as stream:
        if stream.read(len(MAGIC)) != MAGIC:
            stream.seek(0)
            yield dpapi(stream.read(), decrypt=True)
            return
        raw = stream.read(4)
        if len(raw) != 4:
            raise ValueError('Quarantine integrity check failed')
        size = struct.unpack('<I', raw)[0]
        if not 0 < size <= 65536:
            raise ValueError('Quarantine integrity check failed')
        try:
            cipher = AESGCM(dpapi(stream.read(size), decrypt=True))
        except OSError as error:
            raise ValueError('Quarantine key cannot be opened by this Windows account') from error
        index = 0
        while True:
            header = stream.read(5)
            if len(header) != 5:
                raise ValueError('Quarantine integrity check failed: truncated')
            length, final = struct.unpack('<IB', header)
            if length > CHUNK + 16:
                raise ValueError('Quarantine integrity check failed')
            nonce = stream.read(12)
            sealed = stream.read(length)
            try:
                yield cipher.decrypt(nonce, sealed, _associated(identity, index, final))
            except InvalidTag as error:
                raise ValueError('Quarantine integrity check failed') from error
            if final:
                if stream.read(1):
                    raise ValueError('Quarantine integrity check failed: trailing data')
                return
            index += 1


def plain_digest(path, identity):
    """Decrypt a quarantined file in memory and return the SHA-256 of its original content."""
    digest = hashlib.sha256()
    for chunk in read_plain(path, identity):
        digest.update(chunk)
    return digest.hexdigest()


def maximum_blob(size):
    """Return the largest size an encrypted quarantine file of `size` original bytes can legitimately
    have.
    """
    return size + (size // CHUNK + 1) * TAG_OVERHEAD + 1024 * 1024

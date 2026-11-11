# Purpose: Recognize code-signing certificates known to have signed malware (abuse.ch CSCB) inside PE bytes.
# Works with: detection.definition_paths, detection.file_analysis
# Used by: detection.file_analysis, updates.definition_feeds

"""Recognize code-signing certificates known to have signed malware.

The certificates are read from the PE security directory of the bytes being
scanned (so archive members work too) and compared by SHA-256 thumbprint with the
abuse.ch Code Signing Certificate Blocklist. Nothing is executed or loaded.
"""
import csv
import io
import struct
from functools import lru_cache
from sentinelav.detection.definition_paths import definitions_dir

MAX_SECURITY_BYTES = 1024 * 1024
FILE = 'cscb.csv'


@lru_cache(maxsize=1)
def _entries(location, stamp):
    from pathlib import Path
    path = Path(location)
    if not stamp:
        return {}
    text = path.read_text(encoding='utf-8', errors='replace')
    rows = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    found = {}
    for row in csv.DictReader(io.StringIO('\n'.join(rows))):
        thumbprint = (row.get('thumbprint') or '').strip().lower()
        if len(thumbprint) == 64 and (row.get('thumbprint_algorithm') or '').upper() == 'SHA256':
            found[thumbprint] = dict(subject=(row.get('subject_cn') or '')[:80], reason=(row.get('Reason') or '')[:60])
    return found


def entries():
    path = definitions_dir('cert-blocklist') / FILE
    stamp = path.stat().st_mtime_ns if path.is_file() else 0
    return _entries(str(path), stamp)


def security_directory(data):
    """Return the raw WIN_CERTIFICATE area of a PE image, or b''."""
    if len(data) < 0x40 or data[:2] != b'MZ':
        return b''
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    if offset + 24 > len(data) or data[offset:offset + 4] != b'PE\0\0':
        return b''
    optional = offset + 24
    if optional + 2 > len(data):
        return b''
    magic = struct.unpack_from('<H', data, optional)[0]
    directories = optional + (96 if magic == 0x10B else 112 if magic == 0x20B else -1)
    entry = directories + 4 * 8
    if directories < optional or entry + 8 > len(data):
        return b''
    # The security directory holds a file offset, not an RVA.
    start, size = struct.unpack_from('<II', data, entry)
    if not start or not size or size > MAX_SECURITY_BYTES or start + size > len(data):
        return b''
    return data[start:start + size]


def thumbprints(data):
    """SHA-256 thumbprints of every certificate in the PE's Authenticode signatures."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import pkcs7
    area = security_directory(data)
    found = []
    position = 0
    while position + 8 <= len(area):
        length, _, kind = struct.unpack_from('<IHH', area, position)
        if length < 8 or position + length > len(area):
            break
        if kind == 2:
            try:
                for certificate in pkcs7.load_der_pkcs7_certificates(bytes(area[position + 8:position + length])):
                    found.append(certificate.fingerprint(hashes.SHA256()).hex())
            except ValueError:
                pass
        position += (length + 7) & ~7
    return found


def blocklisted(data):
    """The blocklist entry for the first listed certificate, or None."""
    listed = entries()
    if not listed:
        return None
    for thumbprint in thumbprints(data):
        if thumbprint in listed:
            return dict(thumbprint=thumbprint, **listed[thumbprint])
    return None


def install(source):
    target = definitions_dir('cert-blocklist') / FILE
    target.write_bytes(source.read_bytes())
    return len(entries())

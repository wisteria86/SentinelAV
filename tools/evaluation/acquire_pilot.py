# Purpose: Store only authenticated ciphertext; never unpack a sample on the host.
# Works with: lab.static_pilot, paths, response.response, workspace
# Used by: the Python module loader or CLI entry point

"""Store only authenticated ciphertext; never unpack a sample on the host."""

import hashlib
import json
import os
from pathlib import Path
import urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sentinelav.lab.static_pilot import ARCHIVE_BYTES, REVISION, AAD, validate_archive
from sentinelav.response.response import dpapi
from sentinelav.paths import PROJECT_ROOT


def main():
    from sentinelav.workspace import Workspace

    root = Workspace().area('lab') / 'sealed-static-pilot'
    root.mkdir(exist_ok=False)
    url = (
        'https://raw.githubusercontent.com/ytisf/theZoo/'
        + REVISION
        + '/malware/Binaries/Ransomware.WannaCry/Ransomware.WannaCry.zip'
    )
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(ARCHIVE_BYTES + 1)
    entries = validate_archive(raw)  # central-directory metadata only; no member reads
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    sealed = nonce + AESGCM(key).encrypt(nonce, raw, AAD)
    # No raw archive or plaintext malware is written to the host filesystem.
    (root / 'pilot.sealed').write_bytes(sealed)
    (root / 'transfer-key.dpapi').write_bytes(dpapi(key))
    (root / 'acquisition.json').write_text(
        json.dumps(
            dict(
                source=url,
                revision=REVISION,
                archive_sha256=hashlib.sha256(raw).hexdigest(),
                sealed_sha256=hashlib.sha256(sealed).hexdigest(),
                archive_entries=entries,
                host_storage='AES-256-GCM ciphertext',
                key_storage='CurrentUser DPAPI',
                host_archive_extracted=False,
                host_raw_archive_stored=False,
                sample_executed=False,
            ),
            indent=2,
        ),
        encoding='utf-8',
    )
    print(
        'PASS: pinned archive verified; only AES-GCM ciphertext and DPAPI-protected transfer key stored.'
    )


if __name__ == '__main__':
    main()

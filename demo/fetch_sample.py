# Purpose: Fetch a theZoo sample archive for the live demo and store it only in encrypted form.
# Works with: SampleRun.bat, demo/guest-demo.ps1
"""Fetch a theZoo sample archive for the live demo and store it only in encrypted form.

The download is held in memory and written as AES-256-CBC ciphertext plus a key
file, so no antivirus on this PC sees (or removes) the malware. The key is not a
secret: the encryption only keeps the bytes unreadable until the offline Sandbox
decrypts them. Usage: python demo/fetch_sample.py [theZoo folder name]
"""

import hashlib
import os
import sys
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NAME = sys.argv[1] if len(sys.argv) > 1 else 'Ransomware.WannaCry'
URL = f'https://github.com/ytisf/theZoo/raw/master/malware/Binaries/{NAME}/{NAME}.zip'
OUT = Path(os.environ.get('SENTINELAV_WORK_ROOT', 'F:/SentinelAV-Work')) / 'demo' / 'samples'

data = urllib.request.urlopen(URL, timeout=60).read()
if not data.startswith(b'PK'):
    sys.exit('Download is not a ZIP archive')
key, iv = os.urandom(32), os.urandom(16)
padder = padding.PKCS7(128).padder()
encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
sealed = iv + encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()
OUT.mkdir(parents=True, exist_ok=True)
(OUT / f'{NAME}.zip.sealed').write_bytes(sealed)
(OUT / f'{NAME}.zip.key').write_text(key.hex(), encoding='ascii')
print(
    f'{NAME}.zip: {len(data):,} bytes, SHA-256 {hashlib.sha256(data).hexdigest()}, stored encrypted in {OUT}'
)

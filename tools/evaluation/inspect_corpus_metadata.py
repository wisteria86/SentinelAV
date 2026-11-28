# Purpose: Pinned ZIP central-directory metadata only. No member contents or raw writes.
# Works with: lab.static_corpus
# Used by: the Python module loader or CLI entry point

"""Pinned ZIP central-directory metadata only. No member contents or raw writes."""

import hashlib
from io import BytesIO
import json
import urllib.request
import zipfile
from sentinelav.lab.static_corpus import SPECS, HOLDOUT_SPECS, ZEUS_VALIDATION_SPECS, REVISION
import sys

records = []
for spec in (
    ZEUS_VALIDATION_SPECS
    if '--zeus-validation' in sys.argv
    else HOLDOUT_SPECS if '--holdout' in sys.argv else SPECS
):
    family = spec['family']
    url = (
        'https://raw.githubusercontent.com/ytisf/theZoo/'
        + REVISION
        + '/malware/Binaries/'
        + family
        + '/'
        + family
        + '.zip'
    )
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(spec['size'] + 1)
    if (
        len(raw) != spec['size']
        or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != spec['blob']
    ):
        raise ValueError('Pinned archive identity mismatch')
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        records.append(
            dict(
                family=family,
                archive_sha256=hashlib.sha256(raw).hexdigest(),
                members=[
                    dict(
                        name=i.filename,
                        bytes=i.file_size,
                        encrypted=bool(i.flag_bits & 1),
                        directory=i.is_dir(),
                    )
                    for i in archive.infolist()
                ],
            )
        )
print(json.dumps(records, indent=2))

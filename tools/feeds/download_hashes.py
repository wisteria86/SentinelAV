"""Download MalwareBazaar's recent hash CSV only; never fetch sample files."""
from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
import csv
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 32 * 1024 * 1024
MAX_ROWS = 100_000
SOURCE = 'https://bazaar.abuse.ch/export/'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # The documented endpoint embeds credentials in its path. Never follow
        # redirects or include request/error objects in console output.
        raise ValueError('Redirect refused; verify the official export documentation')


def fetch(key):
    if not key or len(key) > 1024 or any(c.isspace() for c in key):
        raise ValueError('Missing or invalid Auth-Key')
    url = 'https://mb-api.abuse.ch/v2/files/exports/' + urllib.parse.quote(key, safe='') + '/recent.csv'
    opener = urllib.request.build_opener(NoRedirect())
    started = time.monotonic()
    try:
        with opener.open(urllib.request.Request(url, headers={'User-Agent': 'SentinelAV-HashImport/1.0'}), timeout=15) as response:
            chunks, size = [], 0
            while True:
                if time.monotonic() - started > 60:
                    raise ValueError('Download exceeded its time limit')
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError('Export exceeded the 32 MiB size limit')
                chunks.append(chunk)
            return b''.join(chunks)
    except urllib.error.HTTPError as error:
        raise ValueError(f'Export server returned HTTP {error.code}; check your key and access permissions') from None
    except (urllib.error.URLError, OSError):
        raise ValueError('Download failed; check your connection and retry later') from None


def parse_export(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError('Export exceeded size limit')
    text = raw.decode('utf-8-sig')
    header = None
    signatures, records = {}, {}
    rows = 0
    for line in io.StringIO(text):
        if not line.strip():
            continue
        comment = line.lstrip().startswith('#')
        content = line.lstrip()[1:].lstrip() if comment else line
        row = next(csv.reader([content], skipinitialspace=True, strict=True))
        names = [v.strip().lower() for v in row]
        if 'sha256_hash' in names:
            if header is not None or len(set(names)) != len(names):
                raise ValueError('Duplicate or ambiguous CSV header')
            header = names
            continue
        if comment:
            continue
        if header is None or len(row) != len(header):
            raise ValueError('Unexpected export format; expected a MalwareBazaar CSV header')
        rows += 1
        if rows > MAX_ROWS:
            raise ValueError('Recent export exceeded row limit')
        item = dict(zip(header, (v.strip() for v in row)))
        digest = item['sha256_hash'].lower()
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError(f'Invalid SHA-256 at data row {rows}; candidate rejected')
        family = item.get('signature', '')
        if len(family) > 200 or any(ord(c) < 32 for c in family):
            raise ValueError('Invalid threat label; candidate rejected')
        label = family if family and family.lower() not in ('n/a', 'none', 'null') else 'Reported malware'
        labels = records.setdefault(digest, set())
        labels.add(label)
        signatures[digest] = 'MalwareBazaar: ' + ' / '.join(sorted(labels))
    if not signatures:
        raise ValueError('Export contained no valid hash records')
    return signatures, rows


def save_candidate(raw, base):
    signatures, rows = parse_export(raw)
    stamp = datetime.now(timezone.utc)
    base = Path(base).absolute()
    for part in [base, *base.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError('Output directory cannot contain linked components')
    base.mkdir(parents=True, exist_ok=True)
    folder = base / ('malwarebazaar-recent-' + stamp.strftime('%Y%m%dT%H%M%S%fZ'))
    folder.mkdir(exist_ok=False)
    candidate = json.dumps(signatures, sort_keys=True, indent=2).encode('utf-8')
    metadata = dict(source='MalwareBazaar', documentation=SOURCE, export='recent.csv',
                    scope='Recent additions from the last 48 hours; not a full malware database',
                    retrieved_utc=stamp.isoformat(), unique_sha256=len(signatures), data_rows=rows,
                    duplicate_rows=rows-len(signatures), export_sha256=hashlib.sha256(raw).hexdigest(),
                    candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                    activated=False, samples_downloaded=False)
    (folder/'recent.csv').write_bytes(raw)
    (folder/'signatures.candidate.json').write_bytes(candidate)
    # Manifest is written last: its presence marks a complete validated import.
    (folder/'manifest.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    return folder, metadata


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true',help='Merge the validated recent CSV into the existing full database')
    args=parser.parse_args()
    key = os.environ.pop('ABUSECH_AUTH_KEY', '') or getpass.getpass('abuse.ch Auth-Key (hidden): ')
    try:
        raw = fetch(key)
        key = ''
        folder, metadata = save_candidate(raw, PROJECT_ROOT/'data/hash-feeds')
        if args.apply:
            from sentinelav.updates.definition_updates import import_recent
            activated=import_recent(RESOURCE_ROOT/'signature-data',folder/'recent.csv')
    except (ValueError, UnicodeError, csv.Error, OSError):
        # Never print exceptions: network errors can embed the credential URL.
        print('Import failed. Check the key, connection, export format, and output permissions. No active signatures were changed.')
        return 1
    print(f"Validated {metadata['unique_sha256']:,} unique SHA-256 hashes from the last 48 hours.")
    print('Saved to: ' + str(folder))
    if args.apply:
        print(f"Activated {activated['unique_sha256']:,} full-feed hashes. Restart monitoring to load the new snapshot.")
        print('No malware samples downloaded. Previous snapshot retained for rollback.')
    else:
        print('Candidate only: SentinelAV active signatures were not changed. No malware samples downloaded.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

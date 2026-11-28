# Purpose: Build and query a large read-only MD5 malware-hash database (VirusShare lists, MalwareBazaar MD5 column).
# Works with: detection.definition_paths, detection.engine
# Used by: detection.engine, updates.definition_feeds

"""Build and query a large read-only MD5 malware-hash database.

Sources are independent public lists. The database is built into a new file
and switched in through active.json, so readers never see a partial build.
"""

import csv
import hashlib
import io
import json
import re
import sqlite3
import time
import uuid
import zipfile
from pathlib import Path
from sentinelav.detection.definition_paths import definitions_dir

MD5 = re.compile(r'[0-9a-f]{32}')
BATCH = 200_000


class Md5Feed:
    """Read-only lookup into the installed MD5 malware-hash database."""

    def __init__(self, folder=None):
        """Open the database that active.json points to, in read-only mode. Raises FileNotFoundError if
        no feed is installed.
        """
        folder = folder or definitions_dir('md5-feed')
        pointer = folder / 'active.json'
        if not pointer.is_file():
            raise FileNotFoundError('MD5 feed is not installed')
        self.metadata = json.loads(pointer.read_text(encoding='utf-8'))
        name = self.metadata['database']
        if not re.fullmatch(r'md5-[0-9a-f]{32}\.sqlite', name):
            raise ValueError('Invalid MD5 feed activation')
        self.db = sqlite3.connect(
            (folder / name).resolve().as_uri() + '?mode=ro&immutable=1',
            uri=True,
            check_same_thread=False,
        )
        self.sources = dict(self.db.execute('SELECT id,name FROM sources'))

    def get(self, digest):
        """Return the name of the list that contains this MD5 hash (for example 'VirusShare'), or None
        if it is not listed.
        """
        row = self.db.execute(
            'SELECT source FROM md5 WHERE md5=?', (bytes.fromhex(digest),)
        ).fetchone()
        return self.sources.get(row[0], 'Unknown') if row else None

    def close(self):
        """Close the database."""
        self.db.close()


def _virusshare(path):
    """Yield every MD5 hash from a VirusShare hash-list file."""
    with open(path, encoding='ascii', errors='ignore') as stream:
        for line in stream:
            value = line.strip().lower()
            if MD5.fullmatch(value):
                yield value


def _bazaar(path):
    """Yield every MD5 hash from the MalwareBazaar full export (a CSV inside a ZIP)."""
    with zipfile.ZipFile(path) as archive, archive.open('full.csv') as raw:
        text = io.TextIOWrapper(raw, encoding='utf-8-sig', errors='replace')
        header = None
        for line in text:
            stripped = line.lstrip()
            if stripped.startswith('#'):
                if 'md5_hash' in stripped:
                    header = [item.strip().strip('"') for item in stripped.lstrip('#').split(',')]
                continue
            if header is None:
                continue
            try:
                row = next(csv.reader([line], skipinitialspace=True))
            except csv.Error:
                continue
            if len(row) == len(header):
                value = row[header.index('md5_hash')].strip().lower()
                if MD5.fullmatch(value):
                    yield value


def build(virusshare_dir=None, bazaar_zip=None, progress=print):
    """Create and activate a new MD5 database from the given sources."""
    folder = definitions_dir('md5-feed')
    identity = uuid.uuid4().hex
    database = folder / f'md5-{identity}.sqlite'
    db = sqlite3.connect(database)
    started = time.monotonic()
    try:
        db.executescript(
            'PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-262144; '
            'CREATE TABLE raw(md5 BLOB NOT NULL, source INTEGER NOT NULL); '
            'CREATE TABLE sources(id INTEGER PRIMARY KEY, name TEXT NOT NULL);'
        )
        sources = []
        if virusshare_dir:
            files = sorted(Path(virusshare_dir).glob('VirusShare_*.md5'))
            sources.append(
                (
                    'VirusShare',
                    len(sources) + 1,
                    [item for path in files for item in [path]],
                    _virusshare,
                )
            )
        if bazaar_zip:
            sources.append(('MalwareBazaar', len(sources) + 1, [Path(bazaar_zip)], _bazaar))
        counts = {}
        for name, number, paths, reader in sources:
            db.execute('INSERT INTO sources VALUES (?,?)', (number, name))
            total = 0
            for path in paths:
                batch = []
                for value in reader(path):
                    batch.append((bytes.fromhex(value), number))
                    if len(batch) >= BATCH:
                        db.executemany('INSERT INTO raw VALUES (?,?)', batch)
                        total += len(batch)
                        batch.clear()
                if batch:
                    db.executemany('INSERT INTO raw VALUES (?,?)', batch)
                    total += len(batch)
                db.commit()
            counts[name] = total
            progress(f'{name}: {total:,} rows')
        # Build the final table de-duplicated and sorted by hash, then throw away the raw import
        # table.
        # Inserting in key order keeps building the primary-key index fast.
        db.executescript(
            'CREATE TABLE md5(md5 BLOB PRIMARY KEY, source INTEGER NOT NULL) WITHOUT ROWID; '
            'INSERT OR IGNORE INTO md5 SELECT md5, MIN(source) FROM raw GROUP BY md5 ORDER BY md5; DROP TABLE raw;'
        )
        db.commit()
        unique = db.execute('SELECT COUNT(*) FROM md5').fetchone()[0]
        db.execute('VACUUM')
        db.close()
        db = None
        digest = hashlib.sha256()
        with database.open('rb') as stream:
            while chunk := stream.read(8 * 1024 * 1024):
                digest.update(chunk)
        metadata = dict(
            schema=1,
            database=database.name,
            unique_md5=unique,
            rows=counts,
            built_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            seconds=round(time.monotonic() - started),
            database_sha256=digest.hexdigest(),
        )
        (folder / 'active.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
        return metadata
    except BaseException:
        if db is not None:
            db.close()
        database.unlink(missing_ok=True)
        raise

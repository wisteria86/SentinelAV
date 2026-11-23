# Purpose: Stream an official-style MalwareBazaar CSV ZIP into a versioned hash DB.
# Works with: paths, updates.definition_updates
# Used by: ui.updates_ui, updates.definition_updates, updates.hash_snapshots, updates.update_envelope

"""Stream an official-style MalwareBazaar CSV ZIP into a versioned hash DB.

No archive extraction, malware acquisition, or execution. Activation is an
atomic manifest switch; existing readers keep their immutable old snapshot.
"""
from sentinelav.paths import RESOURCE_ROOT
import argparse
import csv
from datetime import datetime,timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import time
import uuid
from zipfile import ZipFile

MAX_CSV=1024*1024*1024
MAX_ROWS=5_000_000


def checksum(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk:=stream.read(1024*1024): digest.update(chunk)
    return digest.hexdigest()


def records(stream,on_reject=None):
    header=None
    rows=0
    for line_number,line in enumerate(iter(lambda:stream.readline(65537),''),1):
        if not line.strip(): continue
        if len(line)>65536:
            raise ValueError('CSV line exceeds size limit')
        comment=line.lstrip().startswith('#')
        content=line.lstrip()[1:].lstrip() if comment else line
        try:
            row=next(csv.reader([content],skipinitialspace=True,strict=True))
        except csv.Error:
            if on_reject is None or header is None:
                raise
            # Some exports contain unescaped quotes in submitted filenames.
            # Never guess shifted columns: omit the entire malformed row and
            # record its line number, while bounding total omissions.
            on_reject(line_number)
            continue
        names=[v.strip().lower() for v in row]
        if 'sha256_hash' in names:
            if header is not None or len(set(names))!=len(names):
                raise ValueError('Duplicate or ambiguous CSV header')
            header=names
            continue
        if comment: continue
        if header is None or len(row)!=len(header):
            raise ValueError('Unexpected CSV structure')
        item=dict(zip(header,(v.strip() for v in row)))
        digest=item['sha256_hash'].lower()
        if not re.fullmatch(r'[0-9a-f]{64}',digest):
            raise ValueError(f'Invalid SHA-256 at data row {rows+1}')
        label=item.get('signature','')
        if len(label)>200 or any(ord(c)<32 for c in label):
            raise ValueError('Invalid threat classification label')
        label=label if label and label.lower() not in ('n/a','none','null') else 'Reported malware'
        first_seen=item.get('first_seen_utc','')
        file_type=item.get('file_type_guess','')
        if len(first_seen)>64 or len(file_type)>64:
            raise ValueError('Invalid CSV metadata')
        rows+=1
        if rows>MAX_ROWS: raise ValueError('CSV exceeds row limit')
        yield bytes.fromhex(digest),label,first_seen,file_type


def import_archive(archive,output,activate=False,progress=lambda count:None):
    # Preserve the previous no-output behavior for malformed archive structure.
    with ZipFile(archive) as zipped:
        members=zipped.infolist()
        if len(members)!=1 or members[0].filename!='full.csv' or members[0].flag_bits&1:
            raise ValueError('Expected one unencrypted member named full.csv')
    from sentinelav.updates.definition_updates import update_lock
    with update_lock(output):
        return _import_archive(archive,output,activate,progress)


def _import_archive(archive,output,activate=False,progress=lambda count:None):
    archive,output=Path(archive).resolve(),Path(output).absolute()
    for part in [output,*output.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError('Output cannot contain linked path components')
    # Parse no paths from the archive onto the filesystem.
    with ZipFile(archive) as zipped:
        members=zipped.infolist()
        if len(members)!=1 or members[0].filename!='full.csv' or members[0].flag_bits&1:
            raise ValueError('Expected one unencrypted member named full.csv')
        info=members[0]
        if not 0<info.file_size<=MAX_CSV:
            raise ValueError('CSV exceeds supported size limit')
        archive_hash=checksum(archive)
        output.mkdir(parents=True,exist_ok=True)
        identity=uuid.uuid4().hex
        database=output/f'hashes-{identity}.sqlite'
        db=sqlite3.connect(database)
        started=time.monotonic()
        rows=0
        complete=False
        rejected=[]
        def reject(line):
            rejected.append(line)
            if len(rejected)>1000:
                raise ValueError('Too many malformed CSV records')
        try:
            db.executescript('PRAGMA user_version=1; PRAGMA journal_mode=DELETE; PRAGMA cache_size=-8192; '
                'CREATE TABLE hashes(sha256 BLOB PRIMARY KEY,first_seen TEXT NOT NULL,file_type TEXT NOT NULL) WITHOUT ROWID; '
                'CREATE TABLE labels(sha256 BLOB NOT NULL,label TEXT NOT NULL,PRIMARY KEY(sha256,label)) WITHOUT ROWID; '
                'CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);')
            batch=[]
            def write_batch():
                db.executemany('INSERT OR IGNORE INTO hashes VALUES (?,?,?)',((h,s,t) for h,l,s,t in batch))
                db.executemany('INSERT OR IGNORE INTO labels VALUES (?,?)',((h,l) for h,l,s,t in batch))
                db.commit()
            with zipped.open(info) as raw:
                with io.TextIOWrapper(raw,encoding='utf-8-sig',newline=None) as text:
                    for record in records(text,reject):
                        if time.monotonic()-started>900:
                            raise ValueError('Import exceeded its 15-minute limit')
                        batch.append(record)
                        rows+=1
                        if len(batch)>=10000:
                            write_batch()
                            batch.clear()
                            progress(rows)
                    if batch: write_batch()
            if rows==0: raise ValueError('No hash records found')
            if len(rejected)>max(1,rows//1000):
                raise ValueError('Malformed CSV records exceed the 0.1 percent quality limit')
            # Zip CRC is verified when the member is fully consumed. Also ensure
            # that the supplied archive did not change during processing.
            if checksum(archive)!=archive_hash:
                raise ValueError('Archive changed during import')
            raw_unique=db.execute('SELECT COUNT(*) FROM hashes').fetchone()[0]
            revoked_omissions=0
            if (output/'active.json').exists():
                from sentinelav.updates.definition_updates import load_active
                previous=load_active(output,verify=True)
                prior=sqlite3.connect((output/previous['database']).resolve().as_uri()+'?mode=ro&immutable=1',uri=True)
                try:
                    if prior.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='revocations'").fetchone():
                        db.execute('CREATE TABLE revocations(sha256 BLOB PRIMARY KEY,reason TEXT NOT NULL) WITHOUT ROWID')
                        db.executemany('INSERT INTO revocations VALUES (?,?)',prior.execute('SELECT sha256,reason FROM revocations'))
                        revoked_omissions=db.execute('SELECT COUNT(*) FROM hashes WHERE sha256 IN (SELECT sha256 FROM revocations)').fetchone()[0]
                        db.execute('DELETE FROM hashes WHERE sha256 IN (SELECT sha256 FROM revocations)')
                        db.execute('DELETE FROM labels WHERE sha256 IN (SELECT sha256 FROM revocations)')
                finally: prior.close()
            count=db.execute('SELECT COUNT(*) FROM hashes').fetchone()[0]
            if count<1: raise ValueError('All imported hashes were revoked; refusing an empty active feed')
            metadata=dict(schema=1,database=database.name,source='MalwareBazaar',scope='User-supplied full CSV export',
                imported_utc=datetime.now(timezone.utc).isoformat(),unique_sha256=count,data_rows=rows,
                duplicate_rows=rows-raw_unique,revoked_omissions=revoked_omissions,archive_sha256=archive_hash,csv_bytes=info.file_size,
                skipped_malformed_rows=len(rejected),skipped_physical_lines=rejected,
                csv_crc32=f'{info.CRC:08x}',samples_downloaded=False,provider_labels_independently_verified=False)
            db.executemany('INSERT INTO metadata VALUES (?,?)',((k,json.dumps(v)) for k,v in metadata.items()))
            db.commit()
            if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                raise ValueError('Database integrity check failed')
            db.close()
            db=None
            metadata['database_sha256']=checksum(database)
            candidate=output/f'candidate-{identity}.json'
            candidate.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
            complete=True
            if activate:
                from sentinelav.updates.definition_updates import activate_snapshot
                metadata=activate_snapshot(output,metadata)
            return metadata
        except BaseException:
            if db is not None: db.close()
            # Delete only the newly created UUID-owned partial database.
            if not complete and database.exists(): database.unlink()
            raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    parser.add_argument('--activate',action='store_true')
    args=parser.parse_args()
    from sentinelav.detection.definition_paths import signature_data_dir
    metadata=import_archive(args.archive,signature_data_dir(RESOURCE_ROOT),args.activate,
                            lambda n:print(f'Validated {n:,} rows...',flush=True))
    print(json.dumps(metadata,indent=2))
    print('Activated for new source-app scans.' if args.activate else 'Candidate only; not activated.')


if __name__=='__main__': main()

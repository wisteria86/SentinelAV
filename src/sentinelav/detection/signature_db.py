# Purpose: Read-only exact-hash lookup with an optional versioned SQLite feed.
# Works with: sibling modules in detection
# Used by: detection.engine, entrypoint, tests.unit.test_definition_updates, tests.unit.test_signature_db

"""Read-only exact-hash lookup with an optional versioned SQLite feed."""
import json
from pathlib import Path
import re
import sqlite3


class SignatureIndex:
    def __init__(self, json_path):
        path=Path(json_path)
        self.local=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(self.local,dict) or any(
                not isinstance(k,str) or not re.fullmatch(r'[0-9a-f]{64}',k) or not isinstance(v,str)
                for k,v in self.local.items()):
            raise ValueError('Signatures must map lowercase SHA-256 hashes to threat names')
        self.db=None
        self.metadata=None
        self.revocations=False
        from sentinelav.detection.definition_paths import signature_data_dir
        pointer=signature_data_dir(path.parent)/'active.json'
        if pointer.exists():
            if pointer.stat().st_size>16384:
                raise ValueError('Signature manifest exceeds size limit')
            metadata=json.loads(pointer.read_text(encoding='utf-8'))
            name=metadata.get('database','')
            if (metadata.get('schema')!=1 or not isinstance(name,str)
                    or not re.fullmatch(r'hashes-[0-9a-f]{32}\.sqlite',name)
                    or type(metadata.get('unique_sha256')) is not int or metadata['unique_sha256']<1):
                raise ValueError('Invalid active signature manifest')
            database=pointer.parent/name
            for part in [database,*database.parents]:
                if part.is_symlink() or part.is_junction():
                    raise ValueError('Signature database cannot contain linked path components')
            self.db=sqlite3.connect(database.resolve().as_uri()+'?mode=ro&immutable=1',uri=True,check_same_thread=False)
            try:
                if self.db.execute('PRAGMA user_version').fetchone()[0]!=1:
                    raise ValueError('Unsupported signature database schema')
                count=self.db.execute('SELECT COUNT(*) FROM hashes').fetchone()[0]
                if count!=metadata['unique_sha256']:
                    raise ValueError('Signature database record count disagrees with manifest')
                self.db.execute('PRAGMA cache_size=-4096')
                self.metadata=metadata
                self.revocations=bool(self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='revocations'").fetchone())
                self.count=count+sum(self.get(h) is not None and not self.db.execute('SELECT 1 FROM hashes WHERE sha256=?',(bytes.fromhex(h),)).fetchone() for h in self.local)
            except Exception:
                self.close()
                raise
        else:
            self.count=len(self.local)

    def get(self,digest,default=None):
        if digest in self.local and (self.db is None or not self.local[digest].startswith('MalwareBazaar: ')):
            return self.local[digest]
        if self.db is not None:
            if not re.fullmatch(r'[0-9a-f]{64}',digest):
                return default
            if self.revocations and self.db.execute('SELECT 1 FROM revocations WHERE sha256=?',(bytes.fromhex(digest),)).fetchone():
                return default
            rows=self.db.execute('SELECT label FROM labels WHERE sha256=? ORDER BY label LIMIT 16',(bytes.fromhex(digest),)).fetchall()
            if rows:
                # This snapshot can contain manual corrections and signed deltas
                # from other sources. Do not falsely attribute every row to the
                # provider that supplied the original base database.
                return 'Hash database: '+' / '.join(row[0] for row in rows)
        return self.local.get(digest,default)

    def __contains__(self,digest):
        return self.get(digest) is not None

    def __getitem__(self,digest):
        value=self.get(digest)
        if value is None:
            raise KeyError(digest)
        return value

    def __len__(self):
        return self.count

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db=None

    def __del__(self):
        if getattr(self,'db',None) is not None:
            self.close()

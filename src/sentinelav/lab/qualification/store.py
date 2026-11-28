# Purpose: Crash-durable evaluation queue. Never resumes an in-flight guest.
# Works with: lab.qualification.contracts, workspace
# Used by: lab.qualification.backend_hyperv, lab.qualification.backend_sandbox,
#   lab.qualification.backend_transport, lab.qualification.evaluation_environment

"""Crash-durable evaluation queue. Never resumes an in-flight guest."""

from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import sqlite3
import uuid
from .contracts import digest
from sentinelav.workspace import unlinked


@contextmanager
def exclusive(path):
    """Hold an exclusive lock on a file for the duration of a `with` block, failing immediately if
    someone else holds it.
    """
    path = unlinked(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    f = path.open('a+b')
    try:
        if f.tell() == 0:
            f.write(b'0')
            f.flush()
        f.seek(0)
        if os.name == 'nt':
            import msvcrt

            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        f.close()


def write_json(path, data, replace=False, maximum=4 * 1024 * 1024):
    """Write JSON to a file, refusing oversized data. With replace=False the file must not exist yet;
    with replace=True it is replaced atomically.
    """
    raw = json.dumps(data, indent=2, allow_nan=False).encode()
    if len(raw) > maximum:
        raise ValueError('Report metadata budget exceeded')
    path = unlinked(path)
    if not replace:
        with path.open('xb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    else:
        tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
        with tmp.open('xb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)


class RunStore:
    """Crash-safe queue of evaluation cases for one run, kept in SQLite next to the frozen manifest."""

    def __init__(self, path, manifest=None):
        """Open (or create) the run folder and queue, refusing any linked paths inside it."""
        self.path = unlinked(path)
        self.path.mkdir(parents=True, exist_ok=True)
        for p in self.path.rglob('*'):
            unlinked(p)
        self.db = sqlite3.connect(self.path / 'queue.sqlite', timeout=10)
        try:
            self._initialize(manifest)
        except BaseException:
            self.db.close()
            raise

    def _initialize(self, manifest):
        """Create the tables, store the manifest and pending cases on first use, and refuse to continue
        if the frozen manifest was changed.
        """
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)'
        )
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY,state TEXT NOT NULL,attempt INTEGER NOT NULL,result TEXT)'
        )
        if manifest:
            prior = self.db.execute("SELECT value FROM metadata WHERE key='manifest'").fetchone()
            if prior and digest(json.loads(prior[0])) != digest(manifest):
                raise ValueError('Resume manifest differs')
            if not prior:
                write_json(self.path / 'manifest.json', manifest)
                self.db.execute(
                    'INSERT INTO metadata VALUES (?,?)', ('manifest', json.dumps(manifest))
                )
                self.db.executemany(
                    'INSERT INTO cases VALUES (?,?,?,?)',
                    [(c['id'], 'pending', 0, None) for c in manifest['cases']],
                )
                self.db.commit()
        row = self.db.execute("SELECT value FROM metadata WHERE key='manifest'").fetchone()
        if not row:
            raise ValueError('Missing frozen queue manifest')
        self.manifest = json.loads(row[0])
        if digest(json.loads((self.path / 'manifest.json').read_text())) != digest(self.manifest):
            raise ValueError('Frozen manifest modified')

    def interrupted(self):
        """Return the ids of cases that were running when the run stopped."""
        return [r[0] for r in self.db.execute("SELECT id FROM cases WHERE state='running'")]

    def recover(self):
        # Caller must reconcile/discard recorded owned guests BEFORE requeueing.
        """Put interrupted cases back in the pending state (only after their guests have been disposed
        of).
        """
        self.db.execute("UPDATE cases SET state='pending',result=NULL WHERE state='running'")
        self.db.commit()

    def start(self, case):
        """Mark a pending case as running, create its numbered attempt folder, and return that folder."""
        row = self.db.execute('SELECT state,attempt FROM cases WHERE id=?', (case,)).fetchone()
        if row is None or row[0] != 'pending':
            raise ValueError('Case not pending')
        attempt = row[1] + 1
        self.db.execute("UPDATE cases SET state='running',attempt=? WHERE id=?", (attempt, case))
        self.db.commit()
        path = self.path / 'attempts' / case / str(attempt)
        path.mkdir(parents=True, exist_ok=False)
        return path

    def finish(self, result):
        """Record the result of the running case."""
        cur = self.db.execute(
            "UPDATE cases SET state='done',result=? WHERE id=? AND state='running'",
            (json.dumps(result, allow_nan=False), result['case_id']),
        )
        if cur.rowcount != 1:
            raise ValueError('Result not attached to running case')
        self.db.commit()

    def pending(self):
        """Return the ids of cases still waiting to run."""
        return {r[0] for r in self.db.execute("SELECT id FROM cases WHERE state='pending'")}

    def results(self):
        """Return the results of every finished case."""
        return [
            json.loads(r[0]) for r in self.db.execute("SELECT result FROM cases WHERE state='done'")
        ]

    def close(self):
        """Close the queue database."""
        self.db.close()


def new_path(project):
    """Return a new, timestamped run folder path under the project's logs folder."""
    return unlinked(Path(project) / 'logs') / (
        datetime.now().astimezone().strftime('%Y-%m-%d_%H-%M-%S') + '-' + uuid.uuid4().hex[:12]
    )

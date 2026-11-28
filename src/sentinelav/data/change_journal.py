# Purpose: Account-bound encrypted change state and durable remediation journal.
# Works with: data.contracts, response.response, response.transaction, workspace
# Used by: lab.qualification.guest_inventory, monitoring.core.change_monitor, response.auto_response,
#   ui.core.app_changes_ui

"""Account-bound encrypted change state and durable remediation journal."""

import json
import os
import sqlite3
import time
import csv
import io
import subprocess
from sentinelav.data.contracts import canonical, fingerprint, validate_change
from sentinelav.response.response import dpapi
from sentinelav.workspace import unlinked


class ChangeJournal:
    """Encrypted, durable record of system changes and of the clean-up operations performed on them.

    Everything is stored in a small SQLite database, and every record is encrypted for the current
    Windows account (DPAPI), so another user cannot read or tamper with it. It holds:
    - snapshots: the last known state of each watched resource (a registry value, a startup file,
      ...)
    - changes: what changed, when, and which process did it
    - operations: remediation plans and their progress, so an interrupted clean-up can be recovered
    """

    def __init__(self, folder, *, protect=dpapi):
        """Open (or create) the journal in `folder`.

        On Windows the folder permissions are first locked down so that only the current user and
        SYSTEM can access it. `protect` is the encrypt/decrypt function; tests can pass a fake one.
        """
        self.folder = unlinked(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.protect = protect
        if os.name == 'nt' and protect is dpapi:
            identity = subprocess.run(
                ['whoami', '/user', '/fo', 'csv', '/nh'],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            sid = next(csv.reader(io.StringIO(identity.stdout.strip())))[1]
            if not sid.startswith('S-1-'):
                raise ValueError('Cannot establish journal owner')
            subprocess.run(
                [
                    'icacls',
                    str(self.folder),
                    '/inheritance:r',
                    '/grant:r',
                    f'*{sid}:(OI)(CI)F',
                    '*S-1-5-18:(OI)(CI)F',
                ],
                capture_output=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        self.db = sqlite3.connect(unlinked(self.folder / 'changes.sqlite'), timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS journal_meta(version INTEGER NOT NULL);
          INSERT INTO journal_meta SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM journal_meta);
          CREATE TABLE IF NOT EXISTS snapshots(resource TEXT PRIMARY KEY,payload BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS changes(id TEXT PRIMARY KEY,stamp REAL,payload BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,stamp REAL,payload BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS inventory_complete(kind TEXT PRIMARY KEY);''')
        if self.db.execute('SELECT version FROM journal_meta').fetchone()[0] != 1:
            raise ValueError('Unsupported journal version')
        self.db.commit()

    def seal(self, value):
        """Turn a value into canonical JSON and encrypt it, refusing anything over 8 MB."""
        raw = canonical(value)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('Journal record too large')
        return self.protect(raw)

    def open(self, blob):
        """Decrypt a stored blob and turn it back into a Python value."""
        return json.loads(self.protect(bytes(blob), True))

    def snapshot(self, resource):
        """Return the last saved state of a resource, or None if we have never seen it."""
        row = self.db.execute(
            'SELECT payload FROM snapshots WHERE resource=?', (fingerprint(resource),)
        ).fetchone()
        return self.open(row[0]) if row else None

    def commit_observation(self, resource, state, record=None):
        # Snapshot and its change are one transaction; failed encryption commits neither.
        """Save the new state of a resource and, optionally, the change record describing how it got
        there.
        """
        state_blob = self.seal(dict(resource=resource, state=state))
        change_blob = self.seal(validate_change(record)) if record else None
        with self.db:
            if record:
                self.db.execute(
                    'INSERT INTO changes VALUES (?,?,?)',
                    (record['id'], record['observed_at'], change_blob),
                )
            self.db.execute(
                'INSERT OR REPLACE INTO snapshots VALUES (?,?)', (fingerprint(resource), state_blob)
            )

    def snapshots(self):
        """Return every saved resource snapshot."""
        return [self.open(row[0]) for row in self.db.execute('SELECT payload FROM snapshots')]

    def initialized(self, kind):
        """Tell whether the first full inventory of this kind of resource has been taken yet."""
        return bool(
            self.db.execute('SELECT 1 FROM inventory_complete WHERE kind=?', (kind,)).fetchone()
        )

    def mark_initialized(self, kinds):
        """Remember that the first full inventory has been taken for each of these resource kinds."""
        with self.db:
            self.db.executemany(
                'INSERT OR IGNORE INTO inventory_complete VALUES (?)', [(kind,) for kind in kinds]
            )

    def changes(self, limit=500):
        """Return the most recent change records, newest first (between 1 and 1000 of them)."""
        return [
            self.open(row[0])
            for row in self.db.execute(
                'SELECT payload FROM changes ORDER BY stamp DESC LIMIT ?',
                (min(1000, max(1, limit)),),
            )
        ]

    def change(self, identity):
        """Return one change record by id, checking its integrity first."""
        row = self.db.execute('SELECT payload FROM changes WHERE id=?', (identity,)).fetchone()
        if not row:
            raise ValueError('Change no longer available')
        return validate_change(self.open(row[0]))

    def operation(self, value):
        """Save or update a remediation operation."""
        blob = self.seal(value)
        with self.db:
            self.db.execute(
                'INSERT OR REPLACE INTO operations VALUES (?,?,?)', (value['id'], time.time(), blob)
            )

    def operations(self):
        """Return up to 500 remediation operations, newest first."""
        return [
            self.open(row[0])
            for row in self.db.execute(
                'SELECT payload FROM operations ORDER BY stamp DESC LIMIT 500'
            )
        ]

    def recovery_operations(self):
        # UI pagination must never hide an interrupted operation from recovery.
        """Yield every operation that was still running when the program stopped, so it can be finished
        or rolled back.
        """
        for row in self.db.execute('SELECT payload FROM operations'):
            value = self.open(row[0])
            if value.get('state') == 'Executing':
                yield value

    def get_operation(self, identity):
        """Return one remediation operation by id."""
        row = self.db.execute('SELECT payload FROM operations WHERE id=?', (identity,)).fetchone()
        if not row:
            raise ValueError('Unknown operation')
        return self.open(row[0])

    def close(self):
        """Close the database connection."""
        self.db.close()

    def exclusive(self):
        """Return a lock that ensures only one remediation runs against this journal at a time."""
        from sentinelav.response.transaction import exclusive_file

        return exclusive_file(self.folder / 'execution.lock')

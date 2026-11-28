# Purpose: Persist settings, scan history, protection events, quarantine records, and audits in SQLite.
# Works with: UI controllers; monitoring/background.py; response/response.py
# Used by: lab.qualification.disk_pressure, lab.qualification.guest_inventory,

import json
import sqlite3
from pathlib import Path


class Store:
    """The application's main SQLite database: scan history, settings, activity events, quarantine
    records and lab runs.

    Each row stores a JSON payload, which keeps the schema simple and lets records grow new fields
    without migrations.
    """

    def __init__(self, path):
        """Open (or create) the database at `path`, refusing databases written by a newer version."""
        self.path = Path(path).resolve()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version > 1:
            self.db.close()
            raise ValueError('This history database requires a newer SentinelAV version')
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)'
        )
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
        )
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)'
        )
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS quarantine (id TEXT PRIMARY KEY, payload TEXT NOT NULL)'
        )
        self.db.execute(
            'CREATE TABLE IF NOT EXISTS lab_runs (id TEXT PRIMARY KEY, payload TEXT NOT NULL)'
        )
        self.db.execute('PRAGMA user_version=1')
        self.db.commit()
        self._cache = {}
        self._version = None

    def _cached(self, key, sql, args=()):
        """Run a read query, reusing the previous result if nothing in the database has changed since.

        SQLite's data_version goes up whenever another connection writes, which tells us when the
        cache is stale.
        """
        version = self.db.execute('PRAGMA data_version').fetchone()[0]
        if version != self._version:
            self._cache.clear()
            self._version = version
        if key not in self._cache:
            self._cache[key] = [json.loads(r[0]) for r in self.db.execute(sql, args)]
        return self._cache[key]

    def save_scan(self, result):
        """Add a finished scan result to the history."""
        self._cache.clear()
        self.db.execute('INSERT INTO scans(payload) VALUES (?)', (json.dumps(result),))
        self.db.commit()

    def history(self):
        """Return every saved scan, newest first."""
        return self._cached('scans', 'SELECT payload FROM scans ORDER BY id DESC')

    def get(self, key, default):
        """Read a setting, returning `default` if it has never been saved."""
        row = self.db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        """Save a setting (any JSON-compatible value)."""
        self.db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (key, json.dumps(value)))
        self.db.commit()

    def save_event(self, event):
        """Add an activity event, keeping only the newest 5000."""
        self._cache.clear()
        self.db.execute('INSERT INTO events(payload) VALUES (?)', (json.dumps(event),))
        self.db.execute(
            'DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 5000)'
        )
        self.db.commit()

    def events(self, limit=200):
        """Return the newest `limit` activity events."""
        return self._cached(
            ('events', limit), 'SELECT payload FROM events ORDER BY id DESC LIMIT ?', (limit,)
        )

    def save_quarantine(self, record):
        """Save or update a quarantine record."""
        self.db.execute(
            'INSERT OR REPLACE INTO quarantine VALUES (?,?)', (record['id'], json.dumps(record))
        )
        self.db.commit()

    def quarantine(self):
        """Return every quarantine record, newest first."""
        return [
            json.loads(r[0])
            for r in self.db.execute('SELECT payload FROM quarantine ORDER BY rowid DESC')
        ]

    def save_lab_run(self, run):
        """Save a lab run, keeping only the newest 200."""
        self.db.execute(
            'INSERT OR REPLACE INTO lab_runs VALUES (?,?)', (run['id'], json.dumps(run))
        )
        self.db.execute(
            'DELETE FROM lab_runs WHERE id NOT IN (SELECT id FROM lab_runs ORDER BY rowid DESC LIMIT 200)'
        )
        self.db.commit()

    def lab_runs(self):
        """Return every saved lab run, newest first."""
        return [
            json.loads(row[0])
            for row in self.db.execute('SELECT payload FROM lab_runs ORDER BY rowid DESC')
        ]

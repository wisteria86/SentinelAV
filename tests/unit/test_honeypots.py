# Purpose: Verify decoy deployment, read and change detection, safe removal, and the network honeypot.
# Works with: monitoring.helpers.honeypots

"""Verify decoy deployment, read and change detection, safe removal, and the network honeypot."""

import os
import socket
import tempfile
import time
import unittest
from pathlib import Path

from sentinelav.monitoring.helpers import honeypots


def overwrite(path, data):
    """Windows refuses to recreate a hidden file, so change it in place as ransomware does."""
    with open(path, 'r+b') as stream:
        stream.write(data)
        stream.truncate()


class FakeBehavior:
    def __init__(self):
        self.calls = []

    def indicator(self, entity, category, weight, reason, **metadata):
        self.calls.append((entity, category, weight))


class DecoyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = Path(self.folder.name)
        (self.home / 'Documents').mkdir()
        (self.home / 'Desktop').mkdir()

    def test_deploy_creates_marked_decoys_and_never_overwrites(self):
        existing = self.home / 'Documents' / 'passwords-backup.txt'
        existing.write_text('my real file', encoding='utf-8')
        entries = honeypots.deploy(self.home)
        paths = {Path(entry['path']).name for entry in entries}
        self.assertNotIn('passwords-backup.txt', paths)
        self.assertEqual(existing.read_text(encoding='utf-8'), 'my real file')
        self.assertEqual(
            len([e for e in entries if e['kind'] == 'ransomware_trap']), len(honeypots.TRAP_FILES)
        )
        self.assertTrue(
            all(
                Path(e['path']).read_text(encoding='utf-8').startswith(honeypots.MARKER)
                for e in entries
            )
        )
        self.assertEqual(honeypots.deploy(self.home), [])

    def test_read_change_and_delete_are_reported_once_each(self):
        entries = [e for e in honeypots.deploy(self.home) if e['kind'] != 'ransomware_trap']
        events = []
        behavior = FakeBehavior()
        holder = [dict(pid=4242, name='stealer.exe', exe='C:/x/stealer.exe', create_time=1.0)]
        watcher = honeypots.HoneypotWatcher(
            entries, events.append, behavior, find_holders=lambda path: holder
        )
        self.assertEqual(watcher.poll(), [])
        target = Path(entries[0]['path'])
        time.sleep(0.05)
        target.read_bytes()
        # Some volumes update access time lazily; force the observable effect a read has.
        os.utime(target, ns=(target.stat().st_atime_ns + 10_000_000, target.stat().st_mtime_ns))
        self.assertEqual([e['state'] for e in watcher.poll()], ['read'])
        self.assertIn('stealer.exe (PID 4242)', events[-1]['details'])
        self.assertEqual(behavior.calls[-1][1:], ('decoy_access', 70))
        self.assertEqual(watcher.poll(), [])
        overwrite(entries[1]['path'], b'encrypted!')
        self.assertEqual([e['state'] for e in watcher.poll()], ['modified'])
        Path(entries[2]['path']).unlink()
        events_now = watcher.poll()
        self.assertEqual([e['state'] for e in events_now], ['deleted or renamed'])
        self.assertEqual(events_now[0]['level'], 'Alert')

    def test_mass_trap_changes_mention_ransomware(self):
        entries = [e for e in honeypots.deploy(self.home) if e['kind'] == 'ransomware_trap']
        events = []
        watcher = honeypots.HoneypotWatcher(entries, events.append, find_holders=lambda path: [])
        for entry in entries[:4]:
            overwrite(entry['path'], bytes(64))
        watcher.poll()
        self.assertTrue(all('ransomware' in event['details'] for event in events))

    def test_remove_keeps_changed_decoys_and_unrelated_files(self):
        entries = honeypots.deploy(self.home)
        overwrite(entries[0]['path'], b'changed by something')
        mine = self.home / 'Documents' / honeypots.TRAP_FOLDER / 'my own file.txt'
        mine.write_text('keep', encoding='utf-8')
        kept = honeypots.remove(entries)
        self.assertEqual([entry['path'] for entry in kept], [entries[0]['path']])
        self.assertTrue(mine.exists())
        self.assertFalse(Path(entries[1]['path']).exists())


class NetworkHoneypotTests(unittest.TestCase):
    def test_connection_is_recorded_and_reported(self):
        events = []
        listener = honeypots.NetworkHoneypot(events.append, ports=(0,), host='127.0.0.1')
        port = listener.start()[0]
        self.addCleanup(listener.stop)
        with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
            client.sendall(b'USER root\r\n')
        deadline = time.monotonic() + 5
        while not events and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(events[0]['kind'], 'Network honeypot contacted')
        self.assertEqual(events[0]['level'], 'Warning')
        self.assertEqual(bytes.fromhex(events[0]['first_bytes']), b'USER root\r\n')

    def test_port_in_use_is_left_alone(self):
        busy = socket.socket()
        busy.bind(('127.0.0.1', 0))
        busy.listen()
        self.addCleanup(busy.close)
        listener = honeypots.NetworkHoneypot(
            lambda event: None, ports=(busy.getsockname()[1],), host='127.0.0.1'
        )
        self.assertEqual(listener.start(), [])
        self.assertEqual(listener.skipped, [busy.getsockname()[1]])


if __name__ == '__main__':
    unittest.main()

# Purpose: Verify deception features on a temporary profile, a throwaway registry key and loopback sockets only.
# Works with: monitoring.deception

"""Verify deception features on a temporary profile, a throwaway registry key and loopback sockets only."""
import os
import secrets
import socket
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sentinelav.monitoring.deception import accounts, breadcrumbs, clipboard, registry_decoys, sinkhole, stores, vaccines


class TempHome(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.home = Path(self.folder.name)
        (self.home / 'Documents').mkdir()
        patcher = mock.patch.dict(os.environ, SENTINELAV_DECOY_HOME=str(self.home))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.folder.cleanup)


class StoreTests(TempHome):
    def test_store_is_placed_parsed_and_removed_completely(self):
        entries, record = stores.deploy([s for s in stores.STORES if s[0] == 'Google Chrome'])
        path = Path(entries[0]['path'])
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM logins').fetchone()[0], 3)
        db.close()
        stores.remove(record)
        self.assertFalse((self.home / 'AppData').exists())

    def test_existing_app_folder_is_never_touched(self):
        real = self.home / 'AppData' / 'Roaming' / 'FileZilla'
        real.mkdir(parents=True)
        entries, _ = stores.deploy([s for s in stores.STORES if s[0] == 'FileZilla'])
        self.assertEqual(entries, [])
        self.assertEqual(list(real.iterdir()), [])

    def test_store_retires_when_the_app_is_installed(self):
        marker = self.home / 'chrome.exe'
        store = ('Test', 'local', 'Test/User Data', [('Profile 9/Login Data', 'browser_store', lambda: b'x')], [str(marker)])
        _, record = stores.deploy([store])
        marker.write_bytes(b'')
        kept, retired = stores.retire_installed(record)
        self.assertEqual((kept, retired), ([], ['Test']))
        self.assertFalse((self.home / 'AppData' / 'Local' / 'Test').exists())


@unittest.skipUnless(os.name == 'nt', 'Windows registry')
class RegistryTests(unittest.TestCase):
    def setUp(self):
        import winreg
        self.base = r'Software\SentinelAV-Test-' + secrets.token_hex(4)
        self.addCleanup(registry_decoys._delete_tree, winreg.HKEY_CURRENT_USER, self.base)
        self.specs = [('session', r'App\Tool', r'Sessions\Decoy', dict(HostName='127.0.0.2', PortNumber=4444))]

    def test_change_is_seen_and_removal_keeps_real_entries(self):
        import winreg
        record = registry_decoys.deploy(self.specs, base=self.base)
        self.assertEqual(registry_decoys.changed(record), [])
        registry_decoys._write(winreg.HKEY_CURRENT_USER, record[0]['path'], dict(HostName='evil.example.invalid'))
        self.assertEqual(registry_decoys.changed(record)[0][1], 'modified')
        registry_decoys._write(winreg.HKEY_CURRENT_USER, self.base + r'\App\Tool\Sessions\Real', dict(HostName='real'))
        registry_decoys.remove(record, base=self.base)
        self.assertIsNone(registry_decoys._read(winreg.HKEY_CURRENT_USER, record[0]['path']))
        self.assertEqual(registry_decoys._read(winreg.HKEY_CURRENT_USER, self.base + r'\App\Tool\Sessions\Real'), dict(HostName='real'))

    def test_nothing_is_added_next_to_an_installed_app(self):
        import winreg
        registry_decoys._write(winreg.HKEY_CURRENT_USER, self.base + r'\App\Tool', dict(Version=1))
        self.assertEqual(registry_decoys.deploy(self.specs, base=self.base), [])


class ServerTests(unittest.TestCase):
    def test_decoy_server_reports_who_connected(self):
        events = []
        port = breadcrumbs.free_port('127.0.0.1')
        server = breadcrumbs.DecoyServers(dict(rdp=port), events.append, host='127.0.0.1', owner=lambda *a: dict(pid=7, name='stealer.exe', exe='', create_time=0))
        self.addCleanup(server.stop)
        self.assertEqual(server.start(), [port])
        with socket.create_connection(('127.0.0.1', port)) as client:
            client.sendall(b'Cookie: mstshash=backup-admin\r\n')
        for _ in range(40):
            if events:
                break
            time.sleep(.05)
        self.assertIn('stealer.exe (PID 7)', events[0]['details'])

    def test_tarpit_trickles_and_reports(self):
        events = []
        port = breadcrumbs.free_port('127.0.0.1')
        pit = breadcrumbs.TarpitHoneypot(events.append, [port], interval=.05, hold=1, host='127.0.0.1')
        self.addCleanup(pit.stop)
        pit.start()
        with socket.create_connection(('127.0.0.1', port), timeout=2) as client:
            self.assertEqual(client.recv(1), b'\r')
        self.assertEqual(events[0]['kind'], 'Network honeypot contacted')


class FakeClipboard:
    def __init__(self):
        self.value, self.number, self.input = '', 0, 1

    def sequence(self):
        return self.number

    def text(self):
        return self.value

    def copy(self, value, typed=True):
        self.value, self.number = value, self.number + 1
        self.input += typed

    def owner(self):
        return dict(pid=9, name='clipper.exe', exe='', create_time=0)

    def last_input(self):
        return self.input


class ClipboardTests(unittest.TestCase):
    def test_swap_without_input_is_reported_and_user_copies_are_not(self):
        board, events = FakeClipboard(), []
        guard = clipboard.ClipboardGuard(events.append, clipboard=board)
        board.copy('0x' + 'a' * 40)
        guard.poll()
        board.copy('0x' + 'b' * 40, typed=False)
        guard.poll()
        self.assertIn('clipper.exe', events[0]['details'])
        board.copy('0x' + 'c' * 40, typed=True)
        guard.poll()
        self.assertEqual(len(events), 1)

    def test_wallet_shapes_and_bait_checksum(self):
        self.assertEqual(clipboard.wallet_kind('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'), 'bitcoin')
        self.assertIsNone(clipboard.wallet_kind('hello world'))
        self.assertEqual(clipboard.wallet_kind(clipboard.decoy_address()), 'bitcoin')


class SinkholeTests(unittest.TestCase):
    def test_block_is_added_and_removed_without_touching_other_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            hosts = Path(folder) / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n', encoding='utf-8')
            with mock.patch.object(sinkhole, '_flush'):
                sinkhole.apply(sinkhole.parse('127.0.0.1\tbad.example.invalid\n# comment\n127.0.0.1 localhost\n'), hosts)
                self.assertIn('127.0.0.3 bad.example.invalid', hosts.read_text(encoding='utf-8'))
                sinkhole.remove(hosts)
            self.assertEqual(hosts.read_text(encoding='utf-8'), '127.0.0.1 localhost\n')

    def test_host_header_is_read(self):
        self.assertEqual(sinkhole.requested_name(b'GET / HTTP/1.1\r\nHost: bad.example.invalid\r\n\r\n'), 'bad.example.invalid')


class LogonWatcherTests(unittest.TestCase):
    def test_only_new_events_naming_a_decoy_are_reported(self):
        def xml(record, name):
            return (f"<Event><System><EventID>4625</EventID><EventRecordID>{record}</EventRecordID></System>"
                    f"<EventData><Data Name='TargetUserName'>{name}</Data><Data Name='IpAddress'>10.0.0.5</Data></EventData></Event>")
        replies = iter([[xml(10, 'backup_admin')], [xml(11, 'alice'), xml(12, 'BACKUP_ADMIN')]])
        events = []
        watcher = accounts.LogonWatcher(events.append, ['backup_admin'], query=lambda after: next(replies))
        self.assertEqual(watcher.poll(), [])
        self.assertEqual(len(watcher.poll()), 1)
        self.assertIn('10.0.0.5', events[0]['details'])


@unittest.skipUnless(os.name == 'nt', 'Windows objects')
class VaccineTests(unittest.TestCase):
    def test_mutex_is_held_and_marker_file_removed_only_if_ours(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'marker'
            held = vaccines.Vaccines([dict(family='Test', type='mutex', name='Local\\SentinelAV-test-' + secrets.token_hex(4)),
                                      dict(family='Test', type='file', paths=[str(marker)])])
            self.assertEqual(len(held.start()), 2)
            held.stop()
            vaccines.remove_files([str(marker)])
            self.assertFalse(marker.exists())

    def test_published_markers_cite_sources(self):
        self.assertTrue(all(item['sources'] for item in vaccines.markers()))


@unittest.skipUnless(os.name == 'nt', 'Windows memory API')
class InjectionTests(unittest.TestCase):
    def test_new_executable_memory_is_seen(self):
        import ctypes
        from sentinelav.monitoring.deception import decoy_process
        before = decoy_process.executable_private_regions()
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        block = kernel32.VirtualAlloc(None, 4096, 0x3000, 0x40)
        self.addCleanup(kernel32.VirtualFree, block, 0, 0x8000)
        self.assertIn(block, decoy_process.executable_private_regions() - before)


if __name__ == '__main__':
    unittest.main()

# Purpose: Verify the streaming vault, one-step removal and the automatic quarantine policy.
# Works with: response.vault, response.response, response.auto_response, monitoring.core.behavior, monitoring.core.event_sources
# Used by: test.ps1

"""Verify the streaming vault, one-step removal and the automatic quarantine policy. Fixtures are harmless."""

import io
import os
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path

from sentinelav.monitoring.core.behavior import BehaviorEngine
from sentinelav.monitoring.core.event_sources import PendingFiles, still_downloading
from sentinelav.response.auto_response import eligibility, policy_for
from sentinelav.response.response_files import dpapi
from sentinelav.response.vault import CHUNK, encrypt_stream, plain_digest, read_plain


class VaultTests(unittest.TestCase):
    def seal(self, folder, data, identity=b'a' * 32):
        blob = Path(folder) / 'item.sav'
        with blob.open('wb') as output:
            sha, size = encrypt_stream(io.BytesIO(data), output, identity)
        return blob, sha, size

    def test_round_trip_across_chunks_and_no_plaintext_on_disk(self):
        data = b'recognizable plaintext marker ' * (CHUNK // 10)
        with tempfile.TemporaryDirectory() as folder:
            blob, sha, size = self.seal(folder, data)
            self.assertEqual(size, len(data))
            self.assertEqual(b''.join(read_plain(blob, b'a' * 32)), data)
            self.assertNotIn(b'recognizable plaintext marker', blob.read_bytes())
            self.assertEqual(plain_digest(blob, b'a' * 32), sha)

    def test_empty_file_round_trips(self):
        with tempfile.TemporaryDirectory() as folder:
            blob, _, size = self.seal(folder, b'')
            self.assertEqual(size, 0)
            self.assertEqual(b''.join(read_plain(blob, b'a' * 32)), b'')

    def test_tampering_truncation_and_wrong_identity_are_refused(self):
        data = os.urandom(CHUNK + 100)
        with tempfile.TemporaryDirectory() as folder:
            blob, _, _ = self.seal(folder, data)
            raw = bytearray(blob.read_bytes())
            flipped = Path(folder) / 'flipped.sav'
            copy = bytearray(raw)
            copy[-20] ^= 1
            flipped.write_bytes(copy)
            with self.assertRaises(ValueError):
                plain_digest(flipped, b'a' * 32)
            short = Path(folder) / 'short.sav'
            short.write_bytes(raw[: len(raw) - CHUNK // 2])
            with self.assertRaises(ValueError):
                plain_digest(short, b'a' * 32)
            with self.assertRaises(ValueError):
                plain_digest(blob, b'b' * 32)

    def test_dropping_the_final_chunk_is_detected(self):
        data = os.urandom(CHUNK * 2)
        with tempfile.TemporaryDirectory() as folder:
            blob, _, _ = self.seal(folder, data)
            raw = blob.read_bytes()
            cut = Path(folder) / 'cut.sav'
            cut.write_bytes(raw[: len(raw) - (5 + 12 + CHUNK + 16)])
            with self.assertRaises(ValueError):
                plain_digest(cut, b'a' * 32)

    def test_items_from_the_previous_format_stay_readable(self):
        with tempfile.TemporaryDirectory() as folder:
            legacy = Path(folder) / 'old.sav'
            legacy.write_bytes(dpapi(b'older quarantine item'))
            self.assertEqual(b''.join(read_plain(legacy, b'ignored')), b'older quarantine item')


class AutomaticPolicyTests(unittest.TestCase):
    def event(self, folder, **fields):
        return dict(
            dict(
                sha256='a' * 64,
                path=str(Path(folder) / 'x.exe'),
                verdict='Malicious',
                automatic_response_eligible=True,
                reasons=['Fixture'],
            ),
            **fields,
        )

    def test_defaults_cover_watched_folders_and_respect_saved_choices(self):
        policy = policy_for(None, ['C:/Watched'])
        self.assertTrue(policy['enabled'])
        self.assertTrue(policy['high_confidence'])
        self.assertEqual(policy['roots'], ['C:/Watched'])
        self.assertFalse(policy_for(dict(enabled=False), ['C:/Watched'])['enabled'])
        self.assertEqual(policy_for(dict(enabled=True), ['C:/Watched']).get('roots'), None)

    def test_high_confidence_finding_inside_scope_is_eligible(self):
        with tempfile.TemporaryDirectory() as folder:
            allowed, reason = eligibility(self.event(folder), policy_for(None, [folder]))
            self.assertTrue(allowed, reason)

    def test_everything_short_of_the_policy_stays_manual(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as other:
            policy = policy_for(None, [folder])
            self.assertFalse(
                eligibility(self.event(folder, automatic_response_eligible=False), policy)[0]
            )
            self.assertFalse(eligibility(self.event(folder, verdict='Suspicious'), policy)[0])
            self.assertFalse(eligibility(self.event(folder, member_chain=['a.exe']), policy)[0])
            self.assertFalse(eligibility(self.event(other), policy)[0])
            self.assertFalse(eligibility(self.event(folder), dict(policy, enabled=False))[0])
            self.assertFalse(eligibility(self.event(folder), dict(enabled=True, roots=[folder]))[0])


class RealTimeTests(unittest.TestCase):
    def test_partial_downloads_wait_for_their_final_name(self):
        self.assertTrue(still_downloading('C:/Downloads/setup.exe.crdownload'))
        self.assertTrue(still_downloading('C:/Downloads/setup.exe.PART'))
        self.assertFalse(still_downloading('C:/Downloads/setup.exe'))

    def test_a_retry_waits_for_its_backoff(self):
        pending = PendingFiles(delay=0)
        pending.add('C:/a.bin', 'Filesystem', wait=30)
        self.assertIsNone(pending.pop())
        pending.add('C:/a.bin', 'Filesystem')
        self.assertIsNotNone(pending.pop())


Address = namedtuple('Address', 'ip port')
Connection = namedtuple('Connection', 'status raddr pid')


class NetworkHeuristicTests(unittest.TestCase):
    def run_network(self, exe, port, flag=None):
        events = []
        engine = BehaviorEngine(events.append)
        if flag:
            engine.flag_image(exe, flag)
        info = {7: dict(pid=7, create_time=1.0, exe=exe)}
        engine.network([Connection('ESTABLISHED', Address('8.8.8.8', port), 7)], info)
        return events

    def test_no_user_supplied_indicator_list_is_needed(self):
        events = self.run_network('C:/Users/a/AppData/Local/Temp/x.exe', 4444)
        self.assertTrue(events)
        self.assertIn(
            'remote_control_port', [item['category'] for item in events[-1]['indicators']]
        )

    def test_installed_program_on_a_normal_port_stays_quiet(self):
        self.assertFalse(self.run_network('C:/Program Files/App/app.exe', 443))
        self.assertFalse(self.run_network('C:/Program Files/App/app.exe', 4444))

    def test_a_program_flagged_by_the_file_scanner_is_correlated(self):
        events = self.run_network('C:/Program Files/App/app.exe', 443, flag='Suspicious')
        self.assertIn(
            'flagged_image_network', [item['category'] for item in events[-1]['indicators']]
        )

# Purpose: Verify the ClamAV client, third-party rule packs and how their evidence is scored.
# Works with: detection.clamav_engine, detection.rule_packs, detection.threat_score

"""Verify the ClamAV client, third-party rule packs and how their evidence is scored."""
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from sentinelav.detection import clamav_engine, rule_packs
from sentinelav.detection.file_analysis import signature_items
from sentinelav.detection.threat_score import arm_scores, automatic_eligible, score


class FakeClamd:
    """Speaks just enough of the clamd protocol: PING and INSTREAM."""

    def __init__(self, verdict=lambda data: None):
        self.verdict = verdict
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.server.listen()
        self.endpoint = ('127.0.0.1', self.server.getsockname()[1])
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            with connection:
                command = b''
                while not command.endswith(b'\0'):
                    command += connection.recv(1)
                if command == b'zPING\0':
                    connection.sendall(b'PONG\0')
                    continue
                data = bytearray()
                while True:
                    size = struct.unpack('>I', self.read(connection, 4))[0]
                    if not size:
                        break
                    data.extend(self.read(connection, size))
                found = self.verdict(bytes(data))
                connection.sendall((f'stream: {found} FOUND' if found else 'stream: OK').encode() + b'\0')

    @staticmethod
    def read(connection, size):
        chunk = b''
        while len(chunk) < size:
            chunk += connection.recv(size - len(chunk))
        return chunk

    def close(self):
        self.server.close()


class ClamAVClientTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeClamd(lambda data: 'Win.Test.Marker-1' if b'MARKER' in data else None)
        self.addCleanup(self.fake.close)

    def test_streams_large_content_in_chunks_and_reports_signature(self):
        payload = b'A' * (3 * clamav_engine.CHUNK + 5) + b'MARKER'
        self.assertEqual(clamav_engine.scan_bytes(self.fake.endpoint, payload), 'Win.Test.Marker-1')
        self.assertIsNone(clamav_engine.scan_bytes(self.fake.endpoint, b'harmless'))

    def test_endpoint_file_is_used_only_while_clamd_answers(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder)
            (database / clamav_engine.ENDPOINT_FILE).write_text(json.dumps(dict(port=self.fake.endpoint[1])), encoding='utf-8')
            self.assertEqual(clamav_engine.read_endpoint(database), self.fake.endpoint)
            self.fake.close()
            self.assertIsNone(clamav_engine.read_endpoint(database))

    def test_engine_reports_signature_and_heuristic_separately(self):
        from sentinelav.detection.engine import Scanner
        fake = FakeClamd(lambda data: 'Heuristics.Encrypted.Zip' if b'ZIPPY' in data else 'Doc.Dropper.Agent-1' if b'MARKER' in data else None)
        self.addCleanup(fake.close)
        with mock.patch('sentinelav.detection.clamav_engine.read_endpoint', return_value=fake.endpoint):
            scanner = Scanner(Path('resources/signatures.json'), Path('resources/rules'), options=dict(rule_packs=False))
        self.assertEqual(scanner.analyze_bytes(b'xx MARKER')[0], ['ClamAV: Doc.Dropper.Agent-1'])
        names, matches, _ = scanner.analyze_bytes(b'ZIPPY')
        self.assertEqual(names, [])
        self.assertEqual(matches[0]['layer'], 'clamav_heuristic')

    def test_lost_service_becomes_one_warning_not_per_file_errors(self):
        from sentinelav.detection.engine import Scanner
        with mock.patch('sentinelav.detection.clamav_engine.read_endpoint', return_value=('127.0.0.1', 1)):
            scanner = Scanner(Path('resources/signatures.json'), Path('resources/rules'), options=dict(rule_packs=False))
        _, _, errors = scanner.analyze_bytes(b'anything')
        self.assertEqual(errors, [])
        self.assertIsNone(scanner.clamav)
        self.assertTrue(any('ClamAV stopped answering' in item for item in scanner.warnings))


class ClamAVScoringTests(unittest.TestCase):
    def test_signature_is_decisive_and_excluded_from_generalized_arm(self):
        items = signature_items(['ClamAV: Win.Trojan.Agent-1'], [])
        assessed = score(items)
        self.assertEqual((assessed['score'], assessed['verdict']), (100, 'Malicious'))
        self.assertTrue(automatic_eligible(assessed))
        self.assertEqual(arm_scores(items)['generalized']['verdict'], 'Clean')

    def test_signed_file_with_clamav_signature_needs_a_person(self):
        assessed = score(signature_items(['ClamAV: Win.Trojan.Agent-1'], []), trusted=True)
        self.assertEqual(assessed['verdict'], 'Suspicious')
        self.assertFalse(automatic_eligible(assessed))

    def test_heuristic_alone_stays_below_malicious(self):
        match = dict(rule='Heuristics.Phishing', code='clamav_heuristic', scope='generic', layer='clamav_heuristic',
            group='clamav_heuristic', weight=40, description='ClamAV heuristic')
        assessed = score(signature_items([], [match]))
        self.assertEqual(assessed['verdict'], 'Suspicious')
        self.assertEqual(arm_scores(signature_items([], [match]))['generalized']['verdict'], 'Suspicious')


PACK = '''
rule MAL_Example_Family { meta: score = 80 description = "family" strings: $a = "FAMILYBYTES" condition: $a }
rule SUSP_Example_Trait { meta: score = 75 description = "trait" strings: $a = "TRAITBYTES" condition: $a }
rule MAL_Low_Score { meta: score = 65 strings: $a = "LOWBYTES" condition: $a }
rule MAL_Disabled { meta: score = 90 strings: $a = "NOISYBYTES" condition: $a }
'''


class RulePackTests(unittest.TestCase):
    def test_family_rules_decide_and_technique_rules_add_capped_weight(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, SENTINELAV_DEFINITIONS=folder):
            source = Path(folder) / 'source.yar'
            source.write_text(PACK, encoding='utf-8')
            rule_packs.install('yara-forge', source, 'test', 'local', '0' * 64, disabled={'MAL_Disabled': 'false positive'})
            pack = rule_packs.RulePack('yara-forge')
            again = rule_packs.RulePack('yara-forge')
            self.assertEqual(again.count, 4)
            kinds = {item['rule']: item['kind'] for item in pack.match(b'FAMILYBYTES TRAITBYTES LOWBYTES NOISYBYTES')}
        self.assertEqual(kinds, {'MAL_Example_Family': 'family', 'SUSP_Example_Trait': 'technique', 'MAL_Low_Score': 'technique'})

    def test_tampered_pack_is_refused(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, SENTINELAV_DEFINITIONS=folder):
            source = Path(folder) / 'source.yar'
            source.write_text(PACK, encoding='utf-8')
            manifest = rule_packs.install('yara-forge', source, 'test', 'local', '0' * 64)
            (Path(folder) / 'yara-forge' / manifest['file']).write_text(PACK + '\n// changed', encoding='utf-8')
            packs, warnings = rule_packs.load_packs()
        self.assertEqual(packs, [])
        self.assertIn('pinned digest', warnings[0])

    def test_several_technique_rules_cannot_reach_malicious(self):
        items = signature_items([], [rule_packs.classify(f'SUSP_Trait_{n}', dict(score=80)) for n in range(6)])
        self.assertLess(score(items)['score'], 70)


if __name__ == '__main__':
    unittest.main()

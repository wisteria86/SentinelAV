# Purpose: Verify test engine behavior using controlled fixtures.
# Works with: data.storage, detection.engine, paths
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from sentinelav.detection.engine import Scanner
from sentinelav.data.storage import Store


class EngineTests(unittest.TestCase):
    def test_hash_yara_exclusions_and_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = root / 'files'
            files.mkdir()
            (files / 'clean.txt').write_text('ordinary document')
            marker = b'SENTINELAV_DEMO_THREAT_7C23A'
            (files / 'demo.txt').write_bytes(marker)
            (files / 'excluded.txt').write_bytes(marker)
            signatures = root / 'signatures.json'
            signatures.write_text(json.dumps({hashlib.sha256(marker).hexdigest(): 'Test hash'}))
            scanner = Scanner(
                signatures, RESOURCE_ROOT / 'rules', exclusions=[files / 'excluded.txt']
            )
            result = scanner.scan([files, files / 'demo.txt'], lambda: False, lambda *args: None)
            self.assertEqual(result['scanned'], 2)
            self.assertEqual(len(result['detections']), 1)
            self.assertIn('SHA-256: Test hash', result['detections'][0]['reasons'])
            if scanner.rules:
                self.assertIn('YARA: SentinelAV_Harmless_Demo', result['detections'][0]['reasons'])
            store = Store(root / 'db.sqlite')
            store.save_scan(result)
            self.assertEqual(store.history()[0], result)
            store.set('max_mb', 20)
            self.assertEqual(store.get('max_mb', 100), 20)
            store.db.close()

    def test_cancel_and_size_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            signatures = root / 'signatures.json'
            signatures.write_text('{}')
            target = root / 'large.txt'
            target.write_bytes(b'x' * 1025 * 1024)
            scanner = Scanner(signatures, root / 'rules', max_mb=1)
            result = scanner.scan([target], lambda: False, lambda *args: None)
            self.assertEqual(result['skipped'], 1)
            result = scanner.scan([target], lambda: True, lambda *args: None)
            self.assertEqual(result['status'], 'Cancelled')
            self.assertEqual(result['scanned'], 0)

    def test_missing_path_is_reported(self):
        scanner = Scanner(RESOURCE_ROOT / 'signatures.json', RESOURCE_ROOT / 'rules')
        result = scanner.scan(
            ['nonexistent-sentinelav-test-path'], lambda: False, lambda *args: None
        )
        self.assertEqual(result['status'], 'Complete with omissions')
        self.assertEqual(len(result['errors']), 1)

    def test_empty_roots_and_junction_roots_cannot_report_complete_inspection(self):
        scanner = Scanner(RESOURCE_ROOT / 'signatures.json', RESOURCE_ROOT / 'rules')
        empty = scanner.scan([], lambda: False, lambda *args: None)
        self.assertEqual(empty['status'], 'Complete with omissions')
        with patch.object(Path, 'is_junction', return_value=True), patch('os.walk') as walk:
            linked = scanner.scan([RESOURCE_ROOT], lambda: False, lambda *args: None)
        walk.assert_not_called()
        self.assertEqual(linked['scanned'], 0)
        self.assertIn('Linked scan root', linked['errors'][0])


if __name__ == '__main__':
    unittest.main()

# Purpose: Keep detection logic free of theZoo identifiers and prove the guard can actually fail.
# Works with: tools.maintenance.check_no_zoo_hardcoding
# Used by: test.ps1

"""Keep detection logic free of theZoo identifiers and prove the guard can actually fail."""

import json
import re
import unittest

from tools.maintenance import check_no_zoo_hardcoding as guard


class ZooHardcodingTests(unittest.TestCase):
    def test_detection_sources_are_clean(self):
        self.assertEqual(guard.findings(), [])

    def test_guard_recognizes_real_inventory_entries(self):
        tree = json.loads((guard.ROOT / 'resources/zoo-tree.json').read_text(encoding='utf-8'))
        blobs, samples = guard.inventory(tree)
        self.assertGreater(len(blobs), 1000)
        self.assertGreater(len(samples), 100)
        self.assertTrue(all(re.fullmatch('[0-9a-f]{40}', blob) for blob in blobs))

    def test_guard_catches_a_real_sample_name_and_blob_but_not_ordinary_words(self):
        tree = json.loads((guard.ROOT / 'resources/zoo-tree.json').read_text(encoding='utf-8'))
        blobs, samples = guard.inventory(tree)
        pattern = guard.sample_pattern(samples)
        blob = sorted(blobs)[0]
        name = next(
            entry['path'].split('/')[2]
            for entry in tree['entries']
            if entry['path'].startswith('malware/Binaries/') and entry['path'].count('/') >= 3
        )
        self.assertTrue(guard.scan_text(f"if name=='{name}':detected=True", blobs, pattern))
        self.assertTrue(guard.scan_text(f"KNOWN={{'{blob}'}}", blobs, pattern))
        self.assertTrue(guard.scan_text("rule CryptoLocker_match", blobs, pattern))
        self.assertEqual(
            guard.scan_text('the file format of a dropper is unknown', blobs, pattern), []
        )

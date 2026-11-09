# Purpose: Verify test learned zoo audit behavior using controlled fixtures.
# Works with: tools.evaluation.audit_learned_zoo
# Used by: unittest discovery

import unittest

from tools.evaluation.audit_learned_zoo import command, decode


class LearnedZooAuditTests(unittest.TestCase):
    def test_metadata_rejects_path_and_powershell_injection(self):
        for name in ("';exit 0;#", '../report.json', 'a\\b.bin'):
            with self.assertRaises(ValueError):
                command(dict(path=name, sha256='a' * 64))
        with self.assertRaises(ValueError):
            command(dict(path='fixed.bin', sha256="';exit 0;#"))

    def test_decoding_keeps_partial_detection_separate_from_review(self):
        value = 3 | 8 | 16 | (2 << 8) | (1 << 12) | (225 << 14) | (2 << 28)
        result = decode(1073741824 + value)
        self.assertEqual(result['outcome'], 'detected_incomplete')
        self.assertTrue(result['advanced_review'])
        self.assertFalse(result['scan_complete'])
        self.assertEqual(result['emulation_termination'], 'unsupported_api')
        self.assertEqual(result['api_attempts'], 225)
        self.assertEqual(result['diagnostic_count_capped_at_3'], 2)
        # The final attempted resolution can be observed after 10,000 allowed
        # API calls; metadata must preserve it without widening analysis limits.
        self.assertEqual(decode(1073741824 + (10001 << 14))['api_attempts'], 10001)
        for malformed in (0, 1073741824 + 2**30):
            with self.assertRaises(ValueError):
                decode(malformed)

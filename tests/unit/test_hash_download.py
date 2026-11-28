# Purpose: Verify test hash download behavior using controlled fixtures.
# Works with: tools.feeds.download_hashes
# Used by: unittest discovery

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.feeds.download_hashes import parse_export, save_candidate, NoRedirect, fetch


class HashDownloadTests(unittest.TestCase):
    def export(self, digest='a' * 64):
        return (
            '# MalwareBazaar recent export\n# "first_seen_utc", "sha256_hash", "signature"\n'
            f'"2026-11-01", "{digest}", "ExampleFamily"\n'
        ).encode()

    def test_commented_header_hash_validation_and_deduplication(self):
        raw = self.export() + f'"2026-11-01", "{"a"*64}", "OtherLabel"\n'.encode()
        signatures, rows = parse_export(raw)
        self.assertEqual(rows, 2)
        self.assertEqual(len(signatures), 1)
        self.assertIn('OtherLabel', signatures['a' * 64])
        for raw in (
            b'<html>Access denied</html>',
            self.export('invalid'),
            self.export().splitlines()[0],
        ):
            with self.assertRaises(ValueError):
                parse_export(raw)

    def test_candidate_keeps_active_database_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            active = Path(temp) / 'signatures.json'
            active.write_text('{}')
            folder, manifest = save_candidate(self.export(), Path(temp) / 'feeds')
            self.assertEqual(active.read_text(), '{}')
            self.assertFalse(manifest['activated'])
            self.assertFalse(manifest['samples_downloaded'])
            self.assertEqual(len(json.loads((folder / 'signatures.candidate.json').read_text())), 1)
            self.assertNotIn('auth', (folder / 'manifest.json').read_text().lower())

    def test_redirects_are_refused(self):
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.com')

    def test_network_failure_does_not_reveal_key(self):
        import urllib.error

        with patch('tools.feeds.download_hashes.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect = urllib.error.URLError('SECRET-KEY in URL')
            with self.assertRaises(ValueError) as error:
                fetch('SECRET-KEY')
            self.assertNotIn('SECRET-KEY', str(error.exception))


if __name__ == '__main__':
    unittest.main()

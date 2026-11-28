# Purpose: Verify test static corpus behavior using controlled fixtures.
# Works with: lab.static_corpus
# Used by: unittest discovery

import hashlib
from io import BytesIO
import unittest
from unittest.mock import patch
import zipfile
from sentinelav.lab.static_corpus import SPECS, decode_archive, main, validate_archive


class StaticCorpusTests(unittest.TestCase):
    def test_guest_guard_precedes_input_and_decryption(self):
        with (
            patch('sentinelav.lab.static_corpus.verified_offline_guest', return_value=False),
            patch('sentinelav.lab.static_corpus.AESGCM') as cipher,
        ):
            with self.assertRaises(ValueError):
                main('not-a-key')
            cipher.assert_not_called()

    def test_all_four_families_are_preselected_with_member_identity(self):
        self.assertEqual(len(SPECS), 4)
        self.assertEqual(len({s['id'] for s in SPECS}), 4)
        for spec in SPECS:
            self.assertIn(spec['algorithm'], ('sha256', 'sha1', 'md5'))
            with self.assertRaises(ValueError):
                validate_archive(b'Invalid harmless archive', spec)

    def test_auxiliary_member_not_decoded_and_selected_member_hash_required(self):
        content = b'Harmless selected unit fixture'
        memory = BytesIO()
        with zipfile.ZipFile(memory, 'w') as archive:
            archive.writestr('selected.bin', content)
            archive.writestr('../../auxiliary.exe', b'Harmless excluded unit fixture')
        raw = memory.getvalue()
        archive_hash = hashlib.sha256(raw).hexdigest()
        spec = dict(
            member='selected.bin',
            algorithm='sha256',
            member_hash=hashlib.sha256(content).hexdigest(),
            published=archive_hash,
        )
        metadata = dict(
            member_bytes=len(content), archive_sha256=archive_hash, auxiliary_members_not_selected=1
        )
        with patch('sentinelav.lab.static_corpus.validate_archive', return_value=metadata):
            actual, record = decode_archive(raw, spec)
            self.assertEqual(actual, content)
            self.assertEqual(record['published_digest_scope'], 'archive')
            self.assertEqual(record['auxiliary_members_not_selected'], 1)
            spec['member_hash'] = '0' * 64
            with self.assertRaises(ValueError):
                decode_archive(raw, spec)

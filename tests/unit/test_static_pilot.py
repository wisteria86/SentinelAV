# Purpose: Verify test static pilot behavior using controlled fixtures.
# Works with: lab.static_pilot
# Used by: unittest discovery

import hashlib
from io import BytesIO
import unittest
from unittest.mock import patch
import zipfile

from sentinelav.lab.static_pilot import decode_sample, main, validate_archive


class StaticPilotTests(unittest.TestCase):
    def test_guest_guard_precedes_decryption_and_file_reads(self):
        with (
            patch('sentinelav.lab.static_pilot.verified_offline_guest', return_value=False),
            patch('sentinelav.lab.static_pilot.AESGCM') as cipher,
        ):
            with self.assertRaises(ValueError):
                main('not-a-key')
            cipher.assert_not_called()

    def test_unpinned_archive_refused(self):
        with self.assertRaises(ValueError):
            validate_archive(b'Harmless invalid archive')

    def test_only_hash_matched_bytes_returned_and_archive_paths_ignored(self):
        content = b'Harmless unit fixture'
        memory = BytesIO()
        with zipfile.ZipFile(memory, 'w') as archive:
            archive.writestr('../../must-not-be-written.exe', content)
        with (
            patch('sentinelav.lab.static_pilot.validate_archive'),
            patch('sentinelav.lab.static_pilot.SAMPLE_SHA256', hashlib.sha256(content).hexdigest()),
        ):
            self.assertEqual(decode_sample(memory.getvalue()), content)
        with patch('sentinelav.lab.static_pilot.validate_archive'):
            with self.assertRaises(ValueError):
                decode_sample(memory.getvalue())

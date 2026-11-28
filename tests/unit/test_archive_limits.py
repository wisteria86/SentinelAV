# Purpose: Keep archive reading bounded, and a damaged or hostile member from hiding other members.
# Works with: detection.archive_inspection
# Used by: test.ps1

"""Keep archive reading bounded, and a damaged or hostile member from hiding other members."""

import io
import unittest
import zipfile

from sentinelav.detection.archive_inspection import inspect_archive


def zipped(*entries):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return raw.getvalue()


class ArchiveLimitTests(unittest.TestCase):
    def test_hostile_member_names_are_still_inspected_in_memory(self):
        seen = []

        def analyze(payload, name):
            seen.append(payload)
            return [], [], []

        _, omissions, _ = inspect_archive(zipped(('../../evil.exe', b'content')), analyze)
        self.assertEqual(seen, [b'content'])
        self.assertTrue(any('Unsafe' in item for item in omissions))

    def test_a_corrupt_member_cannot_hide_the_members_after_it(self):
        import struct as layout

        raw = bytearray(
            zipped(('first.bin', b'A' * 2000), ('second.bin', b'second member content'))
        )
        # Replace first.bin's compressed bytes with data that is not a valid deflate stream.
        size = layout.unpack_from('<I', raw, 18)[0]
        start = 30 + layout.unpack_from('<H', raw, 26)[0] + layout.unpack_from('<H', raw, 28)[0]
        raw[start : start + size] = b'\xff' * size
        seen = []

        def analyze(payload, name):
            seen.append(name)
            return [], [], []

        _, omissions, _ = inspect_archive(bytes(raw), analyze)
        self.assertEqual(seen, ['second.bin'])
        self.assertTrue(any('first.bin' in item for item in omissions), omissions)

    def test_entry_limit_is_reported(self):
        _, omissions, _ = inspect_archive(
            zipped(*[(f'{i}.txt', 'x') for i in range(5)]), lambda p, n: ([], [], []), max_entries=2
        )
        self.assertIn('Archive entry limit reached', omissions)

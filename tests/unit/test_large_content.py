# Purpose: Verify that padded scripts and large Office files are still decoded instead of skipped.
# Works with: detection.content_analysis, detection.documents, detection.archive_formats

"""Verify that padded scripts and large Office files are still decoded instead of skipped."""
import base64
import io
import random
import unittest
import zipfile

from sentinelav.detection.archive_formats import rar_members
from sentinelav.detection.content_analysis import normalized_variants
from sentinelav.detection.documents import macro_sources


class LargeContentTests(unittest.TestCase):
    def test_padded_script_tail_is_decoded(self):
        hidden = base64.b64encode(b'inert marker DownloadString placeholder text')
        script = b'var a="' + b'x' * 6_000_000 + b'";\n' + b'f("' + hidden + b'")'
        variants, omissions = normalized_variants(script, '.js')
        self.assertTrue(any(b'DownloadString' in payload for _, payload in variants))
        self.assertIn('Script normalized in part (head and tail)', omissions)

    def test_office_file_with_large_media_is_not_refused(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('[Content_Types].xml', '<Types/>')
            archive.writestr('word/media/image1.bin', random.Random(1).randbytes(6_000_000))  # 6 MB picture-like data
        _, omissions = macro_sources(buffer.getvalue())
        self.assertNotIn('Office container exceeds macro-extraction limits', omissions)

    def test_rar_members_are_read(self):
        # A hand-built RAR 4 archive holding one stored, inert text member.
        rar = bytes.fromhex('526172211a0700cf907300000d00000000000000acd8740080280015000000150000000280bc579d000000001430'
                            '0800200000006e6f74652e747874696e65727420726172206d656d6265722074657874c43d7b00400700')
        members = rar_members(rar)
        self.assertEqual([m.name for m in members], ['note.txt'])
        self.assertEqual(members[0].read(100), b'inert rar member text')


if __name__ == '__main__':
    unittest.main()

# Purpose: Verify the MD5 hash list and the code-signing certificate blocklist on generated inert data.
# Works with: detection.md5_feed, detection.cert_blocklist, detection.threat_score

"""Verify the MD5 hash list and the code-signing certificate blocklist on generated inert data."""

import datetime
import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinelav.detection import cert_blocklist, md5_feed
from sentinelav.detection.file_analysis import signature_items
from sentinelav.detection.threat_score import score


def certificate():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Test Signer')])
    now = datetime.datetime(2026, 1, 1)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def signed_image(cert):
    """A header-only PE whose security directory holds a PKCS#7 bundle. It is not runnable."""
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

    bundle = pkcs7.serialize_certificates([cert], Encoding.DER)
    entry = struct.pack('<IHH', 8 + len(bundle), 0x200, 2) + bundle
    image = bytearray(0x200)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 0x3C, 0x40)
    image[0x40:0x44] = b'PE\0\0'
    optional = 0x40 + 24
    struct.pack_into('<H', image, optional, 0x10B)
    struct.pack_into('<II', image, optional + 96 + 4 * 8, len(image), len(entry))
    return bytes(image) + entry


class CertificateBlocklistTests(unittest.TestCase):
    def test_listed_signer_is_recognized_and_unlisted_is_not(self):
        from cryptography.hazmat.primitives import hashes

        cert = certificate()
        image = signed_image(cert)
        self.assertEqual(
            cert_blocklist.thumbprints(image), [cert.fingerprint(hashes.SHA256()).hex()]
        )
        with (
            tempfile.TemporaryDirectory() as folder,
            mock.patch.dict(os.environ, SENTINELAV_DEFINITIONS=folder),
        ):
            source = Path(folder) / 'list.csv'
            source.write_text(
                '# header\n"time_stamp_utc","serial_number","thumbprint","thumbprint_algorithm","subject_cn","issuer_cn","valid_from","valid_to","Reason"\n'
                f'"2026-01-01","07","{cert.fingerprint(hashes.SHA256()).hex()}","SHA256","Test Signer","Test","x","y","TestLoader"\n',
                encoding='utf-8',
            )
            self.assertEqual(cert_blocklist.install(source), 1)
            self.assertEqual(cert_blocklist.blocklisted(image)['reason'], 'TestLoader')
            self.assertIsNone(cert_blocklist.blocklisted(signed_image(certificate())))

    def test_malformed_security_directory_is_ignored(self):
        image = bytearray(signed_image(certificate()))
        struct.pack_into('<II', image, 0x40 + 24 + 96 + 32, len(image) - 4, 4096)
        self.assertEqual(cert_blocklist.thumbprints(bytes(image)), [])
        self.assertEqual(cert_blocklist.thumbprints(b'not a program'), [])


class Md5FeedTests(unittest.TestCase):
    def test_build_activate_and_lookup(self):
        listed = hashlib.md5(b'listed sample').hexdigest()
        with (
            tempfile.TemporaryDirectory() as folder,
            mock.patch.dict(os.environ, SENTINELAV_DEFINITIONS=folder),
        ):
            lists = Path(folder) / 'vs'
            lists.mkdir()
            (lists / 'VirusShare_00000.md5').write_text(
                '# comment\n' + listed + '\nnot-a-hash\n' + listed + '\n', encoding='ascii'
            )
            metadata = md5_feed.build(virusshare_dir=lists, progress=lambda message: None)
            self.assertEqual(metadata['unique_md5'], 1)
            feed = md5_feed.Md5Feed()
            try:
                self.assertEqual(feed.get(listed), 'VirusShare')
                self.assertIsNone(feed.get(hashlib.md5(b'other').hexdigest()))
            finally:
                feed.close()

    def test_md5_identity_is_decisive_but_ignored_on_signed_files(self):
        items = signature_items(['MD5: listed by VirusShare'], [])
        self.assertEqual(score(items)['score'], 100)
        self.assertEqual(score(items, trusted=True)['verdict'], 'Clean')


if __name__ == '__main__':
    unittest.main()

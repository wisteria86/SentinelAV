# Purpose: Verify test definition updates behavior using controlled fixtures.
# Works with: detection.signature_db, updates.definition_updates, updates.hash_archive
# Used by: unittest discovery

from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZIP_DEFLATED
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sentinelav.updates.definition_updates import (
    apply_changes,
    apply_signed,
    verify_package,
    rollback,
    import_recent,
    load_active,
    update_lock,
    freshness,
)
from sentinelav.updates.hash_archive import import_archive, checksum
from sentinelav.detection.signature_db import SignatureIndex


class DefinitionUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.folder = self.root / 'signature-data'
        self.json = self.root / 'signatures.json'
        self.json.write_text(json.dumps({'a' * 64: 'MalwareBazaar: LegacyLabel'}))
        with ZipFile(self.root / 'full.zip', 'w', ZIP_DEFLATED) as z:
            z.writestr(
                'full.csv',
                '# "sha256_hash","signature"\n' + f'"{"a"*64}","Initial"\n"{"b"*64}","Keep"\n',
            )
        import_archive(self.root / 'full.zip', self.folder, True)
        self.key = Ed25519PrivateKey.generate()
        self.trust = self.root / 'trust.json'
        self.trust.write_text(
            json.dumps(
                dict(schema=1, keys={'test': self.key.public_key().public_bytes_raw().hex()})
            )
        )

    def tearDown(self):
        self.temp.cleanup()

    def package(self, changes=None, revision=1, **overrides):
        changes = changes or dict(upserts=[dict(sha256='c' * 64, labels=['Added'])], removals=[])
        payload = json.dumps(changes).encode()
        now = datetime.now(timezone.utc)
        manifest = dict(
            format=1,
            channel='stable',
            key_id='test',
            revision=revision,
            issued_utc=now.isoformat(),
            expires_utc=(now + timedelta(days=1)).isoformat(),
            base_database_sha256=load_active(self.folder)['database_sha256'],
            changes_sha256=hashlib.sha256(payload).hexdigest(),
        )
        manifest.update(overrides)
        raw = json.dumps(manifest).encode()
        path = self.root / 'update.zip'
        with ZipFile(path, 'w', ZIP_DEFLATED) as z:
            z.writestr('manifest.json', raw)
            z.writestr('changes.json', payload)
            z.writestr('signature.ed25519', self.key.sign(raw))
        return path

    def test_recent_merges_without_removing_absent_hashes_and_reclassifies_legacy_overlay(self):
        recent = self.root / 'recent.csv'
        recent.write_text(
            '# "sha256_hash","signature"\n' + f'"{"a"*64}","Corrected"\n"{"c"*64}","New"\n'
        )
        result = import_recent(self.folder, recent)
        index = SignatureIndex(self.json)
        try:
            self.assertEqual(len(index), 3)
            self.assertIn('Corrected', index['a' * 64])
            self.assertIn('b' * 64, index)
            self.assertEqual(result['delta']['added'], 1)
        finally:
            index.close()

    def test_removal_suppresses_legacy_overlay_and_recent_does_not_resurrect_it(self):
        apply_changes(self.folder, dict(upserts=[], removals=['a' * 64]), 'Manual correction')
        recent = self.root / 'recent.csv'
        recent.write_text('# "sha256_hash","signature"\n' + f'"{"a"*64}","Old source claim"\n')
        result = import_recent(self.folder, recent)
        index = SignatureIndex(self.json)
        try:
            self.assertNotIn('a' * 64, index)
            self.assertEqual(len(index), 1)
            self.assertEqual(result['delta']['ignored_revoked'], 1)
        finally:
            index.close()

    def test_signed_apply_then_rollback_preserves_replay_high_water(self):
        old = SignatureIndex(self.json)
        try:
            package = self.package()
            applied = apply_signed(self.folder, package, self.trust)
            self.assertEqual(applied['highest_signed_revision'], 1)
            self.assertNotIn('c' * 64, old)
            restored = rollback(self.folder)
            self.assertEqual(restored['unique_sha256'], 2)
            self.assertEqual(restored['highest_signed_revision'], 1)
            with self.assertRaisesRegex(ValueError, 'replay|downgrade'):
                apply_signed(self.folder, package, self.trust)
        finally:
            old.close()

    def test_signature_unknown_key_expiration_and_wrong_base_rejected(self):
        before = (self.folder / 'active.json').read_bytes()
        package = self.package(key_id='untrusted')
        with self.assertRaisesRegex(ValueError, 'not trusted'):
            apply_signed(self.folder, package, self.trust)
        package = self.package(
            expires_utc=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        )
        with self.assertRaisesRegex(ValueError, 'expired'):
            apply_signed(self.folder, package, self.trust)
        package = self.package(base_database_sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'different base'):
            apply_signed(self.folder, package, self.trust)
        self.assertEqual((self.folder / 'active.json').read_bytes(), before)

    def test_payload_tampering_and_manifest_tampering_rejected(self):
        package = self.package()
        with ZipFile(package) as z:
            values = {n: z.read(n) for n in z.namelist()}
        values['changes.json'] += b' '
        with ZipFile(package, 'w') as z:
            for name, value in values.items():
                z.writestr(name, value)
        with self.assertRaisesRegex(ValueError, 'payload checksum'):
            verify_package(package, self.trust)
        values['manifest.json'] += b' '
        with ZipFile(package, 'w') as z:
            for name, value in values.items():
                z.writestr(name, value)
        with self.assertRaisesRegex(ValueError, 'signature verification'):
            verify_package(package, self.trust)

    def test_atomic_failure_and_concurrent_mutator_leave_active_untouched(self):
        before = (self.folder / 'active.json').read_bytes()
        changes = dict(upserts=[dict(sha256='c' * 64, labels=['New'])], removals=[])
        with update_lock(self.folder):
            with self.assertRaisesRegex(ValueError, 'in progress'):
                apply_changes(self.folder, changes, 'Fixture')
        with patch(
            'sentinelav.updates.definition_updates.os.replace',
            side_effect=OSError('Fixture replace failure'),
        ):
            with self.assertRaises(OSError):
                apply_changes(self.folder, changes, 'Fixture')
        self.assertEqual((self.folder / 'active.json').read_bytes(), before)

    def test_corrupt_snapshot_and_corrupt_rollback_rejected(self):
        apply_changes(
            self.folder,
            dict(upserts=[dict(sha256='c' * 64, labels=['New'])], removals=[]),
            'Fixture',
        )
        active = load_active(self.folder)
        previous = json.loads((self.folder / active['previous_manifest']).read_text())
        with (self.folder / previous['database']).open('ab') as stream:
            stream.write(b'corruption')
        before = (self.folder / 'active.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'checksum'):
            rollback(self.folder)
        self.assertEqual((self.folder / 'active.json').read_bytes(), before)
        with (self.folder / active['database']).open('ab') as stream:
            stream.write(b'corruption')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            load_active(self.folder, verify=True)

    def test_staleness_uses_definition_age_not_rollback_activation(self):
        now = datetime.now(timezone.utc)
        metadata = dict(
            imported_utc=(now - timedelta(days=4)).isoformat(), activated_utc=now.isoformat()
        )
        self.assertEqual(freshness(metadata, now)[0], 'Stale')
        metadata['imported_utc'] = (now + timedelta(hours=1)).isoformat()
        self.assertEqual(freshness(metadata, now)[0], 'Clock mismatch')

    def test_full_reimport_preserves_revocations_and_signed_high_water(self):
        package = self.package(dict(upserts=[], removals=['a' * 64]), revision=7)
        apply_signed(self.folder, package, self.trust)
        result = import_archive(self.root / 'full.zip', self.folder, True)
        self.assertEqual(result['highest_signed_revision'], 7)
        self.assertEqual(result['revoked_omissions'], 1)
        index = SignatureIndex(self.json)
        try:
            self.assertNotIn('a' * 64, index)
            self.assertIn('b' * 64, index)
        finally:
            index.close()


if __name__ == '__main__':
    unittest.main()

# Purpose: Verify MalwareBazaar corpus selection, sealing and staging offline with harmless archives.
# Works with: lab.qualification.bazaar_corpus, lab.qualification.zoo_inventory

"""Verify MalwareBazaar corpus selection, sealing and staging offline with harmless archives."""
import base64
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from sentinelav.lab.qualification import bazaar_corpus
from sentinelav.lab.qualification.zoo_inventory import blob_identity, seal, unseal

HEADER = '# "first_seen_utc","sha256_hash","md5_hash","file_type_guess","signature"\n'


def export(rows):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('full.csv', '#\n' + HEADER + ''.join(
            f'"{seen}", "{sha}", "{"0" * 32}", "{kind}", "{family}"\n' for seen, sha, kind, family in rows))
    return buffer.getvalue()


class SelectionTests(unittest.TestCase):
    def test_window_family_cap_and_seed(self):
        rows = [(f'2026-11-0{1 + n % 3} 10:00:00', f'{n:064x}', 'exe', 'agenttesla' if n < 60 else f'family{n}') for n in range(80)]
        rows.append(('2026-12-01 00:00:00', 'f' * 64, 'exe', 'late'))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'full.csv.zip'
            path.write_bytes(export(rows))
            found = list(bazaar_corpus.candidates(path, '2026-11-01', '2026-11-04'))
            self.assertEqual(len(found), 80)
            chosen = bazaar_corpus.select(found, 1000, seed=7)
            again = bazaar_corpus.select(found, 1000, seed=7)
        families = [bazaar_corpus.family_of(row) for row in chosen]
        self.assertEqual(families.count('agenttesla'), bazaar_corpus.PER_FAMILY)
        self.assertEqual(len(chosen), bazaar_corpus.PER_FAMILY + 20)
        self.assertEqual([row['sha256_hash'] for row in chosen], [row['sha256_hash'] for row in again])
        self.assertEqual(bazaar_corpus.family_of({'signature': 'n/a', 'file_type_guess': 'elf'}), 'unlabeled-elf')


class StagingTests(unittest.TestCase):
    def test_stage_reseals_with_a_fresh_key_and_keeps_identity(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('harmless.txt', 'not a sample')
        data = buffer.getvalue()
        blob = blob_identity(data)
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, SENTINELAV_WORK_ROOT=folder):
            root = bazaar_corpus.corpus_root('dev')
            key = bazaar_corpus.corpus_key(root)
            self.assertEqual(bazaar_corpus.corpus_key(root), key)
            (root / (blob + '.sealed')).write_bytes(seal(data, key, blob))
            (root / 'manifest.json').write_text(json.dumps(dict(entries=[dict(sha256='a' * 64, blob=blob, bytes=len(data), family='test', file_type='zip', first_seen='x')])), encoding='utf-8')
            case = bazaar_corpus.cases('dev')[0]
            self.assertEqual(case['parameters']['revision'], 'bazaar:dev')
            output = Path(folder) / 'out'
            output.mkdir()
            staged = bazaar_corpus.stage(case['parameters'], output)
            transfer = base64.b64decode(staged['transfer_key'])
            self.assertNotEqual(transfer, key)
            self.assertEqual(unseal((output / (blob + '.sealed')).read_bytes(), transfer, blob), data)
            self.assertNotIn(b'not a sample', (root / (blob + '.sealed')).read_bytes())

    def test_missing_ciphertext_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, SENTINELAV_WORK_ROOT=folder):
            bazaar_corpus.corpus_root('dev')
            staged = bazaar_corpus.stage(dict(corpus='dev', revision='bazaar:dev', entries=[dict(blob='a' * 40, bytes=1)]), folder)
        self.assertEqual(staged['entries'][0]['stage_error'], 'FileNotFoundError')


if __name__ == '__main__':
    unittest.main()

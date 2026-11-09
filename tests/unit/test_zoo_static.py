# Purpose: Verify Zoo batch identity, signature policy and resume using harmless inputs.
# Works with: lab.qualification.zoo_inventory, zoo_guest, zoo_reporting, store.

from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from sentinelav.lab.qualification import zoo_inventory
from sentinelav.lab.qualification.contracts import SuiteManifest
from sentinelav.lab.qualification.store import RunStore
from sentinelav.lab.qualification.zoo_guest import verdict
from sentinelav.lab.qualification.zoo_reporting import render, validate_batch


class ZooStaticTests(unittest.TestCase):
    def test_quick_profile_uses_one_cached_signature_free_batch(self):
        from sentinelav.lab.static_corpus import SPECS
        case, = zoo_inventory.quick_cases()
        self.assertEqual((case['backend'], case['action'], case['mode']), ('sandbox', 'zoo_static', 'signature_free'))
        self.assertEqual([entry['blob'] for entry in case['parameters']['entries']], [spec['blob'] for spec in SPECS])
        self.assertEqual(case['parameters']['group'], 'base')

    def test_checked_in_inventory_covers_pinned_archives_and_split_parts(self):
        batches = zoo_inventory.cases()
        rows = [row for case in batches for row in case['parameters']['entries']]
        self.assertEqual(len(batches), 91)
        self.assertEqual(len({row['path'] for row in rows}), 361)
        self.assertEqual(sum(not row.get('unsupported') for row in rows), 359)

    def test_pinned_tree_and_resume(self):
        with TemporaryDirectory() as temporary:
            work = Path(temporary)
            # Synthetic tree metadata uses no specimen objects.
            records = [dict(mode='100644', type='blob', oid='a'*40, size=10,
                            path=f'malware/Binaries/demo/{i}.zip') for i in range(5)]
            records.append(dict(mode='100644', type='blob', oid='b'*40, size=8,
                                path='malware/Binaries/demo/0.pass'))
            with patch.object(zoo_inventory, 'tree_entries', return_value=records):
                cases = zoo_inventory.cases()
            self.assertEqual([len(case['parameters']['entries']) for case in cases], [4, 1])
            self.assertEqual(cases[0]['parameters']['entries'][0]['password_blob'], 'b'*40)
            self.assertTrue(all(case['mode']=='signature_free' and case['backend']=='sandbox' for case in cases))
            manifest = asdict(SuiteManifest('fixture', 'zoo-static', {'source':'fixture'}, cases, {}))
            store = RunStore(work/'run', manifest)
            try:
                store.start(cases[0]['id'])
                store.finish(dict(case_id=cases[0]['id'], status='failed', reason='fixture batch failure'))
                first = store.start(cases[1]['id'])
                store.recover()
                self.assertNotEqual(store.start(cases[1]['id']), first)
                summary = render(store)
                self.assertEqual(summary['outcomes']['inspection_failure'], 4)
                self.assertEqual(summary['outcomes']['pending'], 1)
            finally:
                store.close()

    def test_staging_rejects_plain_archive(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root/'output'; output.mkdir()
            path = root/'harmless.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('fixture.txt', 'harmless')
            raw = path.read_bytes()
            entry = dict(path='malware/Binaries/fixture.zip', blob=zoo_inventory.blob_identity(raw), bytes=len(raw))
            with patch.object(zoo_inventory, 'repository', return_value=root), patch.object(
                zoo_inventory, 'git', side_effect=[str(len(raw)).encode(), raw]
            ):
                result = zoo_inventory.stage(root, dict(revision=zoo_inventory.REVISION, entries=[entry]), output)
            self.assertEqual(result['entries'][0]['stage_error'], 'ValueError')
            self.assertEqual(list(output.iterdir()), [])

    def test_unattested_or_incomplete_scan_cannot_count_as_miss(self):
        policy = dict(signature_free=True, hashes=False, yara=False, test_markers=False, amsi=False, reputation=False)
        scan = dict(signature_policy=policy, scanned=1, status='Complete')
        self.assertEqual(verdict(scan)[0], 'miss')
        self.assertEqual(verdict({**scan, 'status':'Complete with omissions'})[0], 'inspection_failure')
        self.assertEqual(verdict({**scan, 'advanced_review_total':1})[0], 'warning')
        self.assertEqual(verdict({**scan, 'detections':[{}]})[0], 'confirmed_detection')
        self.assertEqual(verdict({**scan, 'signature_policy':{'signature_free':True}})[0], 'inspection_failure')
        case = {'parameters':dict(revision=zoo_inventory.REVISION, entries=[{'blob':'a'*40}])}
        row = dict(member_index=0, outcome='miss', sha256='c'*64, signature_policy=policy, coverage_complete=True)
        receipt = dict(zoo_accounted=True, zoo_revision=zoo_inventory.REVISION, sample_execution=False,
                       zoo_groups=[dict(blob='a'*40, rows=[row])])
        validate_batch(case, receipt)
        row['coverage_complete'] = False
        with self.assertRaises(ValueError):
            validate_batch(case, receipt)

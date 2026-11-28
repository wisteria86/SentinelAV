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
from cryptography.exceptions import InvalidTag
import os


class ZooStaticTests(unittest.TestCase):
    def test_quick_profile_uses_one_cached_batch(self):
        from sentinelav.lab.static_corpus import SPECS

        (case,) = zoo_inventory.quick_cases()
        self.assertEqual(
            (case['backend'], case['action'], case['mode']), ('sandbox', 'zoo_static', 'normal')
        )
        self.assertEqual(
            [entry['blob'] for entry in case['parameters']['entries']],
            [spec['blob'] for spec in SPECS],
        )
        self.assertEqual(case['parameters']['group'], 'base')

    def test_checked_in_inventory_covers_pinned_archives_and_split_parts(self):
        batches = zoo_inventory.cases()
        rows = [row for case in batches for row in case['parameters']['entries']]
        self.assertEqual(len({row['path'] for row in rows}), 361)
        self.assertEqual(sum(not row.get('unsupported') for row in rows), 359)
        self.assertTrue(
            all(len(case['parameters']['entries']) <= zoo_inventory.BATCH_SIZE for case in batches)
        )

    def test_split_is_family_disjoint_and_keeps_seen_families_out_of_holdout(self):
        dev = {
            zoo_inventory.family_of(row['path'])
            for case in zoo_inventory.cases('dev')
            for row in case['parameters']['entries']
        }
        holdout = {
            zoo_inventory.family_of(row['path'])
            for case in zoo_inventory.cases('holdout')
            for row in case['parameters']['entries']
        }
        self.assertTrue(dev and holdout)
        self.assertFalse(dev & holdout)
        self.assertGreater(len(holdout), len(dev) * 0.8)
        self.assertFalse(zoo_inventory.seen_families() & holdout)
        self.assertEqual(zoo_inventory.family_of('malware/Binaries/Win32.Sample.A/x.zip'), 'sample')
        self.assertEqual(
            zoo_inventory.family_of('malware/Binaries/Sample_10Sep2013/x.zip'), 'sample'
        )
        self.assertEqual(
            zoo_inventory.family_of('malware/Source/Original/Sample_v1/x.zip'), 'sample'
        )
        self.assertTrue(
            any(
                '/Source/' in row['path']
                for case in zoo_inventory.cases('dev')
                for row in case['parameters']['entries']
            )
        )
        self.assertEqual(
            len(dev | holdout),
            len(
                {
                    zoo_inventory.family_of(row['path'])
                    for case in zoo_inventory.cases()
                    for row in case['parameters']['entries']
                }
            ),
        )

    def test_every_zoo_profile_is_a_valid_suite(self):
        for profile, split in (
            ('zoo-static', None),
            ('zoo-dev', 'dev'),
            ('zoo-holdout', 'holdout'),
        ):
            manifest = SuiteManifest(
                'fixture', profile, {'source': 'fixture'}, zoo_inventory.cases(split), {}
            )
            self.assertEqual(manifest.profile, profile)

    def test_pinned_tree_and_resume(self):
        with TemporaryDirectory() as temporary:
            work = Path(temporary)
            # Synthetic tree metadata uses no specimen objects.
            records = [
                dict(
                    mode='100644',
                    type='blob',
                    oid='a' * 40,
                    size=10,
                    path=f'malware/Binaries/demo/{i}.zip',
                )
                for i in range(5)
            ]
            records.append(
                dict(
                    mode='100644',
                    type='blob',
                    oid='b' * 40,
                    size=8,
                    path='malware/Binaries/demo/0.pass',
                )
            )
            with patch.object(zoo_inventory, 'tree_entries', return_value=records):
                cases = zoo_inventory.cases()
            self.assertEqual([len(case['parameters']['entries']) for case in cases], [5])
            self.assertEqual(cases[0]['parameters']['entries'][0]['password_blob'], 'b' * 40)
            self.assertTrue(
                all(case['mode'] == 'normal' and case['backend'] == 'sandbox' for case in cases)
            )
            manifest = asdict(
                SuiteManifest('fixture', 'zoo-static', {'source': 'fixture'}, cases, {})
            )
            store = RunStore(work / 'run', manifest)
            try:
                first = store.start(cases[0]['id'])
                store.recover()
                self.assertNotEqual(store.start(cases[0]['id']), first)
                summary = render(store)
                self.assertEqual(summary['outcomes']['pending'], 5)
                store.finish(
                    dict(case_id=cases[0]['id'], status='failed', reason='fixture batch failure')
                )
                summary = render(store)
                self.assertEqual(summary['outcomes']['inspection_failure'], 5)
                self.assertEqual(summary['arms']['full']['samples']['flagged'], 0)
                self.assertEqual(summary['arms']['full']['samples']['total'], 5)
            finally:
                store.close()

    def test_sealed_staging_hides_content_and_detects_tampering(self):
        key, blob = os.urandom(32), 'a' * 40
        data = b'PK\x03\x04 recognizable archive bytes'
        sealed = zoo_inventory.seal(data, key, blob)
        self.assertNotIn(b'recognizable', sealed)
        self.assertFalse(sealed.startswith(b'PK'))
        self.assertEqual(len(sealed), len(data) + 28)
        self.assertEqual(zoo_inventory.unseal(sealed, key, blob), data)
        with self.assertRaises(InvalidTag):
            zoo_inventory.unseal(sealed, key, 'b' * 40)
        with self.assertRaises(InvalidTag):
            zoo_inventory.unseal(sealed[:-1] + bytes([sealed[-1] ^ 1]), key, blob)

    def test_staging_rejects_plain_archive(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'output'
            output.mkdir()
            path = root / 'harmless.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('fixture.txt', 'harmless')
            raw = path.read_bytes()
            entry = dict(
                path='malware/Binaries/fixture.zip',
                blob=zoo_inventory.blob_identity(raw),
                bytes=len(raw),
            )
            with (
                patch.object(zoo_inventory, 'repository', return_value=root),
                patch.object(zoo_inventory, 'git', side_effect=[str(len(raw)).encode(), raw]),
            ):
                result = zoo_inventory.stage(
                    root, dict(revision=zoo_inventory.REVISION, entries=[entry]), output
                )
            self.assertEqual(result['entries'][0]['stage_error'], 'ValueError')
            self.assertEqual(list(output.iterdir()), [])

    def test_unattested_or_incomplete_scan_cannot_count_as_miss(self):
        def assessed(result, **fields):
            arms = {
                name: dict(score=0, verdict=result) for name in ('full', 'generalized', 'heuristic')
            }
            return dict(
                scanned=1,
                status='Complete',
                errors=[],
                assessment=dict(
                    dict(arms=arms, analyzed=True, inert=False, file_kind='pe'), **fields
                ),
            )

        self.assertEqual(verdict(assessed('Clean'))[0], 'miss')
        self.assertEqual(
            verdict({**assessed('Clean'), 'status': 'Complete with omissions'})[0],
            'inspection_failure',
        )
        self.assertEqual(verdict(assessed('Suspicious'))[0], 'suspicious')
        self.assertEqual(verdict(assessed('Malicious'))[0], 'malicious')
        self.assertEqual(verdict(assessed('Clean', inert=True))[0], 'not_applicable')
        self.assertEqual(verdict(assessed('Clean', analyzed=False))[0], 'unsupported')
        self.assertEqual(
            verdict(
                dict(scanned=0, errors=['x: Read blocked, likely by another security product'])
            )[0],
            'blocked_by_other_av',
        )
        self.assertEqual(verdict(dict(scanned=0, errors=[]))[0], 'inspection_failure')
        case = {'parameters': dict(revision=zoo_inventory.REVISION, entries=[{'blob': 'a' * 40}])}
        arms = {name: [0, 'Clean'] for name in ('full', 'generalized', 'heuristic')}
        row = dict(
            member_index=0, outcome='miss', sha256='c' * 64, arms=arms, coverage_complete=True
        )
        receipt = dict(
            zoo_accounted=True,
            zoo_revision=zoo_inventory.REVISION,
            sample_execution=False,
            zoo_groups=[dict(blob='a' * 40, rows=[row])],
        )
        validate_batch(case, receipt)
        row['coverage_complete'] = False
        with self.assertRaises(ValueError):
            validate_batch(case, receipt)

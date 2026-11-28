# Purpose: Verify test signature free aggregation behavior using controlled fixtures.
# Works with: lab.corpus_evaluation, tools.evaluation.aggregate_signature_free
# Used by: unittest discovery

import json
from pathlib import Path
import tempfile
import unittest
from sentinelav.lab.corpus_evaluation import load_manifest
from tools.evaluation.aggregate_signature_free import aggregate


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manifest = Path(self.temp.name) / 'manifest.json'
        self.entries = [
            dict(
                path=f'fixture-{i}.bin',
                sha256=str(i) * 64,
                label='test',
                provenance='Generated metadata only',
            )
            for i in (0, 1)
        ]
        self.manifest.write_text(json.dumps(dict(schema=1, files=self.entries)))
        _, self.digest = load_manifest(self.manifest)

    def report(self, rows):
        return dict(
            manifest_sha256=self.digest,
            signature_free=True,
            sample_execution=False,
            response_actions=False,
            rows=rows,
        )

    def row(self, index):
        return dict(**self.entries[index], outcome='unavailable', coverage_complete=False)

    def test_missing_and_unavailable_are_not_clean(self):
        result = aggregate(self.manifest, [self.report([self.row(0)])])
        self.assertFalse(result['complete'])
        self.assertEqual(result['groups']['test']['missing'], 1)
        self.assertEqual(result['groups']['test']['outcomes']['unavailable'], 1)

    def test_duplicate_measurements_cannot_inflate_results(self):
        with self.assertRaises(ValueError):
            aggregate(self.manifest, [self.report([self.row(0), self.row(0)])])

    def test_mixed_modes_and_frozen_manifests_are_rejected(self):
        report = self.report([self.row(0)])
        report['signature_free'] = False
        with self.assertRaises(ValueError):
            aggregate(self.manifest, [report])
        report['signature_free'] = True
        report['manifest_sha256'] = 'bad'
        with self.assertRaises(ValueError):
            aggregate(self.manifest, [report])

    def test_partial_findings_cannot_be_promoted(self):
        row = self.row(0)
        row['outcome'] = 'detected'
        with self.assertRaises(ValueError):
            aggregate(self.manifest, [self.report([row])])

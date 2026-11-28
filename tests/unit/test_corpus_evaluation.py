# Purpose: Verify test corpus evaluation behavior using controlled fixtures.
# Works with: lab.corpus_evaluation
# Used by: unittest discovery

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from sentinelav.lab.corpus_evaluation import evaluate, load_manifest, render


class FakeScanner:
    result = None

    def __init__(self, *args, **kwargs):
        self.signatures = SimpleNamespace(metadata={})
        self.rule_summary = {'status': 'Compiled'}

    def scan(self, *args):
        return self.result

    def close(self):
        pass


class CorpusEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / 'fixture.bin'
        self.file.write_bytes(b'Harmless corpus fixture')
        self.entry = dict(
            path='fixture.bin',
            sha256=hashlib.sha256(self.file.read_bytes()).hexdigest(),
            label='test',
            provenance='Generated harmless fixture',
        )
        self.manifest = self.root / 'manifest.json'

    def save(self):
        self.manifest.write_text(json.dumps(dict(schema=1, files=[self.entry])))

    def test_unsafe_paths_and_duplicates_refused(self):
        for name in ('../outside', '/absolute', 'C:/file', 'x:stream', 'a\\b', './file', 'file.'):
            self.entry['path'] = name
            self.save()
            with self.assertRaises(ValueError):
                load_manifest(self.manifest)
        self.entry['path'] = 'fixture.bin'
        self.manifest.write_text(json.dumps(dict(schema=1, files=[self.entry, self.entry])))
        with self.assertRaises(ValueError):
            load_manifest(self.manifest)

    def test_unknown_corpus_refused_before_file_hash_read_on_host(self):
        self.entry['label'] = 'unknown'
        self.save()
        with (
            patch('sentinelav.lab.corpus_evaluation.verified_offline_guest', return_value=False),
            patch('sentinelav.lab.corpus_evaluation.fingerprint') as fp,
        ):
            with self.assertRaises(ValueError):
                evaluate(self.manifest)
            fp.assert_not_called()

    def test_hash_mismatch_never_reaches_scanner(self):
        self.entry['sha256'] = '0' * 64
        self.save()
        with patch('sentinelav.lab.corpus_evaluation.IsolatedScanner') as scanner:
            report = evaluate(self.manifest, scanner_factory=scanner)
            scanner.assert_not_called()
        self.assertEqual(report['rows'][0]['outcome'], 'unavailable')

    def test_omissions_are_not_clean_and_html_escaped(self):
        self.save()

        class Scanner(FakeScanner):
            def __init__(self, *a, **k):
                self.signatures = type('Signatures', (), {'metadata': {}, '__len__': lambda s: 1})()
                self.rule_summary = {'status': 'Compiled'}

        Scanner.result = dict(
            status='Complete with omissions',
            scanned=1,
            skipped=0,
            errors=['timeout'],
            detections=[],
        )
        report = evaluate(self.manifest, scanner_factory=Scanner)
        self.assertEqual(report['rows'][0]['outcome'], 'unavailable')
        self.assertFalse(report['rows'][0]['coverage_complete'])
        Scanner.result = dict(
            status='Complete with omissions',
            scanned=1,
            skipped=0,
            errors=['parser failure'],
            detections=[dict(sha256=self.entry['sha256'])],
        )
        report = evaluate(self.manifest, scanner_factory=Scanner)
        self.assertEqual(report['rows'][0]['outcome'], 'detected_incomplete')
        report['rows'][0]['path'] = '<script>alert(1)</script>'
        self.assertNotIn('<script>', render(report))

    def test_real_worker_does_not_execute_or_modify_fixture(self):
        self.save()
        report = evaluate(self.manifest)
        self.assertEqual(report['rows'][0]['outcome'], 'not_detected')
        self.assertFalse(report['sample_execution'])
        self.assertEqual(self.file.read_bytes(), b'Harmless corpus fixture')

    def test_hash_ablation_removes_exact_match_without_trusting_file(self):
        self.save()
        normal = self.root / 'normal' / 'signatures.json'
        normal.parent.mkdir()
        normal.write_text(json.dumps({self.entry['sha256']: 'Harmless evaluation-only hash'}))
        empty = self.root / 'empty' / 'signatures.json'
        empty.parent.mkdir()
        empty.write_text('{}')
        baseline = evaluate(self.manifest, signature_path=normal)
        ablated = evaluate(self.manifest, signature_path=empty)
        self.assertEqual(baseline['rows'][0]['outcome'], 'detected')
        self.assertEqual(ablated['rows'][0]['outcome'], 'not_detected')
        self.assertEqual(ablated['rows'][0]['definitions']['count'], 0)
        self.assertEqual(ablated['rows'][0]['scan']['scanned'], 1)

    def test_hash_ablation_keeps_content_and_yara_inspection(self):
        import base64

        self.file = self.root / 'fixture.ps1'
        self.file.write_bytes(base64.b64encode(b'SENTINELAV_DEMO_THREAT_7C23A'))
        self.entry.update(
            path=self.file.name, sha256=hashlib.sha256(self.file.read_bytes()).hexdigest()
        )
        self.save()
        empty = self.root / 'empty' / 'signatures.json'
        empty.parent.mkdir()
        empty.write_text('{}')
        report = evaluate(
            self.manifest, signature_path=empty, options={'advanced': True, 'documents': False}
        )
        row = report['rows'][0]
        self.assertEqual(row['definitions']['count'], 0)
        self.assertEqual(row['outcome'], 'detected')
        self.assertTrue(
            any(d.get('detection_scope') == 'derived content' for d in row['scan']['detections'])
        )

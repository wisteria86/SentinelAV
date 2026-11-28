# Purpose: Verify test signature free behavior using controlled fixtures.
# Works with: detection.engine, detection.inspection, lab.corpus_evaluation, paths, platform.engine_policy
# Used by: unittest discovery

import base64
import hashlib
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from sentinelav.detection.engine import Scanner
from sentinelav.platform.engine_policy import inspection_options
from sentinelav.paths import RESOURCE_ROOT


class SignatureFreeTests(unittest.TestCase):
    def test_no_signature_sources_opened_and_allowlist_does_not_skip_inspection(self):
        marker = b'SENTINELAV_DEMO_THREAT_7C23A'
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'fixture.ps1'
            path.write_bytes(base64.b64encode(marker))
            with (
                patch(
                    'sentinelav.detection.engine.SignatureIndex',
                    side_effect=AssertionError('Hash database opened'),
                ),
                patch(
                    'sentinelav.detection.engine.compile_rules',
                    side_effect=AssertionError('YARA compiled'),
                ),
            ):
                scanner = Scanner(
                    'nonexistent',
                    'nonexistent',
                    trusted_hashes=[hashlib.sha256(path.read_bytes()).hexdigest()],
                    options=dict(signature_free=True),
                )
                result = scanner.scan([path], lambda: False, lambda *args: None)
            self.assertEqual(result['scanned'], 1)
            self.assertEqual(result['detections'], [])
            self.assertEqual(len(scanner.signatures), 0)
            self.assertEqual(result['yara']['status'], 'Disabled')
            self.assertTrue(result['signature_policy']['signature_free'])

    def test_signatures_stay_off_in_nested_and_decoded_content(self):
        marker = b'SENTINELAV_DEMO_THREAT_7C23A'
        archive = BytesIO()
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('marker.ps1', base64.b64encode(marker))
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'archive.zip'
            path.write_bytes(archive.getvalue())
            scanner = Scanner(
                RESOURCE_ROOT / 'signatures.json',
                RESOURCE_ROOT / 'rules',
                options=dict(signature_free=True),
            )
            self.assertEqual(
                scanner.scan([path], lambda: False, lambda *args: None)['detections'], []
            )
            eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            self.assertEqual(scanner.analyze_bytes(eicar), ([], [], []))

    def test_external_signature_channels_are_rejected(self):
        for key in ('amsi', 'reputation'):
            with self.assertRaises(ValueError):
                inspection_options(dict(signature_free=True, **{key: True}))

    def test_full_manifest_batch_selection_deduplicates(self):
        import json
        from sentinelav.lab.corpus_evaluation import evaluate

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            entries = []
            for index in range(65):
                path = root / f'{index}.txt'
                path.write_bytes(str(index).encode())
                entries.append(
                    dict(
                        path=path.name,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        label='test',
                        provenance='Generated',
                    )
                )
            (root / 'duplicate.txt').write_bytes(b'0')
            entries.append({**entries[0], 'path': 'duplicate.txt'})
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps(dict(schema=1, files=entries)))
            report = evaluate(manifest, options=dict(signature_free=True), batch_offset=64)
            self.assertEqual(report['duplicates_excluded'], 1)
            self.assertEqual(report['batch_sample_count'], 1)
            self.assertEqual(report['rows'][0]['path'], '64.txt')

    def test_worker_preserves_strict_policy(self):
        from sentinelav.detection.inspection import IsolatedScanner

        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'marker.txt'
            path.write_bytes(b'SENTINELAV_DEMO_THREAT_7C23A')
            scanner = IsolatedScanner(
                'nonexistent', 'nonexistent', options=dict(signature_free=True)
            )
            try:
                result = scanner.scan([path], lambda: False, lambda *args: None)
                self.assertTrue(result['signature_policy']['signature_free'])
                self.assertEqual(result['detections'], [])
                self.assertEqual(len(scanner.signatures), 0)
            finally:
                scanner.close()

    def test_evaluator_rejects_missing_worker_attestation(self):
        import json
        from sentinelav.lab.corpus_evaluation import evaluate

        class Index:
            metadata = {}

            def __len__(self):
                return 0

        class Fake:
            def __init__(self, *a, **k):
                self.signatures = Index()
                self.rule_summary = dict(status='Disabled')

            def scan(self, *a):
                return dict(status='Complete', scanned=1, detections=[], errors=[], skipped=0)

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / 'fixture.txt'
            path.write_bytes(b'ordinary')
            manifest = root / 'manifest.json'
            manifest.write_text(
                json.dumps(
                    dict(
                        schema=1,
                        files=[
                            dict(
                                path=path.name,
                                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                label='test',
                                provenance='Generated',
                            )
                        ],
                    )
                )
            )
            result = evaluate(manifest, scanner_factory=Fake, options=dict(signature_free=True))
            self.assertEqual(result['rows'][0]['outcome'], 'unavailable')
            self.assertIn('attest', result['rows'][0]['error'])

    def test_non_pe_scope_is_not_reported_as_clean(self):
        import json
        from sentinelav.lab.corpus_evaluation import evaluate

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / 'text.txt'
            path.write_bytes(b'ordinary')
            manifest = root / 'manifest.json'
            manifest.write_text(
                json.dumps(
                    dict(
                        schema=1,
                        files=[
                            dict(
                                path=path.name,
                                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                label='test',
                                provenance='Generated',
                            )
                        ],
                    )
                )
            )
            report = evaluate(manifest, options=dict(signature_free=True))
            self.assertEqual(report['rows'][0]['outcome'], 'unavailable')
            self.assertFalse(report['rows'][0]['coverage_complete'])

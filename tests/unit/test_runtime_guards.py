# Purpose: The test suite never authorizes a real runtime specimen or Windows mutation.
# Works with: lab.runtime_job, platform.engine_policy, response.auto_response
# Used by: unittest discovery

"""The test suite never authorizes a real runtime specimen or Windows mutation."""

import unittest
from unittest.mock import patch
from sentinelav.lab.runtime_job import run_job, AUTHORIZATION
from sentinelav.platform.engine_policy import inspection_options
from sentinelav.response.auto_response import eligibility


class RuntimeGuardTests(unittest.TestCase):
    def test_valid_job_is_rejected_on_host_before_reading_any_sample(self):
        job = dict(
            schema=1,
            authorization=AUTHORIZATION,
            sha256='a' * 64,
            seconds=1,
            sample='C:/not-opened.exe',
        )
        with (
            patch('sentinelav.lab.runtime_job.verified_offline_guest', return_value=False),
            patch('pathlib.Path.open') as opened,
        ):
            with self.assertRaises(ValueError):
                run_job(job)
            opened.assert_not_called()

    def test_generalized_detection_defaults_on_and_stays_opt_out(self):
        options = inspection_options({})
        self.assertTrue(options['advanced'])
        self.assertTrue(options['model'])
        self.assertTrue(options['neural_gray'])
        # Virtual execution and external feeds stay opt-in; a saved choice is always respected.
        self.assertFalse(options['emulation'])
        self.assertFalse(options['reputation'])
        self.assertFalse(options['neural'])
        self.assertFalse(inspection_options({'model': False})['model'])
        self.assertTrue(inspection_options({'model': True})['advanced'])
        with self.assertRaises(ValueError):
            inspection_options({'advanced': 'yes'})

    def test_a_missing_model_is_one_warning_and_does_not_mark_every_file_incomplete(self):
        import tempfile
        from pathlib import Path
        from sentinelav.detection.engine import Scanner
        from sentinelav.paths import RESOURCE_ROOT

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'signatures.json').write_text('{}')
            trust = root / 'trust.json'
            trust.write_text('{"schema":1,"keys":{}}')
            for name in ('a.txt', 'b.txt'):
                (root / name).write_text('ordinary notes')
            scanner = Scanner(
                root / 'signatures.json',
                RESOURCE_ROOT / 'rules',
                options=dict(analysis_trust=str(trust)),
            )
            try:
                report = scanner.scan(
                    [root / 'a.txt', root / 'b.txt'], lambda: False, lambda *a: None
                )
            finally:
                scanner.signatures.close()
            self.assertEqual(report['status'], 'Complete', report['errors'])
            self.assertEqual(report['errors'], [])
            self.assertEqual(sum('model unavailable' in item for item in report['warnings']), 1)

    def test_missing_default_model_is_visible_rather_than_a_silent_pass(self):
        import tempfile
        from pathlib import Path
        from sentinelav.detection.advanced_pipeline import AdvancedPipeline

        with tempfile.TemporaryDirectory() as folder:
            trust = Path(folder) / 'trust.json'
            trust.write_text('{"schema":1,"keys":{}}')
            pipeline = AdvancedPipeline(folder, dict(model=True, analysis_trust=str(trust)))
            self.assertNotIn('model', pipeline.assets)
            self.assertTrue(
                any('model unavailable' in item for item in pipeline.omissions), pipeline.omissions
            )

    def test_inner_hash_reason_cannot_authorize_outer_file_automatic_response(self):
        event = dict(
            sha256='a' * 64,
            path='C:/fixture.bin',
            automatic_response_eligible=False,
            reasons=['SHA-256: fixture'],
        )
        self.assertFalse(
            eligibility(event, dict(enabled=True, approved_hashes=['a' * 64], roots=['C:/']))[0]
        )

# Purpose: The test suite never authorizes a real runtime specimen or Windows mutation.
# Works with: lab.runtime_job, platform.engine_policy, response.auto_response
# Used by: unittest discovery

"""The test suite never authorizes a real runtime specimen or Windows mutation."""
import unittest
from unittest.mock import patch
from sentinelav.lab.runtime_job import run_job,AUTHORIZATION
from sentinelav.platform.engine_policy import inspection_options
from sentinelav.response.auto_response import eligibility


class RuntimeGuardTests(unittest.TestCase):
    def test_valid_job_is_rejected_on_host_before_reading_any_sample(self):
        job=dict(schema=1,authorization=AUTHORIZATION,sha256='a'*64,seconds=1,sample='C:/not-opened.exe')
        with patch('sentinelav.lab.runtime_job.verified_offline_guest',return_value=False),patch('pathlib.Path.open') as opened:
            with self.assertRaises(ValueError): run_job(job)
            opened.assert_not_called()

    def test_layer_selection_does_not_implicitly_enable_missing_model(self):
        options=inspection_options({'advanced':True})
        self.assertFalse(options['model']); self.assertFalse(options['reputation'])
        self.assertTrue(inspection_options({'model':True})['advanced'])
        with self.assertRaises(ValueError): inspection_options({'advanced':'yes'})

    def test_inner_hash_reason_cannot_authorize_outer_file_automatic_response(self):
        event=dict(sha256='a'*64,path='C:/fixture.bin',automatic_response_eligible=False,
                   reasons=['SHA-256: fixture'])
        self.assertFalse(eligibility(event,dict(enabled=True,approved_hashes=['a'*64],roots=['C:/']))[0])

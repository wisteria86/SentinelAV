# Purpose: Verify test speakeasy backend behavior using controlled fixtures.
# Works with: detection.file_formats, detection.speakeasy_backend, lab.advanced_check
# Used by: unittest discovery

import importlib.util
import unittest
from sentinelav.lab.advanced_check import exit_fixture
from sentinelav.detection.file_formats import pe_metadata
from sentinelav.detection.speakeasy_backend import emulate


@unittest.skipUnless(importlib.util.find_spec('speakeasy'),'Analysis dependencies not installed')
class SpeakeasyBackendTests(unittest.TestCase):
    def test_actual_modeled_exit_is_reached(self):
        data=exit_fixture();result=emulate(data,pe_metadata(data),lambda x:([],[],[]))
        self.assertEqual(result['api_calls'],1,result)
        self.assertTrue(any(e['api']=='ExitProcess' for e in result['api_events']))
        self.assertFalse(result['findings'])
        self.assertFalse(result['diagnostics'],result)

    def test_declaration_only_fallback_is_not_success(self):
        data=bytearray(exit_fixture())
        data[898:910]=b'Beep\0'+bytes(7)
        result=emulate(data,pe_metadata(data),lambda x:([],[],[]))
        # Beep has metadata but no semantic handler in the pinned backend.
        self.assertEqual(result['termination_reason'],'unsupported_api',result)
        self.assertEqual(result['api_calls'],0,result)
        self.assertFalse(result['findings'])

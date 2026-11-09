# Purpose: Verify test emulation evaluation behavior using controlled fixtures.
# Works with: lab.emulation_evaluation
# Used by: unittest discovery

import unittest
from sentinelav.lab.emulation_evaluation import metrics


class EmulationEvaluationTests(unittest.TestCase):
    def test_unsupported_path_is_not_a_success_or_signature_finding(self):
        row=dict(scan=dict(advanced_analysis=dict(coverage=dict(emulation=dict(status='Partial',
            instructions_observed=12,api_calls=1,changed_pages=0)),
            omissions=['API model stopped: kernel32.dll!CreateThread','Win32 subset: limited environment'],evidence=[])))
        result=metrics(row)
        self.assertTrue(result['omission_categories']['api_model_stopped'])
        self.assertFalse(result['emulation_signature_finding'])
        self.assertEqual(result['status'],'Partial')

    def test_non_pe_and_missing_analysis_are_distinct(self):
        self.assertEqual(metrics(dict(scan=dict(file_format=dict(format='ELF'))))['status'],'Not applicable')
        self.assertEqual(metrics(dict(outcome='unavailable'))['status'],'Not run')

    def test_transport_is_bounded_and_requires_confirmed_emulation_evidence(self):
        row=dict(scan=dict(advanced_analysis=dict(coverage=dict(emulation=dict(status='Partial',
            instructions_observed=99999999,api_calls=-20,changed_pages=9999)),
            evidence=[dict(source='static',confirmed=True),dict(source='emulation',confirmed=False)])))
        result=metrics(row)
        self.assertEqual((result['instructions'],result['api_calls'],result['changed_pages']),(200000,0,256))
        self.assertFalse(result['emulation_signature_finding'])
        row['scan']['advanced_analysis']['evidence'].append(dict(source='emulation',confirmed=True))
        self.assertTrue(metrics(row)['emulation_signature_finding'])

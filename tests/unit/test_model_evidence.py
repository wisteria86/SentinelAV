# Purpose: Keep learned-model evidence in its measured bands and below automatic action on its own.
# Works with: detection.file_analysis, detection.threat_score
# Used by: test.ps1

"""Keep learned-model evidence in its measured bands and below automatic action on its own."""
import unittest

from sentinelav.detection.threat_score import automatic_eligible,indicator,score


class ModelEvidenceTests(unittest.TestCase):
    def bands(self,value,review=False):
        from sentinelav.detection.file_analysis import _model_items
        return [(i['code'],i['weight']) for i in _model_items(dict(coverage=dict(model=dict(model_score=value,review=review))))]

    def test_score_bands(self):
        self.assertEqual(self.bands(.5),[])
        self.assertEqual(self.bands(.7),[('learned_pe_model_notable',20)])
        self.assertEqual(self.bands(.9),[('learned_pe_model_elevated',35)])
        self.assertEqual(self.bands(.99,True),[('learned_pe_model',45)])
        self.assertEqual(self.bands(.9995,True),[('learned_pe_model',55)])

    def test_a_model_alone_never_reaches_malicious_or_automatic_action(self):
        result=score([indicator('learned_pe_model','ml',55,'Model','ml'),indicator('learned_byte_model','ml',30,'Model','ml')])
        self.assertEqual(result['verdict'],'Suspicious')
        self.assertFalse(automatic_eligible(result))

    def test_packing_alone_stays_clean_but_supports_other_evidence(self):
        packed=[indicator(code,'packing',20,'Fixture') for code in ('a','b','c','d')]
        self.assertEqual(score(packed)['verdict'],'Clean')
        self.assertEqual(score(packed+[indicator('capability','injection',32,'Fixture')])['verdict'],'Suspicious')

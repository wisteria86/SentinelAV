# Purpose: Keep learned-model evidence in its measured bands and below automatic action on its own.
# Works with: detection.core.file_analysis, detection.helpers.threat_score
# Used by: test.ps1

"""Keep learned-model evidence in its measured bands and below automatic action on its own."""

import unittest

from sentinelav.detection.helpers.threat_score import automatic_eligible, indicator, score


class ModelEvidenceTests(unittest.TestCase):
    def bands(self, value, review=False):
        from sentinelav.detection.core.file_analysis import _model_items

        return [
            (i['code'], i['weight'])
            for i in _model_items(dict(coverage=dict(model=dict(model_score=value, review=review))))
        ]

    def test_score_bands(self):
        self.assertEqual(self.bands(0.5), [])
        self.assertEqual(self.bands(0.7), [('learned_pe_model_notable', 25)])
        self.assertEqual(self.bands(0.9), [('learned_pe_model_elevated', 40)])
        self.assertEqual(self.bands(0.99, True), [('learned_pe_model', 70)])
        self.assertEqual(self.bands(0.9995, True), [('learned_pe_model', 70)])

    def test_a_model_alone_can_convict_but_never_acts_automatically(self):
        result = score(
            [
                indicator('learned_pe_model', 'ml', 70, 'Model', 'ml'),
                indicator('learned_byte_model', 'ml', 30, 'Model', 'ml'),
            ]
        )
        self.assertEqual((result['verdict'], result['score']), ('Malicious', 70))
        self.assertFalse(automatic_eligible(result))
        # An elevated score plus packing traits stays Suspicious: packing only supports independent evidence.
        packed = [
            indicator('learned_pe_model_elevated', 'ml', 40, 'Model', 'ml'),
            indicator('wx', 'packing', 28, 'Fixture'),
        ]
        self.assertEqual(score(packed)['verdict'], 'Suspicious')

    def test_packing_alone_stays_clean_but_supports_other_evidence(self):
        packed = [indicator(code, 'packing', 20, 'Fixture') for code in ('a', 'b', 'c', 'd')]
        self.assertEqual(score(packed)['verdict'], 'Clean')
        self.assertEqual(
            score(packed + [indicator('capability', 'injection', 32, 'Fixture')])['verdict'],
            'Suspicious',
        )

    def test_a_signed_script_gets_the_same_trust_as_a_signed_program(self):
        from sentinelav.detection.core.file_analysis import SIGNABLE_KINDS

        self.assertLessEqual(
            {'pe', 'vbscript', 'powershell', 'javascript', 'batch', 'ole'}, SIGNABLE_KINDS
        )
        items = [
            indicator('rewrites', 'replication', 30, 'Fixture'),
            indicator('shell', 'obfuscation', 22, 'Fixture'),
        ]
        self.assertEqual(score(items)['verdict'], 'Suspicious')
        self.assertEqual(score(items, trusted=True)['verdict'], 'Clean')

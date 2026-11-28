# Purpose: Verify that a primary-model conviction needs the confirmation model's agreement.
# Works with: detection.pe_ensemble, detection.file_analysis

"""Verify that a primary-model conviction needs the confirmation model's agreement."""

import unittest
from unittest import mock

from sentinelav.detection import pe_ensemble
from sentinelav.detection.file_analysis import _model_items


def scored(score):
    return dict(
        model_score=score,
        review=score >= 0.98,
        classification='Likely malicious' if score >= 0.98 else 'Below review threshold',
    )


class ConfirmationTests(unittest.TestCase):
    def run_predict(self, primary, second, confirm=True):
        scores = iter((scored(primary), scored(second)))
        with (
            mock.patch.object(pe_ensemble, 'validate'),
            mock.patch.object(pe_ensemble, 'features', return_value=[0]),
            mock.patch.object(pe_ensemble, 'predict_vector', side_effect=lambda *a: next(scores)),
            mock.patch('pefile.PE') as pe,
        ):
            pe.return_value.OPTIONAL_HEADER.Magic = 0x20B
            pe.return_value.OPTIONAL_HEADER.DATA_DIRECTORY = []
            return pe_ensemble.predict({}, b'MZ', dict(confirm_threshold=0.64) if confirm else None)

    def test_unconfirmed_conviction_becomes_review(self):
        output = self.run_predict(0.99, 0.30)
        self.assertFalse(output['confirmed'])
        items = _model_items(dict(coverage=dict(model=dict(output, file_type='Win64'))))
        self.assertEqual([i['code'] for i in items], ['learned_pe_model_elevated'])

    def test_confirmed_conviction_stands(self):
        output = self.run_predict(0.99, 0.70)
        self.assertTrue(output['confirmed'])
        items = _model_items(dict(coverage=dict(model=dict(output, file_type='Win64'))))
        self.assertEqual([i['code'] for i in items], ['learned_pe_model'])

    def test_low_scores_skip_the_second_model(self):
        output = self.run_predict(0.5, 0.99)
        self.assertNotIn('confirmed', output)


if __name__ == '__main__':
    unittest.main()

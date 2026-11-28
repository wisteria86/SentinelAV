# Purpose: Verify test anomaly model behavior using controlled fixtures.
# Works with: detection.anomaly_model, tools.evaluation.calibrate_static
# Used by: tests.unit.test_analysis_artifacts

import copy
import unittest
from sentinelav.detection.anomaly_model import FEATURES, fit_evaluate, score
from tools.evaluation.calibrate_static import collect


def row(index, split, value, label='benign'):
    return dict(
        sha256=f'{index:064x}',
        group=f'build-{index}',
        split=split,
        label=label,
        provenance='Synthetic numeric fixture; not efficacy evidence',
        format='PE',
        method='structural-analysis-v1',
        features={k: float(value) for k in FEATURES},
    )


def dataset():
    return [
        row(1, 'train', 0),
        row(2, 'train', 2),
        row(3, 'calibration', 1),
        row(4, 'calibration', 2),
        row(5, 'test', 1),
        row(6, 'test', 10, 'malware'),
    ]


class AnomalyModelTests(unittest.TestCase):
    def test_training_and_threshold_are_independent_of_test_values(self):
        rows = dataset()
        model, report = fit_evaluate(rows)
        rows[-1]['features'] = {k: 1000.0 for k in FEATURES}
        other, _ = fit_evaluate(rows)
        self.assertEqual(model, other)
        self.assertEqual(report['metrics']['benign']['flagged_for_review'], 0)
        self.assertEqual(report['metrics']['malware']['flagged_for_review'], 1)
        self.assertIsNone(report['predictions'][-1]['malware_probability'])
        self.assertFalse(report['predictions'][-1]['automatic_response_eligible'])

    def test_related_groups_and_duplicate_hashes_rejected(self):
        for field in ('group', 'sha256'):
            rows = dataset()
            rows[-1][field] = rows[0][field]
            with self.assertRaises(ValueError):
                fit_evaluate(rows)

    def test_nonfinite_and_missing_features_rejected(self):
        rows = dataset()
        rows[0]['features'][FEATURES[0]] = float('nan')
        with self.assertRaises(ValueError):
            fit_evaluate(rows)
        rows = dataset()
        del rows[0]['features'][FEATURES[0]]
        with self.assertRaises(ValueError):
            fit_evaluate(rows)

    def test_constant_training_dimensions_report_novelty_without_fake_scale(self):
        rows = dataset()
        rows[1]['features'] = dict(rows[0]['features'])
        model, _ = fit_evaluate(rows)
        result = score(model, rows[-1]['features'])
        self.assertEqual(result['distance'], 0)
        self.assertEqual(set(result['constant_feature_novelty']), set(FEATURES))

    def test_collection_retains_omissions_and_uses_reviewed_labels(self):
        annotation = row(1, 'train', 0)
        scan = dict(
            status='Complete',
            errors=[],
            skipped=0,
            file_identity={'sha256': annotation['sha256']},
            file_format={'format': 'PE'},
            static_analysis=dict(method=annotation['method'], features=annotation['features']),
        )
        entry = dict(
            sha256=annotation['sha256'],
            scan=scan,
            postcheck_unchanged=True,
            coverage_complete=True,
            label='malware',
        )
        result = collect(
            {'rows': [entry]}, dict(schema=1, samples={annotation['sha256']: annotation})
        )
        self.assertEqual(result['rows'][0]['label'], 'benign')
        entry['postcheck_unchanged'] = False
        result = collect(
            {'rows': [entry]}, dict(schema=1, samples={annotation['sha256']: annotation})
        )
        self.assertFalse(result['rows'])
        self.assertEqual(len(result['omissions']), 1)

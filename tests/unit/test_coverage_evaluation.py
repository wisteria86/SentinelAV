# Purpose: Verify test coverage evaluation behavior using controlled fixtures.
# Works with: tools.evaluation.evaluate_coverage
# Used by: unittest discovery

import unittest
from tools.evaluation.evaluate_coverage import fixture_cases,summarize,render


class CoverageEvaluationTests(unittest.TestCase):
    def test_fixtures_are_reproducible_and_have_explicit_expectations(self):
        first=fixture_cases()
        self.assertEqual(first,fixture_cases())
        self.assertEqual(len({c['path'] for c in first}),len(first))
        self.assertTrue(all('expected_detection' in c for c in first))

    def test_partial_detections_and_inconclusive_results_do_not_become_clean(self):
        rows=[dict(expected_detection=True,outcome='detected_incomplete',coverage_complete=False),
              dict(expected_detection=True,outcome='not_detected',coverage_complete=True),
              dict(expected_detection=True,outcome='unavailable',coverage_complete=False),
              dict(expected_detection=False,outcome='unavailable',coverage_complete=False),
              dict(expected_detection=False,outcome='detected',coverage_complete=True),
              dict(expected_detection=None,outcome='unavailable',coverage_complete=False)]
        metrics=summarize(rows)
        self.assertEqual(metrics['observed_positive'],1)
        self.assertEqual(metrics['observed_positive_with_gaps'],1)
        self.assertEqual(metrics['complete_misses'],1)
        self.assertEqual(metrics['inconclusive_positive'],1)
        self.assertEqual(metrics['unexpected_fixture_alerts'],1)
        self.assertEqual(metrics['negative_without_alert'],0)
        self.assertEqual(metrics['inconclusive_negative'],1)
        self.assertEqual(metrics['gaps_reported'],1)

    def test_report_escapes_untrusted_names(self):
        report=dict(profiles={'<script>':dict(metrics={},rows=[dict(path='<img>')])})
        output=render(report)
        self.assertNotIn('<script>',output)
        self.assertNotIn('<img>',output)

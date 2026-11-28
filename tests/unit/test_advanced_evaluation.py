# Purpose: Verify test advanced evaluation behavior using controlled fixtures.
# Works with: detection.helpers.active_content, tools.evaluation.evaluate_behavior, tools.evaluation.evaluate_benign
# Used by: unittest discovery

from pathlib import Path
import tempfile
import unittest
from sentinelav.detection.helpers.active_content import active_sources
from tools.evaluation.evaluate_behavior import controls
from tools.evaluation.evaluate_benign import evaluate


class AdvancedEvaluationTests(unittest.TestCase):
    def test_large_non_document_is_not_reported_as_uninspected_document(self):
        payload = b'MZ' + bytes(8 * 1024 * 1024)
        self.assertEqual(active_sources(payload, '.dll'), ([], []))
        # The limit must still apply to content selected by extension or magic.
        self.assertIn('size cap', active_sources(payload, '.html')[1][0])
        self.assertIn('size cap', active_sources(b'<html>' + payload, '.bin')[1][0])

    def test_behavior_controls_preserve_warning_to_alert_transition(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows = controls(Path(temporary))
        self.assertTrue(all(row['passed'] for row in rows), rows)
        row = next(row for row in rows if row['name'].startswith('Office child'))
        self.assertEqual(row['observed_levels'], ['Warning', 'Alert'])

    def test_benign_report_records_selected_analysis_options(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'ordinary.txt'
            path.write_text('Ordinary harmless document')
            report = evaluate([path], repeats=1, options={'advanced': True, 'documents': True})
        self.assertTrue(report['inspection_options']['advanced'])
        self.assertFalse(report['inspection_options']['emulation'])
        self.assertFalse(report['inspection_options']['amsi'])
        self.assertEqual(report['runs'][0]['scan']['detections'], [])

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from tools.evaluation.evaluate_benign import evaluate,render,select_files


class BenignEvaluationTests(unittest.TestCase):
    def test_repeatable_inventory_and_findings_are_not_confirmed_false_positives(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            target=root/'fixture.txt'
            target.write_text('Ordinary harmless fixture')
            signatures=root/'signatures.json'
            signatures.write_text(json.dumps({hashlib.sha256(target.read_bytes()).hexdigest():'Fixture detection'}))
            report=evaluate([target],signature_path=signatures,rules=root/'rules')
            self.assertEqual(report['status'],'Complete')
            self.assertEqual(len(report['runs']),2)
            self.assertEqual(len(report['findings_requiring_review']),1)
            self.assertIsNone(report['confirmed_false_positives'])
            self.assertFalse(report['files_executed'])
            self.assertEqual(target.read_text(),'Ordinary harmless fixture')
            self.assertEqual(report['postchecked_files'],1)
            report['findings_requiring_review'][0]['path']='<script>alert(1)</script>'
            self.assertNotIn('<script>',render(report))

    def test_bounded_top_level_selection_and_size_omissions(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'a.txt').write_text('a')
            (root/'b.txt').write_text('too big')
            (root/'sub').mkdir()
            (root/'sub'/'nested.txt').write_text('ignored')
            paths,omissions=select_files([root],10,2)
            self.assertEqual([p.name for p in paths],['a.txt'])
            self.assertEqual(len(omissions),1)

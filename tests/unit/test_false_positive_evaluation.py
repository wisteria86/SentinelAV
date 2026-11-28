# Purpose: Keep the false-positive split honest and its reported bound correct.
# Works with: tools.evaluation.evaluate_false_positives
# Used by: test.ps1

"""Keep the false-positive split honest and its reported bound correct."""

from pathlib import Path
import tempfile
import unittest

from tools.evaluation import evaluate_false_positives as tool


class FalsePositiveEvaluationTests(unittest.TestCase):
    def test_a_product_never_appears_in_both_halves(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for product in ('alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'):
                (root / product / 'bin').mkdir(parents=True)
                for name in ('a.exe', 'b.dll', 'notes.txt'):
                    (root / product / 'bin' / name).write_bytes(b'x')
            first, _ = tool.select([root], 'calibrate', 10)
            second, _ = tool.select([root], 'report', 10)
            self.assertEqual(len(first) + len(second), 12)
            self.assertFalse({key[1] for key, _ in first} & {key[1] for key, _ in second})
            self.assertTrue(all(path.suffix != '.txt' for _, path in first + second))

    def test_selection_is_repeatable_and_each_product_is_capped(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for product in ('alpha', 'beta', 'gamma', 'delta'):
                (root / product).mkdir()
                for index in range(9):
                    (root / product / f'{index}.dll').write_bytes(b'x')
            for split in ('calibrate', 'report'):
                once, _ = tool.select([root], split, 3)
                self.assertEqual(once, tool.select([root], split, 3)[0])
                counts = {}
                for key, _ in once:
                    counts[key] = counts.get(key, 0) + 1
                self.assertTrue(all(count == 3 for count in counts.values()))

    def test_each_product_is_sampled_per_file_type(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for product in ('alpha', 'beta', 'gamma', 'delta'):
                (root / product).mkdir()
                for index in range(9):
                    (root / product / f'{index}.dll').write_bytes(b'x')
                (root / product / 'manual.pdf').write_bytes(b'x')
            chosen = tool.select([root], 'calibrate', 2)[0] + tool.select([root], 'report', 2)[0]
            self.assertEqual(sum(path.suffix == '.pdf' for _, path in chosen), 4)
            self.assertEqual(sum(path.suffix == '.dll' for _, path in chosen), 8)

    def test_personal_folders_are_refused(self):
        for path in (
            r'C:\Users\someone\Documents',
            r'C:\Users\someone\Desktop\tools',
            r'C:\Users\someone\AppData\Local\Programs',
        ):
            with self.assertRaises(ValueError):
                tool.refuse_private(path)
        self.assertEqual(tool.refuse_private(r'C:\Program Files'), Path(r'C:\Program Files'))

    def test_upper_bound_matches_known_exact_values(self):
        # With zero failures the exact bound is 1-0.05**(1/n), the source of the "rule of three".
        self.assertAlmostEqual(tool.upper_bound(0, 1000), 1 - 0.05 ** (1 / 1000), places=6)
        self.assertAlmostEqual(tool.upper_bound(0, 10), 0.2589, places=3)
        self.assertAlmostEqual(tool.upper_bound(1, 100), 0.0466, places=3)
        self.assertEqual(tool.upper_bound(5, 5), 1.0)
        self.assertEqual(tool.upper_bound(0, 0), 1.0)

    def test_summary_keeps_signed_and_unsigned_apart(self):
        def row(verdict, signed, kind='pe', product='a'):
            return dict(
                verdict=verdict,
                signed=signed,
                kind=kind,
                product=product,
                automatic=False,
                codes=['x'],
            )

        rows = [
            row('Clean', True),
            row('Suspicious', False),
            row('Clean', False),
            row('Malicious', True),
            row('Clean', None, 'python', 'b'),
        ]
        summary = tool.summarize(rows, {}, [0.1, 0.2], 2, 'report')
        self.assertEqual(summary['files'], 5)
        self.assertEqual(summary['any_flag']['flagged'], 2)
        self.assertEqual(summary['malicious']['flagged'], 1)
        self.assertEqual(summary['unsigned_executables_any_flag']['flagged'], 1)
        self.assertEqual(summary['signed_executables_any_flag']['files'], 2)
        self.assertEqual(summary['flagged_by_product'], [('a', 2)])

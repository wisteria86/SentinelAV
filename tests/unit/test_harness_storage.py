# Purpose: Verify test harness storage behavior using controlled fixtures.
# Works with: lab.qualification.backends, lab.qualification.catalog, lab.qualification.comparison,
#   lab.qualification.contracts, lab.qualification.guest
# Used by: unittest discovery

from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

from sentinelav.lab.qualification.contracts import (
    CaseDefinition,
    Observation,
    CaseResult,
    SuiteManifest,
    digest,
    validate_samples,
)
from sentinelav.lab.qualification.scoring import score_case, qualify, detection_metrics, upper_bound
from sentinelav.lab.qualification.store import RunStore, exclusive
from sentinelav.lab.qualification.reporting import render, redact, escape
from sentinelav.lab.qualification.backends import read_export, reconcile, Sandbox, HyperV
from sentinelav.lab.qualification.catalog import suite
from tests.unit.harness_fixtures import HarnessFixture


class HarnessStorageTests(HarnessFixture, unittest.TestCase):
    def test_live_queue_not_reused_without_explicit_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            store = RunStore(Path(d), self.manifest)
            store.start('fixture')
            with self.assertRaises(ValueError):
                store.start('fixture')
            store.close()

    def test_reports_escape_guest_text_and_preserve_blocked_gates(self):
        with tempfile.TemporaryDirectory() as d:
            store = RunStore(Path(d), self.manifest)
            store.start('fixture')
            r = self.result()
            r['reason'] = '<script>|`attack`'
            store.finish(r)
            (Path(d) / 'owned-evidence.json').write_text('{}')
            summary = render(store)
            text = (Path(d) / 'report.md').read_text()
            self.assertNotIn('<script>', text)
            self.assertIn('&#124;', text)
            self.assertEqual(summary['status'], 'blocked')
            store.close()

    def test_redaction_and_formula_escaping(self):
        r = redact(dict(password='secret', message='token=abc --password xyz'))
        self.assertNotIn('secret', json.dumps(r))
        self.assertNotIn('abc', r['message'])
        self.assertNotIn('xyz', r['message'])
        from sentinelav.lab.qualification.reporting import _csv

        self.assertTrue(_csv('=HYPERLINK("bad")').startswith("'"))

    def test_compression_and_trailing_data_rejected(self):
        self.assertEqual(read_export(zlib.compress(b'{"schema":1}')), dict(schema=1))
        for data in (
            zlib.compress(b'A' * 100000),
            zlib.compress(b'{}') + b'extra',
            zlib.compress(b'[]'),
            b'corrupt',
        ):
            with self.assertRaises((ValueError, zlib.error)):
                read_export(data, 100)

    def test_guest_entry_refuses_host_before_specimens(self):
        from sentinelav.lab.qualification.guest import execute

        with (
            patch('sentinelav.lab.qualification.guest.guard', return_value=False),
            patch('pathlib.Path.read_bytes') as read,
        ):
            with self.assertRaises(ValueError):
                execute(dict(backend='sandbox'))
            read.assert_not_called()

    def test_unregistered_hyperv_is_blocked(self):
        from sentinelav.lab.qualification.backends import Blocked

        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Blocked):
                HyperV(Path(d), Path(d), Path(d), lambda: False, lambda _: None)

    def test_catalog_contains_required_vm_and_safety_cases(self):
        manifest = suite('fixture', 'critical', self.versions)
        tracks = {c['track'] for c in manifest['cases']}
        self.assertTrue(
            {'recurrence', 'soak', 'prevention', 'automatic_safety', 'performance', 'deployment'}
            <= tracks
        )
        self.assertEqual(len([c for c in manifest['cases'] if c['action'] == 'live']), 14)

    def test_unrelated_guest_never_stopped(self):
        with tempfile.TemporaryDirectory() as d:
            backend = Sandbox(d, d, d, lambda: False, lambda _: None)
            backend.owner = dict(guest_id='owned', backend='sandbox')
            reply = '{"WindowsSandboxEnvironments":[{"Id":"unrelated"}]}'
            with patch(
                'sentinelav.lab.qualification.backend_sandbox.run', return_value=reply
            ) as command:
                backend.dispose()
                self.assertFalse(any('stop' in call.args[0] for call in command.call_args_list))

    def test_impossible_counts_rejected(self):
        c = asdict(CaseDefinition('fixture', 'classification', 'host', 'feature_qualification'))
        manifest = {**self.manifest, 'cases': [c]}
        o = self.observation(
            format='Dot_Net',
            untouched_holdout=True,
            temporal_separation=True,
            benign=10000,
            malware=1,
            true_positives=2,
            false_positives=0,
        )
        r = asdict(score_case(c, o, self.versions))
        with self.assertRaises(ValueError):
            qualify(manifest, [r])

    def test_missing_or_escaping_host_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            store = RunStore(Path(d), self.manifest)
            store.start('fixture')
            store.finish(self.result())
            with self.assertRaises(ValueError):
                render(store)
            store.close()

    def test_small_qualification_cohort_cannot_pass(self):
        c = asdict(CaseDefinition('fixture', 'classification', 'host', 'feature_qualification'))
        o = self.observation(
            format='Dot_Net',
            untouched_holdout=True,
            temporal_separation=True,
            benign=3000,
            malware=1,
            true_positives=1,
            false_positives=0,
        )
        result = asdict(score_case(c, o, self.versions))
        summary = qualify({**self.manifest, 'cases': [c]}, [result])
        self.assertEqual(summary['gates']['temporal_Dot_Net']['status'], 'blocked')

    def test_soak_profile_defaults_to_24_hours(self):
        cases = suite('fixture', 'soak', self.versions)['cases']
        self.assertEqual(next(c for c in cases if c['action'] == 'soak')['seconds'], 86400)

    def test_paired_comparison_direction(self):
        from sentinelav.lab.qualification.comparison import paired

        result = paired(['a', 'b'], ['b', 'c'], 10)
        self.assertEqual(result['recovered'], 1)
        self.assertEqual(result['new_misses'], 1)
        self.assertEqual(result['paired_recall_change'], 0)

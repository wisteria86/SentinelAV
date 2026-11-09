# Purpose: Verify test critical harness behavior using controlled fixtures.
# Works with: lab.qualification.backends, lab.qualification.catalog, lab.qualification.contracts,
#   lab.qualification.reporting, lab.qualification.scoring
# Used by: unittest discovery

from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zlib

from sentinelav.lab.qualification.contracts import CaseDefinition,Observation,CaseResult,SuiteManifest,digest,validate_samples
from sentinelav.lab.qualification.scoring import score_case,qualify,detection_metrics,upper_bound
from sentinelav.lab.qualification.store import RunStore,exclusive
from sentinelav.lab.qualification.reporting import render,redact,escape
from sentinelav.lab.qualification.backends import read_export,reconcile,Sandbox,HyperV
from sentinelav.lab.qualification.catalog import suite
from tests.unit.harness_fixtures import HarnessFixture

class CriticalHarnessTests(HarnessFixture,unittest.TestCase):
    def test_known_success_and_false_actions(self):
        self.assertEqual(self.result()['status'],'passed')
        for name in ('false_actions','protected_controls_changed'):
            self.assertEqual(self.result(**{name:1})['status'],'failed')

    def test_missing_expected_field_is_inconclusive(self):
        o=self.observation();o['measurements']={}
        self.assertEqual(score_case(self.case,o,self.versions).status,'inconclusive')

    def test_lost_or_truncated_observations_cannot_pass(self):
        for updates in (dict(losses=1),dict(complete=False),dict(evidence=[])):
            o=self.observation();o.update(updates)
            self.assertEqual(score_case(self.case,o,self.versions).status,'inconclusive')
        self.assertEqual(self.result(truncated=True)['status'],'inconclusive')

    def test_wrong_case_or_build_rejected(self):
        for field,value in (('case_id','another'),('versions_digest','0'*64)):
            o=self.observation();o[field]=value
            with self.assertRaises(ValueError):score_case(self.case,o,self.versions)

    def test_no_pass_without_observation(self):
        with self.assertRaises(ValueError):qualify(self.manifest,[asdict(CaseResult('fixture','passed','forged'))])

    def test_duplicate_and_unknown_case_results_rejected(self):
        with self.assertRaises(ValueError):qualify(self.manifest,[self.result(),self.result()])
        r=self.result();r['case_id']='unknown'
        with self.assertRaises(ValueError):qualify(self.manifest,[r])

    def test_missing_qualification_tracks_block(self):
        summary=qualify(self.manifest,[self.result()])
        self.assertEqual(summary['status'],'blocked')
        self.assertEqual(summary['gates']['automatic_actions']['status'],'blocked')

    def test_lost_temporal_evidence_cannot_qualify(self):
        case = {**self.case, 'track': 'classification'}
        manifest = {**self.manifest, 'cases': [case]}
        observation = self.observation()
        observation['measurements'].update(
            format='Win32', untouched_holdout=True, temporal_separation=True,
            malware=2000, true_positives=2000, benign=10000, false_positives=0,
        )
        result = asdict(score_case(case, observation, self.versions))
        self.assertEqual(qualify(manifest, [result])['gates']['temporal_Win32']['status'], 'passed')
        observation['losses'] = 1
        result = asdict(score_case(case, observation, self.versions))
        self.assertEqual(qualify(manifest, [result])['gates']['temporal_Win32']['status'], 'blocked')

    def test_warning_not_confirmed_detection(self):
        self.assertEqual(detection_metrics([self.sample()])['true_positives'],0)

    def test_unavailable_not_clean_or_known_miss(self):
        r=self.sample();r.update(available=False,coverage_complete=False)
        m=detection_metrics([r]);self.assertEqual(m['false_negatives'],0);self.assertEqual(m['unavailable_malware'],1)
        self.assertEqual(m['recall_all_selected'],0)

    def test_confirmed_partial_positive_retained(self):
        r=self.sample();r.update(confirmed=True,evidence_linked=True,coverage_complete=False)
        m=detection_metrics([r]);self.assertEqual(m['true_positives'],1);self.assertEqual(m['partial_confirmed'],1)

    def test_signature_contamination_rejected(self):
        for name in ('hashes','yara','test_markers','amsi','reputation'):
            r=self.sample();r['signature_policy'][name]=True
            with self.assertRaises(ValueError):validate_samples([r])

    def test_duplicate_samples_and_invalid_labels_rejected(self):
        with self.assertRaises(ValueError):validate_samples([self.sample(),self.sample()])
        r=self.sample();r['label']='looks harmless'
        with self.assertRaises(ValueError):validate_samples([r])

    def test_scores_and_versions_fail_closed(self):
        for score in (float('nan'),float('inf'),1.1,-.1,True):
            r=self.sample();r['model_score']=score
            with self.assertRaises(ValueError):validate_samples([r])
        with self.assertRaises(ValueError):validate_samples([self.sample()],'0'*64)

    def test_confirmed_requires_evidence_link(self):
        r=self.sample();r['confirmed']=True
        with self.assertRaises(ValueError):validate_samples([r])

    def test_exact_binomial_safety_bound(self):
        self.assertLessEqual(upper_bound(0,30000),.0001)
        self.assertGreater(upper_bound(0,2000),.001)
        self.assertEqual(upper_bound(0,0),1)
        for args in ((-1,1),(2,1),(0,-1)):
            with self.assertRaises(ValueError):upper_bound(*args)

    def test_queue_crash_recovery_and_frozen_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            store=RunStore(Path(d),self.manifest);first=store.start('fixture');self.assertEqual(store.interrupted(),['fixture']);store.close()
            store=RunStore(Path(d));store.recover();second=store.start('fixture');self.assertNotEqual(first,second)
            store.finish(self.result());self.assertFalse(store.pending());store.close()
            wrong={**self.manifest,'profile':'regression'}
            with self.assertRaises(ValueError):RunStore(Path(d),wrong)

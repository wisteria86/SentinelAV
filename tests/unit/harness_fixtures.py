# Purpose: Share harmless case builders across the separated harness test suites.
# Works with: lab.qualification.backends, lab.qualification.catalog, lab.qualification.contracts,
#   lab.qualification.reporting, lab.qualification.scoring
# Used by: tests.unit.test_critical_harness, tests.unit.test_harness_lifecycle, tests.unit.test_harness_storage

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

class HarnessFixture:
    def setUp(self):
        self.versions=dict(engine='fixture',model='fixture')
        self.case=asdict(CaseDefinition('fixture','harness','host','selfcheck',expected=dict(answer=True)))
        self.manifest=asdict(SuiteManifest('fixture','critical',self.versions,[self.case],{}))

    def observation(self,**measurements):
        return asdict(Observation('fixture',digest(self.versions),dict(answer=True,**measurements),['owned-evidence.json'],True))

    def result(self,**measurements):return asdict(score_case(self.case,self.observation(**measurements),self.versions))

    def sample(self,**changes):
        return dict(sha256='a'*64,label='malware',mode='signature_free',versions_digest=digest(self.versions),
            available=True,coverage_complete=True,confirmed=False,review=True,signature_policy=dict(signature_free=True,hashes=False,yara=False,test_markers=False,amsi=False,reputation=False),**changes)

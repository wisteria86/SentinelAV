# Purpose: Versioned, JSON-only evaluation contracts and strict input validation.
# Works with: sibling modules in lab.qualification
# Used by: lab.qualification.backend_hyperv, lab.qualification.backend_transport, lab.qualification.catalog,
#   lab.qualification.evaluation_environment

"""Versioned, JSON-only evaluation contracts and strict input validation."""
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import re

STATES = ('passed','failed','partial','blocked','unsupported','inconclusive')
TRACKS = ('harness','classification','generalization','raw_detection','prevention','monitoring',
          'false_alarms','automatic_safety','cleanup','recurrence','reliability','performance',
          'deployment','updates','soak','comparison')


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,100}',value):
        raise ValueError('Invalid evaluation identifier')
    return value


def bounded(value, maximum=4*1024*1024):
    if len(json.dumps(value,allow_nan=False).encode())>maximum:raise ValueError('Evaluation metadata budget exceeded')
    return value


@dataclass(frozen=True)
class CaseDefinition:
    id: str
    track: str
    backend: str
    action: str
    mode: str = 'normal'
    required: bool = True
    seconds: int = 120
    parameters: dict = field(default_factory=dict)
    expected: dict = field(default_factory=dict)
    protected_controls: list = field(default_factory=list)
    schema: int = 1

    def __post_init__(self):
        identifier(self.id)
        if self.schema!=1 or self.track not in TRACKS or self.backend not in ('host','sandbox','hyperv'):
            raise ValueError('Unsupported case contract')
        if self.mode not in ('normal','signature_free') or type(self.seconds) is not int or not 1<=self.seconds<=604800:
            raise ValueError('Invalid case mode/budget')
        if type(self.required) is not bool:raise ValueError('Invalid required flag')
        bounded(asdict(self),65536)


@dataclass(frozen=True)
class SuiteManifest:
    run_id: str
    profile: str
    versions: dict
    cases: list
    budgets: dict
    inventories: dict = field(default_factory=dict)
    schema: int = 1

    def __post_init__(self):
        identifier(self.run_id)
        if self.schema!=1 or self.profile not in ('regression','critical','soak','zoo-static','zoo-quick','zoo-dev','zoo-holdout','bazaar-dev','bazaar-holdout'):raise ValueError('Invalid suite')
        ids=[c['id'] for c in self.cases]
        if not ids or len(ids)!=len(set(ids)) or len(ids)>10000:raise ValueError('Invalid/duplicate case inventory')
        for c in self.cases:CaseDefinition(**c)
        if not self.versions:raise ValueError('Frozen versions required')
        bounded(asdict(self))


@dataclass
class Observation:
    case_id: str
    versions_digest: str
    measurements: dict
    evidence: list
    complete: bool = False
    losses: int = 0
    schema: int = 1

    def __post_init__(self):
        identifier(self.case_id)
        if self.schema!=1 or not re.fullmatch('[0-9a-f]{64}',self.versions_digest):raise ValueError('Invalid observation identity')
        if type(self.complete) is not bool or type(self.losses) is not int or self.losses<0:raise ValueError('Invalid observation coverage')
        if not isinstance(self.evidence,list):raise ValueError('Invalid evidence references')
        bounded(asdict(self))


@dataclass
class CaseResult:
    case_id: str
    status: str
    reason: str
    observation: dict | None = None
    schema: int = 1

    def __post_init__(self):
        identifier(self.case_id)
        if self.schema!=1 or self.status not in STATES or not isinstance(self.reason,str) or len(self.reason)>8192:
            raise ValueError('Invalid case result')


@dataclass
class QualificationSummary:
    status: str
    gates: dict
    counts: dict
    required_missing: list
    schema: int = 1


def validate_samples(rows, expected_versions=None):
    seen=set()
    for row in rows:
        sha=row.get('sha256','');mode=row.get('mode')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha) or mode not in ('normal','signature_free'):
            raise ValueError('Invalid sample identity/mode')
        key=(sha,mode)
        if key in seen:raise ValueError('Duplicate measured sample/mode')
        seen.add(key)
        if row.get('label') not in ('malware','benign','unknown','test'):raise ValueError('Invalid ground-truth label')
        if expected_versions and row.get('versions_digest')!=expected_versions:raise ValueError('Mixed engine/model versions')
        for name in ('model_score','neural_score'):
            value=row.get(name)
            if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=1):
                raise ValueError('Invalid model score')
        if row.get('confirmed') and not row.get('evidence_linked'):raise ValueError('Uncorroborated confirmed detection')
        if mode=='signature_free' and row.get('available'):
            p=row.get('signature_policy',{})
            if p.get('signature_free') is not True or any(p.get(k) is not False for k in ('hashes','yara','test_markers','amsi','reputation')):
                raise ValueError('Signature-free attestation absent/contaminated')
    return rows

# Purpose: Shared evidence decisions. Review evidence never grants removal authority.
# Works with: detection.fusion
# Used by: detection.advanced_pipeline, detection.scan_flow, tests.unit.test_fusion_policy

"""Shared evidence decisions. Review evidence never grants removal authority."""
from dataclasses import asdict,dataclass,field


@dataclass(frozen=True)
class Evidence:
    """One piece of evidence about a file.

    source says where it came from (for example 'yara', 'model' or 'emulation'), category is a short
    machine-readable code, and description is a human-readable explanation. confirmed is True for
    definite matches such as a signature hit; unconfirmed evidence only asks for review. details
    holds any extra data.
    """
    source: str
    category: str
    description: str
    confirmed: bool = False
    details: dict = field(default_factory=dict)


def decide(items,omissions=(),policy=None):
    """Combine a list of Evidence into one decision dictionary.

    The verdict is 'Detected' if any confirmed evidence comes from a trusted source, 'Review' if
    there is only unconfirmed evidence, 'Indeterminate' if nothing was found but parts of the file
    could not be checked, and 'No match' otherwise. If a signed fusion policy is supplied, it may
    add one more confirmed fact when several indicators agree.
    """
    facts=[]; seen=set()
    for item in items:
        key=(item.source,item.category,item.description,item.confirmed)
        if key in seen: continue
        seen.add(key); facts.append(item)
        if len(facts)>=128: break
    fusion=None
    if policy:
        from sentinelav.detection.fusion import evaluate
        fusion=evaluate(facts,policy)
        if fusion:facts.append(Evidence('fusion','validated_multi_indicator','Validated multi-indicator classification',True,fusion))
    confirmed=[f for f in facts if f.confirmed and f.source in ('hash','yara','amsi','eicar',
        'normalized-content','container','macro','active-document','emulation','fusion')]
    review=[f for f in facts if not f.confirmed]
    return dict(schema=1,verdict='Detected' if confirmed else 'Review' if review else 'Indeterminate' if omissions else 'No match',
        evidence=[asdict(f) for f in facts],omissions=list(omissions)[:64],
        confirmed_sources=sorted({f.source for f in confirmed}),
        independent_review_categories=sorted({f.category for f in review}),
        automatic_response_eligible=bool(fusion and fusion['automatic_response_eligible']),
        fusion_policy_id=fusion['policy_id'] if fusion else None,
        explanation='Existing signature response policy must separately authorize actions; no match is not a safety guarantee.')

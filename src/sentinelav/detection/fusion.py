# Purpose: Release-gated multi-indicator classification; signed policies are loaded upstream.
# Works with: data.contracts
# Used by: detection.decisions, response.auto_response, updates.artifacts, tests.unit.test_fusion_policy

"""Release-gated multi-indicator classification; signed policies are loaded upstream."""
import math
import re
from sentinelav.data.contracts import fingerprint


def validate_policy(policy):
    """Check that a signed fusion policy is well formed and that its evaluation numbers are possible,
    raising ValueError if not.
    """
    if policy.get('schema')!=1 or policy.get('algorithm')!='fusion-v1':raise ValueError('Unsupported fusion policy')
    if not re.fullmatch('[0-9a-f]{64}',policy.get('model_sha256','')):raise ValueError('Policy requires a pinned model')
    for key in ('threshold',):
        if type(policy.get(key)) not in (int,float) or not math.isfinite(policy[key]) or not 0<=policy[key]<=1:raise ValueError('Invalid fusion threshold')
    report=policy.get('evaluation',{})
    for key in ('benign','false_actions','malware','true_positives','raw_samples','raw_detected','families'):
        if type(report.get(key)) is not int or report[key]<0:raise ValueError('Missing independent evaluation counts')
    if report['false_actions']>report['benign'] or report['true_positives']>report['malware'] or report['raw_detected']>report['raw_samples']:raise ValueError('Impossible evaluation counts')
    if not re.fullmatch('[0-9a-f]{64}',report.get('manifest_sha256','')):raise ValueError('Missing frozen evaluation identity')
    return policy


def gates(policy):
    """Decide what a fusion policy is allowed to do, based on how well it was evaluated.

    Using a statistical upper bound on the false-positive rate, a policy may ask for review only
    after a large, clean evaluation, and may trigger automatic action only after an even larger one
    with zero false alarms. Returns {'review': bool, 'automatic': bool, 'fpr_upper_95': float}.
    """
    validate_policy(policy)
    from scipy.stats import beta
    e=policy['evaluation'];n=e['benign'];fp=e['false_actions']
    # 95% upper bound on the false-positive rate (Clopper-Pearson), given fp mistakes out of n
    # benign files.
    upper=float(beta.ppf(.95,fp+1,n-fp)) if n and fp<n else 1.0
    review=(n>=1000 and upper<=.001 and e['malware']>0 and e['true_positives']/e['malware']>=.9
        and e['raw_samples']>=200 and e['raw_detected']/e['raw_samples']>=.8 and e['families']>=20)
    return dict(review=review,automatic=review and n>=30000 and fp==0 and upper<=.0001,fpr_upper_95=upper)


def evaluate(facts,policy):
    """Apply the fusion policy: a confident model score plus independent behaviour evidence together
    make a confirmed detection.

    Returns the fusion details, or None if the policy is not allowed to act or the evidence does not
    line up.
    """
    state=gates(policy)
    if not state['review']:return None
    model=next((f for f in facts if f.source=='model' and f.details.get('model_id')==policy['model_sha256']
        and f.details.get('calibrated_probability') and f.details.get('model_score',-1)>=policy['threshold']),None)
    # Static packing/import heuristics share the model's inputs: never count them twice.
    corroboration=[f for f in facts if
        (f.source=='emulation' and f.category=='modeled_behavior_sequence') or
        (f.source=='behavior' and f.details.get('verified_process_identity') is True and f.details.get('independent_indicators',0)>=2)]
    if model is None or not corroboration:return None
    return dict(reasons=['Calibrated local model and independent execution evidence meet signed policy'],
        policy_id=fingerprint(policy),automatic_response_eligible=state['automatic'],
        model_id=policy['model_sha256'],correlation_groups=['static-pe-features','execution-behavior'],gate=state)

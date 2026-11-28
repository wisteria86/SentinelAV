# Purpose: Fail-closed qualification, with warnings distinct from confirmed detections.
# Works with: lab.qualification.contracts
# Used by: lab.qualification.evaluation_environment, lab.qualification.features, lab.qualification.inventories,
#   lab.qualification.reporting

"""Fail-closed qualification, with warnings distinct from confirmed detections."""

from dataclasses import asdict
from collections import Counter
from .contracts import Observation, CaseResult, QualificationSummary, digest, validate_samples


def upper_bound(false_positives, total):
    """Return the 95% upper confidence bound on a false-positive rate, given false_positives mistakes
    out of total benign files.

    With zero mistakes this is 1 - 0.05^(1/n) (the 'rule of three' idea); otherwise the exact
    Clopper-Pearson bound.
    """
    if (
        type(false_positives) is not int
        or type(total) is not int
        or not 0 <= false_positives <= total
    ):
        raise ValueError('Invalid binomial counts')
    if not total or false_positives == total:
        return 1.0
    if false_positives == 0:
        return 1 - 0.05 ** (1 / total)
    from scipy.stats import beta

    return float(beta.ppf(0.95, false_positives + 1, total - false_positives))


def score_case(case, observation, versions):
    """Decide a case's result from its observation, failing closed.

    Collateral damage or a false automatic action always fails; incomplete, lost or truncated
    evidence is inconclusive; then every expected measurement must be present and match. Only if all
    of that holds does the case pass.
    """
    o = Observation(**observation)
    if o.case_id != case['id'] or o.versions_digest != digest(versions):
        raise ValueError('Observation does not belong to frozen case/build')
    if not o.evidence:
        return CaseResult(case['id'], 'inconclusive', 'No evidence references', observation)
    m = o.measurements
    if m.get('protected_controls_changed', 0) or m.get('false_actions', 0):
        return CaseResult(
            case['id'], 'failed', 'Collateral damage / false automatic action', observation
        )
    if not o.complete or o.losses or m.get('truncated'):
        return CaseResult(
            case['id'], 'inconclusive', 'Incomplete, lost or truncated evidence', observation
        )
    for key, expected in case.get('expected', {}).items():
        if key not in m:
            return CaseResult(
                case['id'], 'inconclusive', 'Missing expected measurement: ' + key, observation
            )
        if m[key] != expected:
            return CaseResult(case['id'], 'failed', 'Expectation failed: ' + key, observation)
    if m.get('failures', 0):
        return CaseResult(case['id'], 'failed', 'Observed test failures', observation)
    if m.get('skipped', 0):
        return CaseResult(case['id'], 'partial', 'Some checks skipped', observation)
    return CaseResult(case['id'], 'passed', 'Frozen case assertions met', observation)


def detection_metrics(rows):
    """Compute detection statistics for sample rows: true and false positives, misses, recall (over
    eligible and over all selected samples), the false-positive upper bound, and how many were only
    warnings or partial.
    """
    validate_samples(rows)
    malware = [r for r in rows if r['label'] == 'malware']
    benign = [r for r in rows if r['label'] == 'benign']
    measured = lambda rs: [r for r in rs if r.get('available') and r.get('coverage_complete')]
    m, b = measured(malware), measured(benign)
    tp = sum(r.get('available') and r.get('confirmed') is True for r in malware)
    fp = sum(r.get('available') and r.get('confirmed') is True for r in benign)
    fn = sum(not r.get('confirmed') for r in m)
    false_partial = sum(
        r.get('available') and r.get('confirmed') and not r.get('coverage_complete') for r in benign
    )
    return dict(
        selected_malware=len(malware),
        selected_benign=len(benign),
        measured_malware=len(m),
        measured_benign=len(b),
        unavailable_malware=sum(
            not r.get('available') or not r.get('coverage_complete') and not r.get('confirmed')
            for r in malware
        ),
        true_positives=tp,
        false_negatives=fn,
        false_positives=fp,
        recall_eligible=tp / (tp + fn) if tp + fn else None,
        recall_all_selected=tp / len(malware) if malware else None,
        fpr_upper_95=upper_bound(fp, len(b) + false_partial),
        warnings=sum(r.get('review') is True for r in rows),
        partial_confirmed=sum(
            r.get('confirmed') is True and not r.get('coverage_complete') for r in rows
        ),
    )


def qualify(manifest, results):
    """Turn all case results into the overall qualification verdict.

    Every passing result is re-scored to be sure it really passes. Then each gate is checked (per-
    format temporal classification, raw detection, automatic-action safety, every required track,
    and 7-day soak), each with minimum sample sizes. Any failure fails the run; anything missing
    blocks it.
    """
    cases = {c['id']: c for c in manifest['cases']}
    seen = {}
    samples = []
    validated = []
    for result in results:
        CaseResult(**result)
        key = result['case_id']
        if key not in cases or key in seen:
            raise ValueError('Unknown/duplicate case result')
        seen[key] = result
        o = result.get('observation')
        if result['status'] == 'passed' and not o:
            raise ValueError('Passing result requires validated evidence')
        if o:
            verified = score_case(cases[key], o, manifest['versions'])
            if result['status'] == 'passed' and verified.status != 'passed':
                raise ValueError('Unsupported passing result')
            rows = o['measurements'].get('samples', [])
            validate_samples(rows, digest(manifest['versions']))
            if result['status'] == 'passed':
                validated.append(result)
                samples.extend(rows)
    validate_samples(samples, digest(manifest['versions']))
    missing = [
        c['id']
        for c in cases.values()
        if c['required'] and (c['id'] not in seen or seen[c['id']]['status'] != 'passed')
    ]
    gates = {}

    def blocked(name, reason):
        """Mark a gate as blocked, with the reason."""
        gates[name] = dict(status='blocked', reason=reason)

    # Feature candidates, not warnings from raw scanners, measure statistical
    # classification. Keep each supported format as its own mandatory gate.
    for fmt in ('Win32', 'Win64', 'Dot_Net'):
        ms = [
            r.get('observation', {}).get('measurements', {})
            for r in validated
            if r.get('observation')
            and cases[r['case_id']]['track'] == 'classification'
            and r['observation']['measurements'].get('format') == fmt
            and r['observation']['measurements'].get('untouched_holdout')
        ]
        name = 'temporal_' + fmt
        if (
            len(ms) != 1
            or not ms[0].get('untouched_holdout')
            or not ms[0].get('temporal_separation')
        ):
            blocked(name, 'A unique untouched temporal benchmark is required')
            continue
        m = ms[0]
        n = m.get('benign', 0)
        mal = m.get('malware', 0)
        tp = m.get('true_positives', 0)
        fp = m.get('false_positives', 0)
        if any(type(x) is not int or x < 0 for x in (n, mal, tp, fp)) or tp > mal or fp > n:
            raise ValueError('Impossible classification counts')
        if mal < 2000 or n < 10000:
            blocked(
                name,
                'At least 2,000 malicious and 10,000 benign temporal examples per format required',
            )
            continue
        passed = mal > 0 and n > 0 and tp / mal >= 0.9 and upper_bound(fp, n) <= 0.001
        gates[name] = dict(
            status='passed' if passed else 'failed',
            recall=tp / mal if mal else None,
            fpr_upper_95=upper_bound(fp, n),
        )
    raw = [
        r
        for r in samples
        if r['label'] == 'malware'
        and r['mode'] == 'signature_free'
        and r.get('qualification')
        and r.get('independently_selected')
        and r.get('declared_format', r.get('format')) == 'PE'
    ]
    stats = detection_metrics(raw)
    families = {r['family'] for r in raw if r.get('family') and r.get('family_verified')}
    if len(raw) < 200 or len(families) < 20:
        blocked(
            'raw_detection',
            'Requires 200 independent Windows specimens across 20 verified families',
        )
    else:
        gates['raw_detection'] = dict(
            status='passed' if stats['recall_all_selected'] >= 0.8 else 'failed', metrics=stats
        )
    controls = [
        r
        for r in samples
        if r['label'] == 'benign'
        and r.get('available')
        and r.get('automatic_action_exercised')
        and r.get('independent_control')
    ]
    unique = {r['sha256']: r for r in controls}
    false = sum(r.get('false_action') is True for r in unique.values())
    if len(unique) < 30000:
        blocked(
            'automatic_actions', 'Requires 30,000 independently verified automatic-action controls'
        )
    else:
        gates['automatic_actions'] = dict(
            status=(
                'passed' if false == 0 and upper_bound(false, len(unique)) <= 0.0001 else 'failed'
            ),
            false_actions=false,
        )
    for track in (
        'generalization',
        'recurrence',
        'cleanup',
        'deployment',
        'reliability',
        'performance',
        'monitoring',
        'updates',
        'soak',
        'prevention',
        'false_alarms',
    ):
        cs = [c for c in cases.values() if c['track'] == track and c['required']]
        if not cs or any(c['id'] not in seen or seen[c['id']]['status'] != 'passed' for c in cs):
            blocked(track, 'Required evidence missing or not passing')
        else:
            gates[track] = dict(status='passed')
    soak = [
        r.get('observation', {}).get('measurements', {}).get('seconds', 0)
        for r in results
        if r.get('observation')
        and cases[r['case_id']]['track'] == 'soak'
        and r['status'] == 'passed'
    ]
    if not soak or max(soak) < 604800:
        blocked(
            'soak',
            'Seven-day evidence required for release qualification; 24h is an engineering trial',
        )
    if any(r['status'] == 'failed' and cases[r['case_id']]['required'] for r in results) or any(
        g['status'] == 'failed' for g in gates.values()
    ):
        status = 'failed'
    elif missing or any(g['status'] != 'passed' for g in gates.values()):
        status = 'blocked'
    else:
        status = 'passed'
    return asdict(
        QualificationSummary(status, gates, dict(Counter(r['status'] for r in results)), missing)
    )

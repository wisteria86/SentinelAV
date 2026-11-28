# Purpose: Paired cleanup statistics; unavailable Defender baselines never count as wins.
# Works with: sibling modules in lab
# Used by: lab.qualification.guest_inventory, tests.unit.test_removal_benchmark,
#   tools.evaluation.compare_removal

"""Paired cleanup statistics; unavailable Defender baselines never count as wins."""

import random
import statistics


def compare(manifest, trials):
    """Compare clean-up results of SentinelAV and Microsoft Defender on the same frozen set of test
    cases.

    Only fair, matched pairs count: same starting state and OS configuration, separate reset guests,
    two post-reboot checks, and a working Defender baseline. Each product's clean-up is judged
    complete only if no malicious artifact remains and no harmless one was damaged. A bootstrap
    confidence interval decides whether SentinelAV is genuinely better.
    """
    if manifest.get('schema') != 1 or not isinstance(manifest.get('cases'), list):
        raise ValueError('Frozen case manifest required')
    cases = {row['id']: row for row in manifest['cases']}
    if len(cases) != len(manifest['cases']):
        raise ValueError('Duplicate case identity')
    rows = []
    differences = []
    families = set()
    for identity, case in cases.items():
        pair = [row for row in trials if row.get('case_id') == identity]
        by_product = {row['product']: row for row in pair}
        if len(pair) != 2 or set(by_product) != {'Defender', 'SentinelAV'}:
            rows.append(dict(case_id=identity, eligible=False, reason='Missing matched pair'))
            continue
        defender = by_product['Defender']
        sentinel = by_product['SentinelAV']
        reason = None
        if not defender.get('defender_active'):
            reason = 'Defender baseline not operational'
        elif any(
            not all(
                row.get(key)
                for key in (
                    'os_build',
                    'guest_id',
                    'reset_evidence_sha256',
                    'engine_version',
                    'intelligence_version',
                    'configuration_sha256',
                )
            )
            for row in pair
        ):
            reason = 'Missing environment, engine or reset evidence'
        elif any(row.get('setup_blocked') for row in pair):
            reason = 'Prevention/setup block, not remediation'
        elif any(row.get('initial_state_sha256') != case['initial_state_sha256'] for row in pair):
            reason = 'Initial artifact state differs'
        elif defender.get('os_build') != sentinel.get('os_build') or defender.get(
            'configuration_sha256'
        ) != sentinel.get('configuration_sha256'):
            reason = 'OS configurations differ'
        elif defender.get('guest_id') == sentinel.get('guest_id'):
            reason = 'Independent reset environments not established'
        elif any(len(row.get('reboot_checks', [])) != 2 for row in pair):
            reason = 'Two post-reboot checks required'
        elif not defender.get('full_scan_completed'):
            reason = 'Defender Full Scan not completed'
        elif any(not row.get('observations_complete') for row in pair):
            reason = 'Incomplete artifact observations'
        if reason:
            rows.append(dict(case_id=identity, eligible=False, reason=reason))
            continue

        def outcome(row):
            """Judge one product's result for this case: remaining malicious artifacts, damaged
            harmless ones, and whether clean-up was complete.
            """
            malicious = set(case['malicious_artifacts'])
            protected = set(case['benign_artifacts'])
            remaining = set(row.get('remaining_artifacts', [])) & malicious
            for check in row['reboot_checks']:
                remaining.update(set(check.get('remaining_artifacts', [])) & malicious)
            collateral = set(row.get('changed_artifacts', [])) & protected
            complete = not remaining and not collateral and not row.get('unresolved')
            return dict(
                complete=complete,
                malicious_remnants=sorted(remaining),
                collateral=sorted(collateral),
            )

        d = outcome(defender)
        s = outcome(sentinel)
        difference = int(s['complete']) - int(d['complete'])
        differences.append(difference)
        families.add(case['family'])
        rows.append(dict(case_id=identity, eligible=True, Defender=d, SentinelAV=s))
    interval = None
    improvement = None
    if differences:
        rng = random.Random(23)
        n = len(differences)
        bootstrap = sorted(sum(rng.choice(differences) for _ in range(n)) / n for _ in range(10000))
        interval = [bootstrap[249], bootstrap[9749]]
        improvement = statistics.mean(differences)
    no_damage = all(not row['SentinelAV']['collateral'] for row in rows if row['eligible'])
    passed = len(differences) >= 30 and len(families) >= 10 and interval[0] > 0 and no_damage
    return dict(
        schema=1,
        cases=rows,
        eligible_pairs=len(differences),
        families=len(families),
        paired_improvement=improvement,
        bootstrap_95=interval,
        superiority_gate_passed=passed,
        interpretation='Caller-supplied ground truth and observation evidence require audit; only this frozen suite is compared. Defender Offline is a separate benchmark track.',
    )

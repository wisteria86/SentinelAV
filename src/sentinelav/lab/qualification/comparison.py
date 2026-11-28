# Purpose: Paired changes only for frozen identical cohorts and compatible protocols.
# Works with: sibling modules in lab.qualification
# Used by: lab.qualification.reporting, lab.qualification.runner, tests.unit.test_harness_storage

"""Paired changes only for frozen identical cohorts and compatible protocols."""

import json
from pathlib import Path


def import_soak(manifest, logs, case):
    """Find a compatible, verified 7-day soak result from an earlier run and reuse it for this case.
    Returns None if there is none.
    """
    import hashlib

    for folder in sorted(Path(logs).iterdir(), reverse=True):
        if not folder.is_dir():
            continue
        try:
            source = json.loads((folder / 'manifest.json').read_text())
            if source['profile'] != 'soak' or source['versions'] != manifest['versions']:
                continue
            hashes = json.loads((folder / 'hashes.json').read_text())['sha256']
            for name in ('manifest.json', 'results.json'):
                if hashlib.sha256((folder / name).read_bytes()).hexdigest() != hashes[name]:
                    raise ValueError('Soak receipt changed')
            results = json.loads((folder / 'results.json').read_text())['results']
            for result in results:
                if result['status'] != 'passed' or not result.get('observation'):
                    continue
                observation = result['observation']
                m = observation['measurements']
                if (
                    m.get('soak_verified') is not True
                    or m.get('seconds', 0) < 604800
                    or not observation.get('complete')
                    or observation.get('losses')
                ):
                    continue
                observation = {**observation, 'case_id': case['id']}
                return dict(
                    schema=1,
                    source=str(folder),
                    source_results_sha256=hashes['results.json'],
                    observation=observation,
                )
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return None


def paired(old_misses, new_misses, total):
    """Compare the missed samples of two runs on the same cohort: how many were recovered, how many
    newly missed, with a bootstrap 95% interval.
    """
    old = set(old_misses)
    new = set(new_misses)
    recovered = len(old - new)
    regressed = len(new - old)
    if not total or len(old | new) > total:
        raise ValueError('Invalid paired cohort')
    import numpy as np

    rng = np.random.default_rng(23)
    draws = rng.multinomial(
        total,
        [recovered / total, regressed / total, 1 - (recovered + regressed) / total],
        size=10000,
    )
    values = (draws[:, 0] - draws[:, 1]) / total
    return dict(
        total=total,
        recovered=recovered,
        new_misses=regressed,
        paired_recall_change=(recovered - regressed) / total,
        bootstrap_95=[float(np.quantile(values, 0.025)), float(np.quantile(values, 0.975))],
    )


def previous(store):
    """Find the most recent earlier run with the same cases and protocol, and compare its detection
    results with this one, pair by pair.
    """
    current = store.manifest
    for folder in sorted(store.path.parent.iterdir(), reverse=True):
        if folder == store.path or not folder.is_dir():
            continue
        try:
            manifest = json.loads((folder / 'manifest.json').read_text())
            results = json.loads((folder / 'results.json').read_text())['results']
            if (
                manifest['profile'] != current['profile']
                or manifest['cases'] != current['cases']
                or manifest['inventories'] != current['inventories']
            ):
                continue
            if any(
                manifest['versions'].get(k) != current['versions'].get(k)
                for k in ('os', 'harness_protocol', 'scorer_sha256')
            ):
                continue
            current_results = {r['case_id']: r for r in store.results()}
            comparisons = []
            for old in results:
                new = current_results.get(old['case_id'])
                if not new or not old.get('observation') or not new.get('observation'):
                    continue
                a = old['observation']['measurements']
                b = new['observation']['measurements']
                if (
                    a.get('dataset_sha256')
                    and a.get('dataset_sha256') == b.get('dataset_sha256')
                    and a.get('malware') == b.get('malware')
                    and not a.get('truncated')
                    and not b.get('truncated')
                ):
                    if 'missed_examples' not in a or 'missed_examples' not in b:
                        continue
                    if (
                        len(a['missed_examples']) != a['malware'] - a['true_positives']
                        or len(b['missed_examples']) != b['malware'] - b['true_positives']
                    ):
                        continue
                    metric = paired(
                        [r['sha256'] for r in a.get('missed_examples', [])],
                        [r['sha256'] for r in b.get('missed_examples', [])],
                        a['malware'],
                    )
                    metric.update(
                        case_id=old['case_id'],
                        new_false_alarms=len(
                            {r['sha256'] for r in b.get('false_alarm_examples', [])}
                            - {r['sha256'] for r in a.get('false_alarm_examples', [])}
                        ),
                    )
                    comparisons.append(metric)
            return dict(
                schema=1,
                baseline=str(folder),
                product_versions_changed=manifest['versions'] != current['versions'],
                pairs=comparisons,
                interpretation='Same declared cohorts/protocol; not proof of unseen generalization',
            )
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return dict(
        schema=1,
        baseline=None,
        pairs=[],
        reason='No compatible previous frozen cohort/protocol with paired evidence',
    )

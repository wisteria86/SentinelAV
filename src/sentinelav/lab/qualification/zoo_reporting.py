# Purpose: Verify Zoo batch receipts and report measured detection by arm, family and platform.
# Works with: lab.qualification.zoo_guest, zoo_inventory, reporting, runner, store.

from collections import Counter, defaultdict
import json
import re

from .zoo_guest import OUTCOMES
from .zoo_inventory import family_of, split_of

ARMS = (('full', 'A. Full product'), ('generalized', 'B. Generalized: no hashes or family rules'), ('heuristic', 'C. Heuristics and generic rules only'))


def validate_batch(case, measurements):
    parameters = case['parameters']
    groups = measurements['zoo_groups']
    if (measurements.get('zoo_revision') != parameters['revision'] or
            measurements.get('sample_execution') is not False or
            measurements.get('zoo_accounted') is not True or len(groups) != len(parameters['entries'])):
        raise ValueError('Zoo batch receipt does not match its frozen case')
    for entry, group in zip(parameters['entries'], groups):
        rows = group['rows']
        if entry['blob'] != group['blob'] or not rows:
            raise ValueError('Zoo archive receipt identity or coverage mismatch')
        for index, row in enumerate(rows):
            if row['outcome'] not in OUTCOMES:
                raise ValueError('Unknown Zoo inspection outcome')
            if row.get('member_index') != index and not (len(rows) == 1 and 'member_index' not in row
                    and row['outcome'] in ('inspection_failure', 'unsupported', 'blocked_by_other_av')):
                raise ValueError('Invalid Zoo member order')
            if row['outcome'] in ('malicious', 'suspicious', 'miss'):
                if not re.fullmatch('[a-f0-9]{64}', row.get('sha256', '')) or set(row.get('arms', {})) != {name for name, _ in ARMS}:
                    raise ValueError('Zoo sample lacks identity or per-arm evidence')
                if row['outcome'] == 'miss' and row.get('coverage_complete') is not True:
                    raise ValueError('Incomplete inspection cannot be a miss')


def _rate(part, whole):
    return f'{part}/{whole} ({100*part/whole:.1f}%)' if whole else '0/0'


def _arm_verdict(row, arm):
    value = row.get('arms', {}).get(arm)
    return value[1] if value else 'Clean'


def _tally(rows, arm):
    """Files that could not be assessed stay in the denominator and count as not detected."""
    counted = [row for row in rows if row['outcome'] != 'not_applicable']
    return dict(total=len(counted), malicious=sum(_arm_verdict(row, arm) == 'Malicious' for row in counted),
                flagged=sum(_arm_verdict(row, arm) in ('Malicious', 'Suspicious') for row in counted))


def _archives(ledger, arm):
    grouped = defaultdict(list)
    for row in ledger:
        grouped[row['archive']].append(row)
    relevant = {name: rows for name, rows in grouped.items() if any(row['outcome'] != 'not_applicable' for row in rows)}
    return dict(total=len(relevant), malicious=sum(any(_arm_verdict(r, arm) == 'Malicious' for r in rows) for rows in relevant.values()),
                flagged=sum(any(_arm_verdict(r, arm) in ('Malicious', 'Suspicious') for r in rows) for rows in relevant.values()))


def _response_totals(ledger):
    cycles = [row['response_cycle'] for row in ledger if 'response_cycle' in row]
    checks = [row['realtime'] for row in ledger if 'realtime' in row]
    latency = sorted(item['seconds_to_detect'] for item in checks if 'seconds_to_detect' in item)
    return dict(cycles=len(cycles), cycles_completed=sum(item.get('completed', False) for item in cycles), cycle_errors=[item['error'] for item in cycles if item.get('error')][:8],
                realtime_checks=len(checks), realtime_detected=sum(item.get('detected', False) for item in checks),
                realtime_auto_quarantined=sum(item.get('file_removed', False) for item in checks),
                median_seconds_to_detect=latency[len(latency)//2] if latency else None, realtime_errors=[item['error'] for item in checks if item.get('error')][:8])


def summarize(ledger, counts, results, cases):
    binaries = [row for row in ledger if '/Source/' not in row['archive']]
    source = [row for row in ledger if '/Source/' in row['archive']]
    arms = {}
    for arm, _ in ARMS:
        arms[arm] = dict(samples=_tally(binaries, arm), archives=_archives(binaries, arm), source_archives=_archives(source, arm))
    status = 'blocked' if counts['pending'] else 'partial' if counts['inspection_failure'] else 'passed'
    return dict(status=status, outcomes={key: counts[key] for key in (*OUTCOMES, 'pending')}, batches_completed=len(results), batches_total=len(cases),
                arms=arms, response=_response_totals(ledger))


def _breakdown(rows, key, arm='generalized'):
    grouped = defaultdict(list)
    for row in rows:
        if row['outcome'] != 'not_applicable':
            grouped[key(row)].append(row)
    return sorted((name, _tally(items, arm)) for name, items in grouped.items())


def render(store):
    from .reporting import _text, escape
    from .store import write_json
    cases = store.manifest['cases']
    results = {result['case_id']: result for result in store.results()}
    counts = Counter()
    ledger = []
    for case in cases:
        result = results.get(case['id'])
        measurements = ((result or {}).get('observation') or {}).get('measurements', {})
        groups = measurements.get('zoo_groups', []) if result and result['status'] == 'passed' else []
        if groups:
            validate_batch(case, measurements)
        for index, entry in enumerate(case['parameters']['entries']):
            rows = groups[index]['rows'] if groups else [
                dict(outcome='inspection_failure' if result else 'pending',
                     reason=result['reason'] if result else 'Batch pending or interrupted')]
            for row in rows:
                counts[row['outcome']] += 1
                family = family_of(entry['path'])
                ledger.append(dict(case_id=case['id'], archive=entry['path'], blob=entry['blob'], family=family, split=split_of(family), **row))
    summary = summarize(ledger, counts, results, cases)
    revision = cases[0]['parameters']['revision']
    profile = store.manifest['profile']
    lines = [f'# SentinelAV Zoo evaluation ({profile})', '',
             f'Pinned revision {revision}. Each batch ran in a fresh offline Windows Sandbox. Samples were read, never launched.',
             f"Code under test: {store.manifest.get('versions', {}).get('source_identity', store.manifest.get('versions', {}).get('source', 'see manifest'))}",
             'Files that could not be assessed stay in the denominator and count as not detected.', '',
             f"**{summary['status'].upper()}** · {len(results)}/{len(cases)} batches recorded", '',
             '## Detection rates (malware binaries)', '',
             '| Arm | Samples rated Malicious | Samples flagged (incl. Suspicious) | Archives flagged |', '| --- | ---: | ---: | ---: |']
    for arm, label in ARMS:
        item = summary['arms'][arm]
        lines.append(f"| {label} | {_rate(item['samples']['malicious'], item['samples']['total'])} | {_rate(item['samples']['flagged'], item['samples']['total'])} | {_rate(item['archives']['flagged'], item['archives']['total'])} |")
    lines += ['', 'Arm B has no hashes or family rules. Arm C also removes the learned models, whose overlap with these samples is unknown.', '',
              '## Source-code archives', '', 'These hold source text, which static analysis of programs is not designed to judge.', '',
              '| Arm | Archives flagged |', '| --- | ---: |']
    lines += [f"| {label} | {_rate(summary['arms'][arm]['source_archives']['flagged'], summary['arms'][arm]['source_archives']['total'])} |" for arm, label in ARMS]
    lines += ['', '## Outcomes', '', '| Outcome | Count |', '| --- | ---: |']
    lines += [f"| {key.replace('_', ' ')} | {count} |" for key, count in summary['outcomes'].items()]
    binaries = [row for row in ledger if '/Source/' not in row['archive']]
    lines += ['', '## Arm B by file type', '', '| File type | Flagged | Malicious |', '| --- | ---: | ---: |']
    lines += [f"| {escape(name)} | {_rate(tally['flagged'], tally['total'])} | {tally['malicious']} |" for name, tally in _breakdown(binaries, lambda row: str(row.get('kind') or row['outcome']))]
    lines += ['', '## Arm B by family', '', '| Family | Flagged | Malicious |', '| --- | ---: | ---: |']
    lines += [f"| {escape(name)} | {_rate(tally['flagged'], tally['total'])} | {tally['malicious']} |" for name, tally in _breakdown(binaries, lambda row: row['family'])]
    response = summary['response']
    lines += ['', '## Removal and real-time, on real detected samples', '',
              f"- Quarantine, restore and delete cycles completed: {_rate(response['cycles_completed'], response['cycles'])}",
              f"- Real-time checks detected: {_rate(response['realtime_detected'], response['realtime_checks'])}; auto-quarantined: {response['realtime_auto_quarantined']}; median seconds to detect: {response['median_seconds_to_detect']}"]
    lines += [f'- Response error: {escape(item)}' for item in response['cycle_errors']+response['realtime_errors']]
    lines += ['', 'Complete per-entry evidence is in zoo-results.jsonl.', '']
    _text(store.path/'report.md', '\n'.join(lines)+'\n')
    _text(store.path/'zoo-results.jsonl', ''.join(json.dumps(row, allow_nan=False)+'\n' for row in ledger))
    write_json(store.path/'results.json', dict(schema=1, summary=summary, results=list(results.values())), True, 64*1024*1024)
    return summary

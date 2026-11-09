# Purpose: Verify Zoo batch receipts and render static inspection coverage.
# Works with: lab.qualification.zoo_guest, reporting, runner, store.

from collections import Counter
import json
import re

from .zoo_guest import OUTCOMES


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
                    and row['outcome'] in ('inspection_failure', 'unsupported_format')):
                raise ValueError('Invalid Zoo member order')
            if row['outcome'] in ('confirmed_detection', 'warning', 'miss'):
                policy = row.get('signature_policy', {})
                if (policy.get('signature_free') is not True or any(policy.get(key) is not False
                        for key in ('hashes', 'yara', 'test_markers', 'amsi', 'reputation')) or
                        not re.fullmatch('[a-f0-9]{64}', row.get('sha256', ''))):
                    raise ValueError('Zoo sample lacks signature-free identity evidence')
                if row['outcome'] == 'miss' and row.get('coverage_complete') is not True:
                    raise ValueError('Incomplete inspection cannot be a miss')


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
                ledger.append(dict(case_id=case['id'], archive=entry['path'], blob=entry['blob'], **row))
    status = 'blocked' if counts['pending'] else 'partial' if counts['inspection_failure'] else 'passed'
    summary = dict(status=status, outcomes={key:counts[key] for key in (*OUTCOMES,'pending')},
                   batches_completed=len(results), batches_total=len(cases))
    revision = cases[0]['parameters']['revision']
    quick=store.manifest['profile']=='zoo-quick'
    lines = ['# SentinelAV Quick Zoo Check' if quick else '# SentinelAV Zoo static inspection', '',
             f'Pinned revision {revision}. Each batch runs in a fresh offline Windows Sandbox.',
             'Scope is one cached batch of four pinned archives.' if quick else
             'Scope covers the repository malware tree. Checksum and password sidecars are inventory metadata.',
             'Signatures, emulation, sample execution and automatic response are disabled.',
             'Unsupported and unreadable archives receive archive-level rows when members cannot be enumerated.',
             'This development scan does not establish release qualification.', '',
             f"**{status.upper()}** · {len(results)}/{len(cases)} batches recorded", '',
             '| Outcome | Count |', '| --- | ---: |']
    lines.extend(f'| {key.replace("_", " ")} | {count} |' for key, count in summary['outcomes'].items())
    lines.extend(['', 'Complete per-entry evidence is in zoo-results.jsonl.', '',
                  '| Batch | Archive | Member | Outcome | Reason |', '| --- | --- | --- | --- | --- |'])
    for row in ledger:
        lines.append('| ' + ' | '.join(escape(row.get(key, '')) for key in
                     ('case_id', 'archive', 'member', 'outcome', 'reason')) + ' |')
    _text(store.path/'report.md', '\n'.join(lines)+'\n')
    _text(store.path/'zoo-results.jsonl', ''.join(json.dumps(row, allow_nan=False)+'\n' for row in ledger))
    write_json(store.path/'results.json', dict(schema=1, summary=summary, results=list(results.values())),
               True, 64*1024*1024)
    return summary

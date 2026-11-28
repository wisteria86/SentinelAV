# Purpose: Export bounded diagnostic metadata for a completed fixed-corpus guest run.
# Works with: tools.evaluation.run_learned_zoo
# Used by: tests.unit.test_learned_zoo_audit

"""Export bounded diagnostic metadata for a completed fixed-corpus guest run.

This never transfers samples, free-form sample strings, or guest file paths.
Run before disposing the registered offline guest. The original report stays
immutable; diagnostics and computed counts are a separate evidence artifact.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess

from tools.evaluation.run_learned_zoo import invoke

OUTCOMES = ('unavailable', 'not_detected', 'detected', 'detected_incomplete')
TERMINATIONS = (
    'not_applicable',
    'not_started',
    'unsupported_api',
    'execution_fault',
    'instruction_limit',
    'modeled_run_ended',
    'backend_error',
    'timeout',
    'time_limit',
    'changed_page_limit',
)
EMULATION = ('Not run', 'Partial', 'Unavailable', 'Not applicable')


def command(row, kind='diagnostics'):
    name = row['path']
    sha = row['sha256']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or not re.fullmatch('[0-9a-f]{64}', sha):
        raise ValueError('Invalid fixed measurement identity')
    script = r'''
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or @(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 80}
$dirs=@(Get-ChildItem 'C:\SentinelAV-Test' -Directory -Filter 'StaticCorpus-*')
if($dirs.Count -ne 3){exit 81}
$rows=@()
foreach($d in $dirs){
 if($d.Name -notmatch '^StaticCorpus-[0-9a-f]{32}$'){exit 82}
 $p=Join-Path $d.FullName 'report.json'
 if((Get-Item -LiteralPath $p).Length -gt 67108864){exit 83}
 $r=Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
 if($r.signature_free -ne $true -or $r.sample_execution -ne $false -or $r.response_actions -ne $false){exit 84}
 $rows+=@($r.rows | Where-Object path -eq '__NAME__')
}
if($rows.Count -ne 1 -or $rows[0].sha256 -ne '__SHA__'){exit 85}
$x=$rows[0];$e=$x.scan.advanced_analysis.coverage.emulation
$o=@('unavailable','not_detected','detected','detected_incomplete').IndexOf([string]$x.outcome)
if($o -lt 0){exit 86};$v=$o
if($x.error){$v=$v -bor 4};if($null -ne $x.scan){$v=$v -bor 8}
if($x.scan.advanced_review_total -gt 0){$v=$v -bor 16}
if(@($x.scan.errors | Where-Object {$null -ne $_}).Count -gt 0){$v=$v -bor 32}
if($x.scan.skipped -gt 0){$v=$v -bor 64}
if($x.scan.status -eq 'Complete'){$v=$v -bor 128}
$t='not_applicable';if($e.termination_reason){$t=[string]$e.termination_reason}
$ti=@('not_applicable','not_started','unsupported_api','execution_fault','instruction_limit','modeled_run_ended','backend_error','timeout','time_limit','changed_page_limit').IndexOf($t)
if($ti -lt 0){$ti=15};$v=$v -bor ($ti -shl 8)
$ei=0;if($e.status -eq 'Partial'){$ei=1}elseif($e.status -eq 'Unavailable'){$ei=2}elseif($e.status -eq 'Not applicable'){$ei=3}
$v=$v -bor ($ei -shl 12)
$a=0;if($null -ne $e.api_attempts){$a=[int]$e.api_attempts}
if($a -lt 0 -or $a -gt 16383){exit 89}
$v=$v -bor ($a -shl 14)
$v=$v -bor ([int][Math]::Min(3,@($e.diagnostics | Where-Object {$null -ne $_}).Count) -shl 28)
exit (1073741824+$v)
'''.replace('__NAME__', name).replace('__SHA__', sha)
    if kind == 'neural':
        return script.replace(
            'exit (1073741824+$v)',
            r'''
$n=$x.candidate_neural
$s=16383
if($null -ne $n.model_score){$s=[int][Math]::Round(10000*[double]$n.model_score);if($s -lt 0 -or $s -gt 10000){exit 87}}
$i=@('Complete','Partial','Not applicable','Disabled','Unavailable').IndexOf([string]$n.status)
if($i -lt 0){$i=7}
exit (1073741824+$s+($i -shl 14))
''',
        )
    if kind in ('bytes_examined', 'bytes_total'):
        return script.replace(
            'exit (1073741824+$v)',
            "$b=$x.candidate_neural."
            + kind
            + ";if($null -eq $b -or $b -lt 0 -or $b -gt 8388608){exit 88};exit (1073741824+[int]$b)",
        )
    if kind != 'diagnostics':
        raise ValueError('Unsupported numeric metadata field')
    return script


def decode(value):
    value -= 1073741824
    if not 0 <= value < 2**30:
        raise ValueError('Invalid bounded diagnostic response')
    ti = (value >> 8) & 15
    return dict(
        outcome=OUTCOMES[value & 3],
        row_error=bool(value & 4),
        scan_present=bool(value & 8),
        advanced_review=bool(value & 16),
        scan_errors=bool(value & 32),
        scan_skipped=bool(value & 64),
        scan_complete=bool(value & 128),
        emulation_termination=TERMINATIONS[ti] if ti < len(TERMINATIONS) else 'Unclassified',
        emulation_status=EMULATION[(value >> 12) & 3],
        api_attempts=(value >> 14) & 16383,
        diagnostic_count_capped_at_3=(value >> 28) & 3,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    state = json.loads(
        Path('F:/SentinelAV-Work/lab/windows-sandbox/latest.json').read_text(encoding='utf-8-sig')
    )
    guest = report['guest_id']
    running = json.loads(subprocess.check_output(['wsb.exe', 'list', '--raw']))[
        'WindowsSandboxEnvironments'
    ]
    if not (
        state.get('active_guest_verified')
        and state.get('guest_id') == guest
        and state.get('kit_id') == report['kit_id']
        and len(running) == 1
        and running[0]['Id'] == guest
    ):
        raise ValueError('Matching registered offline guest required')
    if (
        report.get('signature_free') is not True
        or report.get('sample_native_execution') is not False
    ):
        raise ValueError('Strict static/virtual evaluation required')
    rows = []
    for row in report['rows']:
        result = dict(row)
        if not row.get('unavailable'):
            result['diagnostics'] = decode(invoke(guest, command(row)))
            result['neural_status'] = 'Complete' if row['neural_complete'] else 'Unavailable'
            if not row['neural_complete']:
                value = invoke(guest, command(row, 'neural')) - 1073741824
                if not 0 <= value < 131072 or (10000 < (value & 16383) < 16383):
                    raise ValueError('Invalid neural metadata')
                index = value >> 14
                statuses = ('Complete', 'Partial', 'Not applicable', 'Disabled', 'Unavailable')
                result['neural_status'] = (
                    statuses[index] if index < len(statuses) else 'Unavailable'
                )
                result['neural_score'] = (
                    None if (value & 16383) == 16383 else (value & 16383) / 10000
                )
                if result['neural_status'] == 'Partial':
                    for field in ('bytes_examined', 'bytes_total'):
                        size = invoke(guest, command(row, field)) - 1073741824
                        if not 0 <= size <= 8388608:
                            raise ValueError('Invalid bounded neural byte count')
                        result['neural_' + field] = size
        rows.append(result)
    eligible_observations = [
        r
        for r in rows
        if not r.get('unavailable')
        and r.get('signature_free_attested')
        and r.get('postcheck_unchanged')
        and not r['diagnostics']['row_error']
    ]
    unique = {}
    duplicates = []
    for row in eligible_observations:
        previous = unique.get(row['sha256'])
        if previous is not None:
            if previous['label'] != row['label']:
                raise ValueError('Conflicting labels for one measured identity')
            duplicates.append(
                dict(path=row['path'], duplicate_of=previous['path'], sha256=row['sha256'])
            )
        else:
            unique[row['sha256']] = row
    eligible = list(unique.values())
    counts = {}
    for label in ('malware', 'benign'):
        selected = [r for r in eligible if r['label'] == label]
        counts[label] = dict(
            planned=sum(r['label'] == label for r in rows),
            unique_imported_and_attested=len(selected),
            feature_model_complete=sum(r['model_complete'] for r in selected),
            neural_complete=sum(r['neural_complete'] for r in selected),
            neural_partial=sum(r['neural_status'] == 'Partial' for r in selected),
            both_models_complete=sum(
                r['model_complete'] and r['neural_complete'] for r in selected
            ),
            feature_model_flags=sum(r['model_complete'] and r['model_flag'] for r in selected),
            neural_flags=sum(r['neural_complete'] and r['neural_flag'] for r in selected),
            either_complete_model_flags=sum(
                (r['model_complete'] and r['model_flag'])
                or (r['neural_complete'] and r['neural_flag'])
                for r in selected
            ),
            neural_partial_review_flags=sum(
                r['neural_status'] == 'Partial' and r['neural_flag'] for r in selected
            ),
            either_model_review_flags_including_partial=sum(
                (r['model_complete'] and r['model_flag'])
                or (r['neural_status'] in ('Complete', 'Partial') and r['neural_flag'])
                for r in selected
            ),
            pipeline_review_flags=sum(r['diagnostics']['advanced_review'] for r in selected),
            rows_with_scan_errors=sum(r['diagnostics']['scan_errors'] for r in selected),
            confirmed_detections=sum(
                r['diagnostics']['outcome'] in ('detected', 'detected_incomplete') for r in selected
            ),
            full_inspection_coverage=sum(r['coverage_complete'] for r in selected),
        )
    evidence = dict(
        schema=1,
        source_report=str(args.report.absolute()),
        guest_id=guest,
        kit_id=report['kit_id'],
        counts=counts,
        rows=rows,
        duplicates_excluded_from_counts=duplicates,
        limitations=report['limitations'],
    )
    path = args.report.with_name('diagnostic-audit.json')
    with path.open('x', encoding='utf-8') as stream:
        json.dump(evidence, stream, indent=2)
    print(json.dumps(counts, indent=2))
    print('AUDIT', path)


if __name__ == '__main__':
    main()

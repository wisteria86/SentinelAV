# Purpose: Print a short, paste-ready status of every evaluation stage for the 90% detection goal.
# Works with: lab.qualification ledgers under logs/, benign evaluations and snapshots on the work drive
# Used by: scripts/eval/SentinelAV-Eval.ps1

"""Print a short, paste-ready status of every evaluation stage for the 90% detection goal.

Reads only result files; scans nothing. Output also goes to <work>/STATUS.txt.
"""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get('SENTINELAV_WORK_ROOT', 'F:/SentinelAV-Work'))
ARMS = (('full', 'A. Full product (all layers)'), ('generalized', 'B. Unseen-malware layers (no hashes/family rules)'),
        ('heuristic', 'C. Rules only (no hashes, no ML)'))


def pct(part, whole):
    return f'{part}/{whole} ({100 * part / whole:.1f}%)' if whole else '0/0'


def latest_run(profile):
    runs = []
    for report in (ROOT / 'logs').glob('*/report.md'):
        head = report.read_text(encoding='utf-8', errors='replace')[:400]
        if f'({profile})' in head:
            runs.append(report.parent)
    return max(runs, key=lambda p: p.name) if runs else None


def corpus(profile, lines):
    run = latest_run(profile)
    lines.append(f'== {profile} ==')
    if not run:
        lines.append('  not run yet')
        return
    rows = [json.loads(l) for l in (run / 'zoo-results.jsonl').open(encoding='utf-8')]
    done = [r for r in rows if r['outcome'] != 'pending']
    state = next((l for l in (run / 'report.md').read_text(encoding='utf-8').splitlines() if 'batches recorded' in l), '')
    lines.append(f'  run: {run.name}   {state.strip("* ")}')
    lines.append(f'  samples scanned: {len(done)} of {len(rows)}')
    if not done:
        return
    for key, label in ARMS:
        verdicts = [(r.get('arms') or {}).get(key, [0, 'Clean'])[1] for r in done]
        lines.append(f'  {label}: flagged {pct(sum(v != "Clean" for v in verdicts), len(done))}, '
                     f'Malicious {pct(sum(v == "Malicious" for v in verdicts), len(done))}')
    pe = [r for r in done if r.get('kind') == 'pe' and 'pe_features' in (r.get('model_scores') or {})]
    lines.append(f'  EMBER model alone on Windows programs (score>=0.98): {pct(sum(r["model_scores"]["pe_features"] >= .98 for r in pe), len(pe))}')
    kinds = {}
    for r in done:
        kinds.setdefault(r.get('kind') or '?', []).append((r.get('arms') or {}).get('generalized', [0, 'Clean'])[1] != 'Clean')
    worst = sorted(kinds.items(), key=lambda kv: sum(kv[1]) / len(kv[1]))
    lines.append('  arm B by file type (worst first): ' + ', '.join(f'{k} {sum(v)}/{len(v)}' for k, v in worst[:10]))
    missed = [r for r in done if (r.get('arms') or {}).get('full', [0, 'Clean'])[1] == 'Clean']
    lines.append(f'  missed by full product: {len(missed)}' + (' -> ' + ', '.join(f'{r.get("family")}({r.get("kind")})' for r in missed[:12]) if missed else ''))


def benign(lines):
    lines.append('== false alarms on clean software ==')
    found = sorted((WORK / 'evaluations').glob('benign-*/summary.json'), key=lambda p: p.stat().st_mtime)
    if not found:
        lines.append('  not run yet')
        return
    for path in found[-2:]:
        s = json.loads(path.read_text(encoding='utf-8'))
        lines.append(f'  {path.parent.name[:30]} ({s.get("split")}, {s.get("created_utc", "")[:16]}, ClamAV {s.get("clamav", "unknown")})')
        lines.append(f'    files {s["files"]}; Malicious {s["malicious"]["flagged"]} ({s["malicious"]["percent"]}%); '
                     f'any flag {s["any_flag"]["flagged"]} ({s["any_flag"]["percent"]}%); omitted {s.get("omitted")}')
        for item in (s.get('flagged_by_product') or [])[:5]:
            lines.append(f'    flagged: {str(item)[:150]}')


def main():
    lines = ['SentinelAV status for the 90% goal (paste this to Claude)']
    try:
        commit = subprocess.run(['git', 'log', '-1', '--format=%h %s'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(['git', 'status', '--porcelain', 'src', 'tools', 'tests', 'scripts'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        lines.append(f'code: {commit}' + ('  (UNCOMMITTED changes present)' if dirty else ''))
    except OSError:
        pass
    freeze = WORK / 'freeze.json'
    lines.append('freeze: ' + (freeze.read_text(encoding='utf-8').strip() if freeze.is_file() else 'not frozen yet'))
    corpus('bazaar-dev', lines)
    corpus('bazaar-holdout', lines)
    benign(lines)
    text = '\n'.join(lines)
    print(text)
    (WORK / 'STATUS.txt').write_text(text + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()

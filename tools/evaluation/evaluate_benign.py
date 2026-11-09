# Purpose: Read-only, repeatable evaluation of presumed-benign installed files.
# Works with: detection.engine, paths, platform.engine_policy, workspace
# Used by: tests.unit.test_advanced_evaluation, tests.unit.test_benign_evaluation

"""Read-only, repeatable evaluation of presumed-benign installed files.

Detections require review; this tool does not establish ground truth or a real
malware protection rate. No response actions, uploads, or file execution.
"""
from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
import argparse
from datetime import datetime,timezone
import hashlib
import html
import json
import os
from pathlib import Path
import threading
import time
import uuid
import psutil
from sentinelav.detection.engine import Scanner
from sentinelav.platform.engine_policy import inspection_options

ROOT=RESOURCE_ROOT


def fingerprint(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        while chunk:=stream.read(1024*1024): digest.update(chunk)
        after=os.fstat(stream.fileno())
    current=path.stat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    if identity(before)!=identity(after) or identity(after)!=identity(current):
        raise ValueError('File changed during corpus fingerprinting')
    return digest.hexdigest()


def select_files(roots,limit,max_bytes):
    candidates={}
    omissions=[]
    for root in roots:
        root=Path(root).absolute()
        if any(p.is_symlink() or p.is_junction() for p in [root,*root.parents]):
            omissions.append(dict(path=str(root),reason='Linked input path rejected'))
            continue
        try:
            entries=[root] if root.is_file() else sorted(root.iterdir(),key=lambda p:p.name.casefold())
            for path in entries:
                if len(candidates)>=limit: break
                if path.is_symlink() or path.is_junction() or not path.is_file(): continue
                if path.suffix.lower() not in ('.exe','.dll','.pyd','.txt','.json','.html','.xml'):
                    continue
                size=path.stat().st_size
                if size>max_bytes:
                    omissions.append(dict(path=str(path),reason='Above evaluation file-size cap'))
                    continue
                candidates[str(path.resolve())]=path.resolve()
        except OSError as error:
            omissions.append(dict(path=str(root),reason=str(error)))
    return list(candidates.values()),omissions


def evaluate(paths,repeats=2,max_mb=20,timeout=120,signature_path=None,rules=None,options=None):
    if not 1<=repeats<=5 or not 1<=max_mb<=100 or not 1<=timeout<=600:
        raise ValueError('Invalid evaluation limits')
    process=psutil.Process()
    stop=threading.Event()
    peak=[process.memory_info().rss]
    baseline_rss=peak[0]
    def sample():
        while not stop.wait(.02): peak[0]=max(peak[0],process.memory_info().rss)
    sampler=threading.Thread(target=sample,name='evaluation-memory',daemon=True)
    sampler.start()
    deadline=time.monotonic()+timeout
    inventory=[]
    runs=[]
    scanner=None
    try:
        init=time.perf_counter()
        selected_options=inspection_options(options)
        scanner=Scanner(signature_path or ROOT/'signatures.json',rules or ROOT/'rules',max_mb=max_mb,options=selected_options)
        initialization=time.perf_counter()-init
        metadata=scanner.signatures.metadata
        for path in paths:
            if time.monotonic()>=deadline: break
            entry=dict(path=str(path),ground_truth='Presumed benign; not independently verified')
            try:
                entry.update(sha256=fingerprint(path),bytes=path.stat().st_size)
            except (OSError,ValueError) as error: entry['error']=str(error)
            inventory.append(entry)
        eligible=[entry['path'] for entry in inventory if 'sha256' in entry]
        for iteration in range(repeats):
            if time.monotonic()>=deadline: break
            before=process.cpu_times()
            started=time.perf_counter()
            result=scanner.scan(eligible,lambda:time.monotonic()>=deadline,lambda *a:None)
            seconds=time.perf_counter()-started
            after=process.cpu_times()
            runs.append(dict(iteration=iteration+1,seconds=round(seconds,4),
                             cpu_seconds=round(after.user+after.system-before.user-before.system,4),
                             files_per_second=round(result['scanned']/seconds,2) if seconds else None,
                             scan=result))
        changed=[]
        postcheck_errors=[]
        verified=0
        for entry in inventory:
            if 'sha256' not in entry: continue
            if time.monotonic()>=deadline: break
            try:
                if fingerprint(Path(entry['path']))!=entry['sha256']: changed.append(entry['path'])
                verified+=1
            except (OSError,ValueError) as error:
                postcheck_errors.append(dict(path=entry['path'],error=str(error)))
        findings={d['sha256']:d for run in runs for d in run['scan']['detections']}
        corpus_id=hashlib.sha256(json.dumps([(e['path'],e.get('sha256')) for e in inventory],sort_keys=True).encode()).hexdigest()
        completed=(len(inventory)==len(paths) and len(runs)==repeats and all(r['scan']['status']=='Complete' for r in runs)
                   and verified==len(eligible) and not changed and not postcheck_errors and len(eligible)==len(paths))
        return dict(created_utc=datetime.now(timezone.utc).isoformat(),scope='Read-only presumed-benign corpus evaluation',
                    status='Complete' if completed else 'Incomplete / review omissions',corpus_id=corpus_id,
                    selected_files=len(paths),fingerprinted_files=len(eligible),inventory=inventory,
                    signature_count=len(scanner.signatures),signature_feed=metadata,inspection_options=selected_options,
                    local_overlay_sha256=fingerprint(Path(signature_path or ROOT/'signatures.json')),
                    rule_sha256={p.name:fingerprint(p) for p in sorted(Path(rules or ROOT/'rules').glob('*.yar'))},
                    initialization_seconds=round(initialization,4),rss_baseline_mb=round(baseline_rss/1024**2,2),
                    sampled_peak_rss_mb=round(max(peak[0],process.memory_info().rss)/1024**2,2),
                    memory_sample_interval_ms=20,runs=runs,files_changed=changed,postcheck_errors=postcheck_errors,
                    postchecked_files=verified,findings_requiring_review=list(findings.values()),
                    confirmed_false_positives=None,files_executed=False,files_modified=False,
                    limitations=['Ground truth is not independently verified; detections are not confirmed false positives.',
                                 'Repeated reads use OS cache; results are not cold-start benchmarks.',
                                 'Sampled RSS may miss short peaks; it includes Python and the evaluation harness.',
                                 'No malware detection rate or dynamic protection effectiveness is measured.'])
    finally:
        stop.set()
        sampler.join(2)
        if scanner is not None: scanner.signatures.close()


def render(report):
    esc=lambda value:html.escape(str(value),quote=True)
    rows=''.join('<tr>'+''.join('<td>'+esc(v)+'</td>' for v in [r['iteration'],r['scan']['scanned'],len(r['scan']['detections']),r['scan'].get('structural_review_total',0),r['scan'].get('advanced_review_total',0),r['scan']['skipped'],len(r['scan']['errors']),r['seconds'],r['scan']['status']])+'</tr>' for r in report['runs'])
    findings=''.join('<li>'+esc(d['path'])+' — '+esc('; '.join(d['reasons']))+'</li>' for d in report['findings_requiring_review']) or '<li>None in inspected files.</li>'
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>SentinelAV benign-file evaluation</title>'
            '<style>body{font:15px Segoe UI,sans-serif;background:#fff8ee;color:#302217;margin:36px;max-width:1100px}h1{color:#d96b19}table{border-collapse:collapse;width:100%}td,th{border:1px solid #dfd0bb;padding:10px;text-align:left}th{background:#f5e6d1}li{overflow-wrap:anywhere}</style>'
            '<h1>SentinelAV benign-file evaluation</h1><p>'+esc(report['status'])+' · '+esc(report['created_utc'])+'</p>'
            '<p>'+esc(report['selected_files'])+' selected files · '+esc(report['signature_count'])+' hash signatures · sampled peak RSS '+esc(report['sampled_peak_rss_mb'])+' MiB</p>'
            '<p>Inspection options: '+esc(json.dumps(report.get('inspection_options',{}),sort_keys=True))+'</p>'
            '<table><tr><th>Run</th><th>Scanned</th><th>Detections</th><th>Structural reviews</th><th>Advanced reviews</th><th>Skipped</th><th>Errors/omissions</th><th>Seconds</th><th>Status</th></tr>'+rows+'</table>'
            '<h2>Detections requiring review</h2><ul>'+findings+'</ul><h2>Limits</h2><ul>'+''.join('<li>'+esc(v)+'</li>' for v in report['limitations'])+'</ul>'
            '<p>JSON contains the hashed corpus inventory, scan warnings, errors, selection omissions, and database version.</p></html>')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,action='append',help='Top-level files only; repeat to add locations')
    parser.add_argument('--limit',type=int,default=200)
    parser.add_argument('--repeats',type=int,default=2)
    parser.add_argument('--max-mb',type=int,default=20)
    parser.add_argument('--advanced',action='store_true',help='Enable content/document analysis; model, reputation, emulation and AMSI remain off')
    parser.add_argument('--timeout',type=int,default=120,help='Total evaluation budget, 1..600 seconds')
    parser.add_argument('--per-root-limit',type=int,help='Cap each root to avoid the first location filling the entire corpus')
    args=parser.parse_args()
    if not 1<=args.limit<=1000: parser.error('--limit must be between 1 and 1000')
    roots=args.root or [Path(os.environ.get('SystemRoot','C:/Windows'))/'System32']
    if args.per_root_limit is not None and not 1<=args.per_root_limit<=1000:
        parser.error('--per-root-limit must be between 1 and 1000')
    if args.per_root_limit:
        paths=[]; omissions=[]
        for root in roots:
            selected,gaps=select_files([root],args.per_root_limit,args.max_mb*1024**2)
            omissions.extend(gaps)
            for path in selected:
                if path not in paths and len(paths)<args.limit: paths.append(path)
    else:
        paths,omissions=select_files(roots,args.limit,args.max_mb*1024**2)
    if not paths: parser.error('No eligible files found')
    report=evaluate(paths,args.repeats,args.max_mb,args.timeout,options={'advanced':args.advanced})
    report['selection_omissions']=omissions
    report['roots']=[str(p) for p in roots]
    from sentinelav.workspace import Workspace
    output=Workspace().area('evaluations')/('benign-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    output.mkdir(parents=True,exist_ok=False)
    (output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (output/'report.html').write_text(render(report),encoding='utf-8')
    print(json.dumps(dict(status=report['status'],files=len(paths),hashes=report['signature_count'],
                         review_findings=len(report['findings_requiring_review']),
                         runs=[dict(scanned=r['scan']['scanned'],seconds=r['seconds'],skipped=r['scan']['skipped'],errors=len(r['scan']['errors'])) for r in report['runs']],
                         peak_rss_mb=report['sampled_peak_rss_mb'],report=str(output/'report.html')),indent=2))


if __name__=='__main__': main()

# Purpose: Redacted host reports. Never interprets Markdown or guest paths as commands.
# Works with: lab.qualification.comparison, lab.qualification.contracts, lab.qualification.scoring,
#   lab.qualification.store, workspace
# Used by: lab.qualification.backend_transport, lab.qualification.guest, lab.qualification.guest_lifecycle,
#   lab.qualification.guest_telemetry

"""Redacted host reports. Never interprets Markdown or guest paths as commands."""
import csv
import hashlib
import html
import io
import json
import re
from collections import defaultdict
from .contracts import digest
from .scoring import qualify,detection_metrics
from .store import write_json


def redact(value):
    """Recursively hide secrets in a value: keys that look like passwords, tokens or command lines, and
    secret-looking text inside strings.
    """
    if isinstance(value,dict):
        return {str(k):('[REDACTED]' if re.search(r'(?i)(password|secret|transfer.key|private.key|auth.token|credential|commandline|authorization|api.?key|^token$|cookie)',str(k)) else redact(v)) for k,v in value.items()}
    if isinstance(value,list):return [redact(v) for v in value[:10000]]
    if isinstance(value,str):
        value=re.sub(r'(?i)((?:password|passwd|api[_-]?key|token|secret|authorization)\s*[:=]\s*)(?:"[^"]*"|\S+)',r'\1[REDACTED]',value)
        value=re.sub(r'(?i)(-(?:password|token|apikey)\s+)(?:"[^"]*"|\S+)',r'\1[REDACTED]',value)
        value=re.sub(r'(?i)\b(Bearer|Basic)\s+\S+',r'\1 [REDACTED]',value)
        value=re.sub(r'(?im)(\b(?:Parent)?CommandLine\s*:)[^\r\n]*',r'\1 [REDACTED]',value)
        return ''.join(c for c in value[:8192] if c in '\n\t' or ord(c)>=32)
    return value


def escape(value):
    """Make a value safe to place in a Markdown table (redacted, HTML-escaped, Markdown characters
    neutralised).
    """
    text=html.escape(str(redact(value))).replace('|','&#124;').replace('`','&#96;').replace('\n',' ')
    for c in ('[',']','(',')','*','_','!'):text=text.replace(c,'\\'+c)
    return text


def render(store):
    """Write all report files for a run: the Markdown report, results, failure backlog, telemetry
    health, per-sample CSV, per-track summaries and a hash list.

    Every evidence reference is checked to be a real file inside the run folder. Returns the
    qualification summary.
    """
    if store.manifest['profile'] in ('zoo-static','zoo-quick','zoo-dev','zoo-holdout','bazaar-dev','bazaar-holdout'):
        from .zoo_reporting import render as render_zoo
        return render_zoo(store)
    from pathlib import Path
    from sentinelav.workspace import unlinked
    manifest=store.manifest;results=redact(store.results())
    for result in results:
        if not result.get('observation'):continue
        for reference in result['observation']['evidence']:
            if not isinstance(reference,str) or Path(reference).is_absolute():raise ValueError('Host evidence must be a run-relative file')
            path=unlinked(store.path/reference)
            if not path.resolve().is_relative_to(store.path.resolve()) or not path.is_file():raise ValueError('Missing/escaping evidence reference')
    summary=qualify(manifest,results)
    grouped=defaultdict(list);samples=[];errors=[];telemetry=[];health=[];backlog=[]
    cases={c['id']:c for c in manifest['cases']}
    for r in results:
        grouped[cases[r['case_id']]['track']].append(r)
        m=(r.get('observation') or {}).get('measurements',{})
        samples.extend(m.get('samples',[]));telemetry.extend(m.get('telemetry',[]));health.extend(m.get('telemetry_health',[]))
        if r['status']!='passed':
            item=dict(case_id=r['case_id'],status=r['status'],reason=r['reason'],track=cases[r['case_id']]['track'])
            errors.append(item);backlog.append({**item,'priority':0 if m.get('protected_controls_changed') or m.get('false_actions') else 1 if r['status']=='failed' else 2})
    backlog.sort(key=lambda r:(r['priority'],r['case_id']))
    lines=['# SentinelAV critical evaluation','',f"**Qualification: {summary['status'].upper()}**",'',
        'Internal evaluation; no certification, general protection percentage or independent-laboratory claim. Missing evidence never counts as success.','',
        f"Run: `{manifest['run_id']}` · Profile: {manifest['profile']} · Frozen identity: `{digest(manifest['versions'])}`",'',
        f'Completed cases: {len(results)}/{len(manifest["cases"])}. Resume uses the frozen queue; incomplete guest cases restart in a clean environment.','',
        '## Critical findings','', '| Priority | Case | State | Finding |','| --- | --- | --- | --- |']
    lines += [f"| {r['priority']} | {escape(r['case_id'])} | {r['status']} | {escape(r['reason'])} |" for r in backlog]
    if not backlog:lines.append('| — | — | pending | No completed failure evidence yet |')
    lines+=['','## Qualification gates','','| Gate | State | Evidence |','| --- | --- | --- |']
    lines += [f"| {escape(k)} | {v['status']} | {escape(v)} |" for k,v in summary['gates'].items()]
    lines+=['','## Coverage','','| Track | Case | State | Explanation |','| --- | --- | --- | --- |']
    for c in manifest['cases']:
        r=next((r for r in results if r['case_id']==c['id']),None)
        lines.append(f"| {c['track']} | {escape(c['id'])} | {r['status'] if r else 'pending'} | {escape(r['reason']) if r else 'Not completed'} |")
    lines+=['','## Detection accounting','',
        'Warnings, confirmed detections, prevention and successful cleanup are distinct. Classification feature benchmarks are not live protection tests. Unavailable and partial inspections remain visible.']
    lines+=['','### Feature classification','','| Case | Scope | Malicious flagged | Malicious missed | Benign false alarms | 95% FPR upper bound |','| --- | --- | --- | --- | --- | --- |']
    for r in results:
        m=(r.get('observation') or {}).get('measurements',{})
        if 'true_positives' in m:
            recall=100*m['true_positives']/m['malware'] if m['malware'] else 0
            fpr=100*m['false_positives']/m['benign'] if m['benign'] else 0
            lines.append(f"| {escape(r['case_id'])} | {'Qualification' if m.get('untouched_holdout') else 'Regression'} | {m['true_positives']}/{m['malware']} ({recall:.2f}%) | {m['malware']-m['true_positives']} | {m['false_positives']}/{m['benign']} ({fpr:.2f}%) | {100*m.get('fpr_upper_95',1):.3f}% |")
    for mode in ('signature_free','normal'):
        selected=[r for r in samples if r['mode']==mode]
        if selected:lines+=['',f'### {mode}', '', '```json',json.dumps(detection_metrics(selected),indent=2),'```']
    lines+=['','## Evidence limitations','',
        '- Offline guests cannot measure internet-dependent behavior. Sandbox does not establish reboot persistence or Windows-equivalent emulation.',
        '- Guest observations are not externally attested; integrity hashes do not prove uncompromised collection.',
        '- Full guest journals are bounded and destroyed on disposal; exported summaries disclose truncation.',
        '- A missing corpus, VM, telemetry source or mandatory safety track blocks qualification.',
        '- Previously viewed feature rows are regression data, not untouched holdouts.',
        '', '## What’s next','', 'Investigate priority 0/1 failures first, then provide missing independent evidence. Do not tune on the final holdout.']
    from .comparison import previous
    comparison=previous(store)
    lines+=['','## Compatible-run comparison','','```json',json.dumps(comparison,indent=2),'```']
    write_json(store.path/'comparison.json',comparison,True)
    _text(store.path/'report.md','\n'.join(lines)+'\n')
    write_json(store.path/'results.json',dict(schema=1,summary=summary,results=results),True,64*1024*1024)
    write_json(store.path/'failure-backlog.json',backlog,True)
    write_json(store.path/'telemetry-health.json',health,True)
    for name,rows in [('errors.jsonl',errors),('telemetry-summary.jsonl',telemetry),('missed-malware.jsonl',[r for r in samples if r['label']=='malware' and not r.get('confirmed')]),('false-alarms.jsonl',[r for r in samples if r['label']=='benign' and (r.get('review') or r.get('confirmed') or r.get('false_action'))])]:
        _text(store.path/name,''.join(json.dumps(r,allow_nan=False)+'\n' for r in rows))
    feature_misses=[];feature_false=[]
    for r in results:
        m=(r.get('observation') or {}).get('measurements',{})
        feature_misses.extend(dict(case_id=r['case_id'],**v) for v in m.get('missed_examples',[]))
        feature_false.extend(dict(case_id=r['case_id'],**v) for v in m.get('false_alarm_examples',[]))
    _text(store.path/'feature-misses.jsonl',''.join(json.dumps(r)+'\n' for r in feature_misses))
    _text(store.path/'feature-false-alarms.jsonl',''.join(json.dumps(r)+'\n' for r in feature_false))
    out=io.StringIO(newline='');columns=('sha256','label','mode','available','coverage_complete','confirmed','review','model_score','neural_score','family','versions_digest')
    writer=csv.DictWriter(out,fieldnames=columns,extrasaction='ignore');writer.writeheader()
    for r in samples:
        writer.writerow({k:(_csv(v)) for k,v in r.items() if k in columns})
    _text(store.path/'samples.csv',out.getvalue())
    for track,rs in grouped.items():
        _text(store.path/('track-'+track+'.md'),'# '+track+'\n\n'+'\n'.join(f"- {escape(r['case_id'])}: **{r['status']}** — {escape(r['reason'])}" for r in rs)+'\n')
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in store.path.iterdir() if p.is_file() and p.suffix in ('.md','.json','.jsonl','.csv') and p.name!='hashes.json'}
    write_json(store.path/'hashes.json',dict(schema=1,sha256=hashes),True)
    return summary


def _csv(value):
    """Prefix a value with a quote if a spreadsheet might treat it as a formula."""
    value=str(value)
    return "'"+value if value.lstrip(' \t\r\n\ufeff').startswith(('=','+','-','@')) or value.startswith(('\t','\r')) else value


def _text(path,text):
    """Write a text file atomically (temp file plus rename), within a 64 MB budget."""
    from pathlib import Path
    import os,uuid
    if len(text.encode())>64*1024*1024:raise ValueError('Rendered report exceeds budget')
    tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp');tmp.write_text(text,encoding='utf-8');os.replace(tmp,path)

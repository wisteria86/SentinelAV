# Purpose: Read-only manifest evaluation. Sample contents are never executed or extracted.
# Works with: detection.inspection, paths
# Used by: entrypoint, lab.qualification.guest, lab.qualification.guest_context, lab.runtime_job

"""Read-only manifest evaluation. Sample contents are never executed or extracted."""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import subprocess
import time
import zipfile
from io import BytesIO

from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.paths import RESOURCE_ROOT

MAX_FILES=64
MAX_BYTES=8*1024*1024


def fingerprint(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        if before.st_size>MAX_BYTES:
            raise ValueError('Above 8 MiB evaluation limit')
        total=0
        while chunk:=stream.read(1024*1024):
            total+=len(chunk)
            if total>MAX_BYTES: raise ValueError('File grew above evaluation limit')
            digest.update(chunk)
        after=os.fstat(stream.fileno())
    current=path.stat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    if identity(before)!=identity(after) or identity(after)!=identity(current):
        raise ValueError('File changed during fingerprinting')
    return digest.hexdigest()


def unlinked(path):
    if any(p.is_symlink() or p.is_junction() for p in (path,*path.parents)):
        raise ValueError('Linked input/output path refused')


def load_manifest(path,max_files=MAX_FILES):
    path=Path(path).absolute()
    unlinked(path)
    if path.stat().st_size>max_files*2048: raise ValueError('Manifest too large')
    raw=path.read_bytes()
    data=json.loads(raw)
    if data.get('schema')!=1 or not isinstance(data.get('files'),list) or not 1<=len(data['files'])<=max_files:
        raise ValueError('Expected schema 1 and bounded explicit files')
    seen=set()
    for entry in data['files']:
        name=entry.get('path','')
        if not isinstance(name,str) or not name or len(name)>240 or ':' in name or '\\' in name:
            raise ValueError('Use relative forward-slash paths without drive/stream names')
        parts=name.split('/')
        if any(p in ('','.','..') or p.endswith((' ','.')) for p in parts):
            raise ValueError('Ambiguous/escaping sample path')
        if name.casefold() in seen: raise ValueError('Duplicate sample path')
        seen.add(name.casefold())
        sha=entry.get('sha256')
        if not isinstance(sha,str) or len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha):
            raise ValueError('Expected lowercase SHA-256 for every file')
        if entry.get('label') not in ('malware','benign','test','unknown') or not isinstance(entry.get('provenance'),str) or not entry['provenance'].strip():
            raise ValueError('Each file needs an explicit label and provenance')
        target=path.parent.joinpath(*parts)
        unlinked(target)
        if not target.resolve().is_relative_to(path.parent.resolve()): raise ValueError('Sample escapes corpus')
    return data,hashlib.sha256(raw).hexdigest()


def verified_offline_guest():
    if os.name!='nt' or os.environ.get('USERNAME')!='WDAGUtilityAccount': return False
    code="$ErrorActionPreference='Stop'; if((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine'){exit 1}; if(@(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 2}; exit 0"
    try:
        return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',code],
                              capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW).returncode==0
    except (OSError,subprocess.TimeoutExpired): return False


def evaluate(manifest,scanner_factory=IsolatedScanner,options=None,signature_path=None,batch_offset=None):
    manifest=Path(manifest).absolute()
    data,manifest_hash=load_manifest(manifest,10000 if batch_offset is not None else MAX_FILES)
    # No unsafe-content hash reads on the host. Test/benign labels are caller
    # assertions, not a mechanism for proving an arbitrary file is harmless.
    if any(e['label'] in ('malware','unknown') for e in data['files']) and not verified_offline_guest():
        raise ValueError('Malware/unknown corpus evaluation requires the offline test guest')
    started=time.monotonic()
    strict=bool((options or {}).get('signature_free'))
    files=data['files'];duplicates=0
    if batch_offset is not None:
        if type(batch_offset) is not int or batch_offset<0:raise ValueError('Invalid batch offset')
        unique={}
        for entry in files:
            if entry['sha256'] in unique and unique[entry['sha256']]['label']!=entry['label']:raise ValueError('Conflicting labels for one sample identity')
            unique.setdefault(entry['sha256'],entry)
        duplicates=len(files)-len(unique);files=list(unique.values())
        if batch_offset>=len(files):raise ValueError('Batch offset exceeds unique sample count')
        files=files[batch_offset:batch_offset+MAX_FILES]
    rows=[]
    for entry in files:
        path=manifest.parent/entry['path']
        row={**entry,'outcome':'unavailable','coverage_complete':False}
        scanner=None
        began=time.monotonic()
        try:
            if began-started>(len(files)*65+30 if strict else 600): raise TimeoutError('Evaluation exceeded its bounded run budget')
            unlinked(path)
            if fingerprint(path)!=entry['sha256']: raise ValueError('Manifest SHA-256 mismatch')
            scanner=scanner_factory(signature_path or RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',max_mb=8,
                                    options={**(options or {}),'amsi':False})
            row['definitions']=dict(count=len(scanner.signatures),metadata=scanner.signatures.metadata)
            row['yara']=scanner.rule_summary
            result=scanner.scan([path],lambda:False,lambda *a:None)
            row['scan']=result
            row['candidate_model']=result.get('advanced_analysis',{}).get('coverage',{}).get('model',dict(status='Unavailable'))
            row['candidate_neural']=result.get('advanced_analysis',{}).get('coverage',{}).get('neural',dict(status='Disabled'))
            if strict:
                policy=result.get('signature_policy',{})
                if policy.get('signature_free') is not True or any(policy.get(key) is not False for key in ('hashes','yara','test_markers','amsi','reputation')):
                    raise ValueError('Worker did not attest a fully signature-free scan')
                if len(scanner.signatures)!=0 or row['yara'].get('status')!='Disabled':raise ValueError('Saved signatures remain loaded')
                for finding in result.get('detections',[]):
                    evidence=finding.get('analysis_evidence',[])
                    if not evidence or any(e.get('source')!='fusion' for e in evidence):raise ValueError('Non-independent detection in signature-free evaluation')
            unchanged=fingerprint(path)==entry['sha256']
            findings=result.get('detections',[])
            if not unchanged or any(d.get('sha256')!=entry['sha256'] for d in findings):
                raise ValueError('Sample changed or finding identity differs')
            complete=result.get('status')=='Complete' and result.get('scanned')==1 and not result.get('errors') and not result.get('skipped') and row['yara'].get('status')==('Disabled' if strict else 'Compiled')
            if strict and result.get('file_format',{}).get('format')!='PE':
                complete=False
                row['independent_scope']='Independent classifier coverage unavailable for this format; not a clean result'
            row.update(coverage_complete=complete,postcheck_unchanged=True,
                       outcome=('detected' if complete else 'detected_incomplete') if findings else ('not_detected' if complete else 'unavailable'))
        except Exception as error:
            row['error']=str(error)
        finally:
            if scanner is not None: scanner.close()
        row['seconds']=round(time.monotonic()-began,4)
        rows.append(row)
    summary={label:{outcome:sum(r['label']==label and r['outcome']==outcome for r in rows)
                    for outcome in ('detected','not_detected','detected_incomplete','unavailable')}
             for label in ('malware','benign','test','unknown')}
    return dict(schema=1,created_utc=datetime.now(timezone.utc).isoformat(),manifest_sha256=manifest_hash,
                status='Complete' if all(r['coverage_complete'] for r in rows) else 'Incomplete / review omissions',
                seconds=round(time.monotonic()-started,4),rows=rows,summary=summary,
                sample_execution=False,sample_extraction=False,response_actions=False,
                signature_free=strict,
                batch_offset=batch_offset,duplicates_excluded=duplicates,batch_sample_count=len(files),
                limitations=['Labels and provenance are caller assertions, not independently verified ground truth.',
                             'Read-only static/content inspection with the selected options; no behavioral protection rate is measured.',
                             'Unavailable results and partial detections are never counted as clean.',
                             'Worker job limits provide fault/resource isolation, not a security boundary.',
                             'No representative detection-rate claim can be made from a small selected corpus.'])


def create_demo(root):
    """Generate only inert fixtures, never malware or executable test payloads."""
    root=Path(root).absolute()
    unlinked(root)
    root.mkdir(parents=True,exist_ok=False)
    marker=b'SENTINELAV_DEMO_THREAT_7C23A'
    nested=BytesIO()
    with zipfile.ZipFile(nested,'w') as archive: archive.writestr('marker.txt',marker)
    outer=BytesIO()
    with zipfile.ZipFile(outer,'w') as archive: archive.writestr('inner.zip',nested.getvalue())
    fixtures={'ordinary.txt':b'Ordinary generated evaluation document.',
              'renamed.bin':marker,'utf16.txt':marker.decode().encode('utf-16-le'),
              'nested.zip':outer.getvalue(),'unsupported.7z':b'7z\xbc\xaf\x27\x1cHarmless unsupported-format fixture'}
    entries=[]
    for name,content in fixtures.items():
        (root/name).write_bytes(content)
        entries.append(dict(path=name,sha256=hashlib.sha256(content).hexdigest(),label='test',
                            provenance='Generated inert SentinelAV evaluation fixture'))
    manifest=root/'manifest.json'
    manifest.write_text(json.dumps(dict(schema=1,files=entries),indent=2),encoding='utf-8')
    return manifest


def render(report):
    esc=lambda v:html.escape(str(v),quote=True)
    rows=''.join('<tr>'+''.join('<td>'+esc(r.get(k,''))+'</td>' for k in ('path','label','outcome','seconds','error'))+'</tr>' for r in report['rows'])
    return ('<!doctype html><meta charset="utf-8"><title>SentinelAV static evaluation</title>'
            '<style>body{font:15px Segoe UI;background:#fff8ee;color:#302217;margin:32px}td,th{padding:10px;border:1px solid #dbcbb7}table{border-collapse:collapse}</style>'
            '<h1>SentinelAV static evaluation</h1><p>'+esc(report['status'])+'</p>'
            '<table><tr><th>File</th><th>Declared label</th><th>Outcome</th><th>Seconds</th><th>Error</th></tr>'+rows+'</table><ul>'
            +''.join('<li>'+esc(v)+'</li>' for v in report['limitations'])+'</ul>')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest',type=Path)
    parser.add_argument('--output',required=True,type=Path,help='New report directory, outside the corpus')
    parser.add_argument('--signature-free',action='store_true',help='Disable saved hashes, YARA, reputation, AMSI and test markers')
    parser.add_argument('--batch-offset',type=int,help='Evaluate at most 64 unique samples from a frozen manifest of up to 10000')
    args=parser.parse_args(argv)
    output=args.output.absolute()
    unlinked(output)
    corpus=args.manifest.absolute().parent.resolve()
    if output.resolve().is_relative_to(corpus) or corpus.is_relative_to(output.resolve()):
        parser.error('Report directory and corpus must be separate')
    output.mkdir(parents=True,exist_ok=False)
    report=evaluate(args.manifest,options=dict(signature_free=True,advanced=True,emulation=True,model=True,neural=True,emulation_profile='lab') if args.signature_free else None,batch_offset=args.batch_offset)
    (output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (output/'report.html').write_text(render(report),encoding='utf-8')
    return 0 if report['status']=='Complete' else 2

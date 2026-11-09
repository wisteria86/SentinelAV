# Purpose: Collect existing scan features and fit an offline review-only baseline.
# Works with: detection.anomaly_model
# Used by: tests.unit.test_anomaly_model

"""Collect existing scan features and fit an offline review-only baseline.

No sample acquisition, sample execution, pickle loading or active-model changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
from sentinelav.detection.anomaly_model import fit_evaluate,validate


def read_json(path):
    with Path(path).open('rb') as stream:
        raw=stream.read(32*1024*1024+1)
    if len(raw)>32*1024*1024: raise ValueError('JSON exceeds 32 MiB limit')
    return json.loads(raw)


def collect(report,assignments):
    """Labels come from reviewed assignments, never scanner detections."""
    if assignments.get('schema')!=1 or not isinstance(assignments.get('samples'),dict):
        raise ValueError('Expected schema 1 assignments with samples keyed by SHA-256')
    rows=[]
    omissions=[]
    for item in report.get('files',report.get('rows',[])):
        scan=item.get('scan',{})
        identity=scan.get('file_identity',{})
        sha=identity.get('sha256',item.get('sha256'))
        annotation=assignments['samples'].get(sha)
        if annotation is None:
            omissions.append(dict(sha256=sha,reason='No reviewed split/label assignment'))
            continue
        analysis=scan.get('static_analysis',{})
        if (scan.get('status')!='Complete' or scan.get('errors') or scan.get('skipped') or
            not identity.get('sha256') or item.get('sha256')!=identity.get('sha256') or
            not item.get('postcheck_unchanged',False) or not item.get('coverage_complete',False) or
            scan.get('file_format',{}).get('format')!='PE' or not analysis.get('features')):
            omissions.append(dict(sha256=sha,reason='Incomplete, unsupported, or missing versioned PE features'))
            continue
        rows.append(dict(sha256=sha,label=annotation.get('label'),group=annotation.get('group'),
            split=annotation.get('split'),provenance=annotation.get('provenance'),
            method=analysis.get('method'),format='PE',features=analysis['features']))
    if rows: validate(rows)
    return dict(schema=1,rows=rows,omissions=omissions)


def write_new(path,data):
    # Exclusive creation preserves frozen datasets and prior evidence.
    with Path(path).open('x',encoding='utf-8') as stream:
        json.dump(data,stream,indent=2,allow_nan=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    gather=sub.add_parser('collect')
    gather.add_argument('report')
    gather.add_argument('assignments')
    gather.add_argument('--output',required=True)
    fit=sub.add_parser('fit')
    fit.add_argument('dataset')
    fit.add_argument('--output',required=True,help='New directory for model and evaluation JSON')
    fit.add_argument('--target-fpr',type=float,default=.01)
    args=parser.parse_args()
    if args.command=='collect':
        dataset=collect(read_json(args.report),read_json(args.assignments))
        dataset['source_report_sha256']=hashlib.sha256(Path(args.report).read_bytes()).hexdigest()
        dataset['assignments_sha256']=hashlib.sha256(Path(args.assignments).read_bytes()).hexdigest()
        write_new(args.output,dataset)
        print(f"Collected {len(dataset['rows'])} rows; {len(dataset['omissions'])} omissions retained.")
    else:
        dataset=read_json(args.dataset)
        if dataset.get('schema')!=1: raise ValueError('Unsupported dataset schema')
        model,evaluation=fit_evaluate(dataset['rows'],args.target_fpr)
        evaluation['dataset_sha256']=hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest()
        evaluation['collection_omissions']=dataset.get('omissions',[])
        target=Path(args.output)
        target.mkdir(parents=True,exist_ok=False)
        write_new(target/'model.json',model)
        write_new(target/'evaluation.json',evaluation)
        print(json.dumps(evaluation['metrics'],indent=2))
        print('Offline research model only; active scanner policy unchanged.')


if __name__=='__main__': main()

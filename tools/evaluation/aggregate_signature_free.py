# Purpose: Aggregate bounded guest reports; reads metadata only, never specimen contents.
# Works with: lab.corpus_evaluation, updates.artifacts, workspace
# Used by: tests.unit.test_signature_free_aggregation

"""Aggregate bounded guest reports; reads metadata only, never specimen contents."""
import argparse
import json
from pathlib import Path
from sentinelav.lab.corpus_evaluation import load_manifest
from sentinelav.updates.artifacts import bounded_json
from sentinelav.workspace import Workspace


def aggregate(manifest,reports):
    data,digest=load_manifest(manifest,10000);expected={}
    for entry in data['files']:
        sha=entry['sha256']
        if sha in expected and expected[sha]['label']!=entry['label']:raise ValueError('Conflicting labels')
        expected.setdefault(sha,entry)
    if not 1<=len(reports)<=(len(expected)+63)//64:raise ValueError('Unexpected report count')
    seen={};engines=set();models={}
    for report in reports:
        if report.get('manifest_sha256')!=digest or report.get('signature_free') is not True:raise ValueError('Mixed manifest or evaluation modes')
        if report.get('sample_execution') is not False or report.get('response_actions') is not False:raise ValueError('Unexpected evaluation side effects')
        for row in report['rows']:
            sha=row['sha256']
            if sha not in expected or sha in seen:raise ValueError('Unknown or duplicate measured sample')
            if row['label']!=expected[sha]['label'] or row['path']!=expected[sha]['path']:raise ValueError('Sample identity/label mismatch')
            if row['outcome'] not in ('detected','detected_incomplete','not_detected','unavailable'):raise ValueError('Unknown outcome')
            scan=row.get('scan')
            if scan:
                policy=scan.get('signature_policy',{})
                if policy.get('signature_free') is not True or any(policy.get(key) is not False for key in ('hashes','yara','test_markers','amsi','reputation')):raise ValueError('Contaminated or unattested worker')
                if row['definitions']['count']!=0 or row['yara']['status']!='Disabled':raise ValueError('Saved signatures were loaded')
                engine=scan.get('analysis_result',{}).get('versions',{}).get('engine')
                if not engine:raise ValueError('Engine version unavailable')
                engines.add(engine)
                candidate=row.get('candidate_model',{})
                if candidate.get('model_id'):
                    kind=scan.get('file_format',{}).get('format','Unknown')
                    models.setdefault(kind,set()).add(candidate['model_id'])
            elif row['outcome']!='unavailable':raise ValueError('Missing scan evidence')
            if row['outcome']=='detected' and not row.get('coverage_complete'):raise ValueError('Partial detection counted as complete')
            seen[sha]=row
    if len(engines)>1 or any(len(ids)>1 for ids in models.values()):raise ValueError('Mixed engine/model versions; run separately')
    groups={}
    for label in ('malware','benign','test','unknown'):
        identities=[sha for sha,e in expected.items() if e['label']==label]
        rows=[seen[sha] for sha in identities if sha in seen]
        groups[label]=dict(total=len(identities),measured=len(rows),missing=len(identities)-len(rows),
            outcomes={kind:sum(r['outcome']==kind for r in rows) for kind in ('detected','detected_incomplete','not_detected','unavailable')},
            model_candidate_positives=sum(r.get('candidate_model',{}).get('review') is True for r in rows))
    return dict(schema=1,kind='SignatureFreeAggregate',manifest_sha256=digest,unique_samples=len(expected),
        measured=len(seen),missing=sorted(set(expected)-set(seen)),groups=groups,
        complete=len(seen)==len(expected) and all(r.get('coverage_complete') for r in seen.values()),
        engine_versions=sorted(engines),model_versions={k:sorted(v) for k,v in models.items()},
        sample_contents_read=False,superiority_established=False,
        limitation='Guest/caller-supplied labels and reports require audit. Candidates and unavailable/partial results are not validated detections or clean results.')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',required=True,type=Path)
    parser.add_argument('--reports',required=True,nargs='+',type=Path);args=parser.parse_args()
    result=aggregate(args.manifest,[bounded_json(path,64*1024*1024) for path in args.reports])
    print(Workspace().immutable_report(result,'signature-free-aggregate'))


if __name__=='__main__':main()

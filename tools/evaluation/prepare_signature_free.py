# Purpose: Prepare metadata-only signature-free evaluation readiness; never opens samples.
# Works with: detection.fusion, lab.corpus_evaluation, paths, updates.artifacts, workspace
# Used by: the Python module loader or CLI entry point

"""Prepare metadata-only signature-free evaluation readiness; never opens samples."""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.workspace import Workspace
from sentinelav.lab.corpus_evaluation import load_manifest


def readiness(manifest=None):
    dependencies={name:importlib.util.find_spec(name) is not None for name in ('speakeasy','unicorn','thrember','lightgbm')}
    blockers=[];models={}
    from sentinelav.updates.artifacts import active
    try:
        model,meta=active(RESOURCE_ROOT/'analysis-data',RESOURCE_ROOT/'trusted-update-keys.json','model')
        models=dict(algorithm=model['algorithm'],formats=model.get('formats',[]),revision=meta['revision'],
            validated=model.get('validated',False),validation=model.get('validation',{}))
    except Exception as error:blockers.append('No usable signed local model: '+str(error))
    if not all(dependencies.values()):blockers.append('Missing analysis dependencies')
    if not models.get('validated'):blockers.append('Independent model release validation has not passed')
    if set(models.get('formats',[]))!={'Win32','Win64','Dot_Net'}:blockers.append('Validated model coverage for all Windows PE classes is unavailable')
    try:
        from sentinelav.detection.fusion import gates
        policy,_=active(RESOURCE_ROOT/'analysis-data',RESOURCE_ROOT/'trusted-update-keys.json','policy')
        if not gates(policy)['review']:blockers.append('Signed independent decision policy has not passed its release gate')
    except Exception as error:blockers.append('No usable signed independent decision policy: '+str(error))
    plan=None
    if manifest:
        data,digest=load_manifest(manifest,10000);unique={}
        for entry in data['files']:
            if entry['sha256'] in unique and unique[entry['sha256']]['label']!=entry['label']:raise ValueError('Conflicting sample labels')
            unique.setdefault(entry['sha256'],entry)
        plan=dict(manifest_sha256=digest,manifest=str(Path(manifest).absolute()),total_entries=len(data['files']),
            unique_samples=len(unique),duplicate_entries=len(data['files'])-len(unique),
            batches=[dict(offset=i,count=min(64,len(unique)-i)) for i in range(0,len(unique),64)])
        if not isinstance(data.get('source_revision'),str) or not re.fullmatch('[0-9a-f]{40}',data['source_revision']):blockers.append('Corpus source revision is not frozen')
    else:blockers.append('A full pinned corpus manifest has not been supplied; historical pilot samples are insufficient')
    return dict(schema=1,kind='SignatureFreeReadiness',dependencies=dependencies,model=models,
        production_detection_ready=not blockers,blockers=blockers,plan=plan,
        disabled=['hash matching','YARA','AMSI','reputation feeds','EICAR/demo marker matching','hash allowlists'],
        sample_contents_read=False,samples_downloaded=False,sample_execution=False,response_actions=False,
        limitations=['Only metadata and dependency/artifact availability checked; no efficacy established.',
            'Model candidate scores are separate from release-gated detections.',
            'Whole-repository coverage requires a pinned, inventoried manifest; fixed historical pilots are not the full Zoo.',
            'Raw corpus measurement is restricted to the offline guest; only static/content/virtual emulation is measured.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path);args=parser.parse_args()
    report=readiness(args.manifest);path=Workspace().immutable_report(report,'signature-free-readiness')
    print(json.dumps(dict(report=str(path),production_detection_ready=report['production_detection_ready'],blockers=report['blockers']),indent=2))


if __name__=='__main__':main()

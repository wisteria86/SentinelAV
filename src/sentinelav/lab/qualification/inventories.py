# Purpose: Approved metadata inventories. Never opens specimen plaintext on the host.
# Works with: detection.pe_classifier, detection.pe_ensemble, lab.qualification.contracts,
#   lab.qualification.scoring, paths
# Used by: lab.qualification.runner

"""Approved metadata inventories. Never opens specimen plaintext on the host."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
from .contracts import identifier,digest
from sentinelav.workspace import unlinked


def load_inventory(work,name):
    """Load an approved evaluation inventory by name, checking it has approval, a reviewer, provenance
    and a role.
    """
    identifier(name);root=unlinked(Path(work)/'lab/qualification/inventories');path=unlinked(root/(name+'.json'))
    if not path.exists():raise FileNotFoundError('Approved inventory required: '+str(path))
    if path.stat().st_size>32*1024*1024:raise ValueError('Inventory metadata exceeds 32 MiB')
    data=json.loads(path.read_text(encoding='utf-8-sig'))
    if data.get('schema')!=1 or data.get('approved') is not True or not data.get('provenance') or not data.get('reviewer'):
        raise ValueError('Inventory needs explicit approval, reviewer and provenance')
    if data.get('role') not in ('qualification','regression','training','development','calibration'):raise ValueError('Inventory role missing')
    return data


def frozen(work):
    """Return {name: {hash, role}} for every inventory, so a run records exactly which ones it used.
    """
    root=Path(work)/'lab/qualification/inventories'
    result={}
    for path in root.glob('*.json'):
        data=load_inventory(work,path.stem);result[path.stem]=dict(sha256=digest(data),role=data['role'])
    return result


def feature_qualification(work,fmt,cancelled,progress,resource_root=None):
    """Score an untouched, time-separated holdout set for one PE format with the active model.

    Every row must be newer than the training cutoff, unseen in earlier datasets, and (if claimed)
    from families not used in training. Reports recall, false positives with a 95% upper bound, and
    per-week and per-family breakdowns.
    """
    from sentinelav.paths import RESOURCE_ROOT
    from sentinelav.detection.pe_classifier import extractor_class
    from sentinelav.detection.pe_ensemble import predict_vector
    from sentinelav.updates.artifacts import active
    from .scoring import upper_bound
    inv=load_inventory(work,'temporal-'+fmt)
    if inv['role']!='qualification' or inv.get('model_training_overlap')!='excluded':raise ValueError('Untouched qualification provenance required')
    if inv.get('untouched_holdout') is not True or inv.get('related_build_separation') is not True:raise ValueError('Reviewed untouched holdout and related-build separation required')
    path=unlinked(Path(inv['feature_rows']))
    if not path.is_relative_to(Path(work)/'datasets'):raise ValueError('Feature data must stay under F: managed datasets')
    h=hashlib.sha256()
    with path.open('rb') as source:
        while chunk:=source.read(1024*1024):h.update(chunk)
    if h.hexdigest()!=inv['feature_rows_sha256']:raise ValueError('Frozen feature inventory changed')
    consumed=set();training_families=set(inv.get('training_families',[]))
    for old in (Path(work)/'datasets').glob('prepared-*/rows.jsonl'):
        with old.open(encoding='utf-8') as stream:
            for line in stream:consumed.add(json.loads(line)['sha256'])
    resource_root=Path(resource_root) if resource_root else RESOURCE_ROOT
    model,meta=active(resource_root/'analysis-data',resource_root/'trusted-update-keys.json','model')
    extractor=extractor_class()();seen=set();mal=ben=tp=fp=0;misses=[];false=[];week={};family={}
    cutoff=datetime.fromisoformat(inv['training_cutoff'].replace('Z','+00:00'))
    with path.open(encoding='utf-8') as stream:
        for index,line in enumerate(stream):
            if len(line)>2*1024*1024:raise ValueError('Oversized feature row')
            if cancelled():raise InterruptedError('Qualification benchmark cancelled')
            row=json.loads(line);sha=row['sha256'];label=row['label']
            if sha in seen or sha in consumed or type(label) is not int or label not in (0,1) or row['file_type']!=fmt:raise ValueError('Consumed, duplicate or invalid qualification identity')
            date=datetime.fromisoformat(row['first_submission_date'].replace('Z','+00:00'))
            if date<=cutoff:raise ValueError('Temporal separation violated')
            if inv.get('family_disjoint') and (not row.get('family') or row['family'] in training_families):raise ValueError('Family-disjoint claim not supported')
            seen.add(sha);output=predict_vector(model,extractor.process_raw_features(row['features']),fmt);flag=output['review']
            mal+=label==1;ben+=label==0;tp+=label==1 and flag;fp+=label==0 and flag
            entry=dict(sha256=sha,label=label,score=output['model_score'],member_scores=output['member_scores'],family=row.get('family'),date=row['first_submission_date'])
            if label and not flag:misses.append(entry)
            if not label and flag:false.append(entry)
            for collection,key in ((week,date.strftime('%Y-%W')),(family,row.get('family','unattributed'))):
                metric=collection.setdefault(key,dict(malware=0,benign=0,true_positives=0,false_positives=0));metric['malware']+=label==1;metric['benign']+=label==0;metric['true_positives']+=label==1 and flag;metric['false_positives']+=label==0 and flag
            if index%100==0:progress(fmt+' qualification: '+str(index))
    return dict(benchmark_completed=bool(seen),format=fmt,benign=ben,malware=mal,true_positives=tp,false_positives=fp,
        recall=tp/mal if mal else None,fpr_upper_95=upper_bound(fp,ben),untouched_holdout=True,temporal_separation=True,
        family_disjoint=bool(inv.get('family_disjoint')),per_week=week,per_family=family,
        missed_examples=misses[:5000],false_alarm_examples=false[:5000],truncated=len(misses)>5000 or len(false)>5000,
        inventory_digest=digest(inv),model_id=output['model_id'] if seen else None,automatic_actions=False)

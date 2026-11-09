# Purpose: Offline benign-distance baseline. JSON only; never a malware verdict.
# Works with: sibling modules in detection
# Used by: detection.classifier, tests.unit.test_analysis_artifacts, tests.unit.test_anomaly_model,
#   tools.evaluation.calibrate_static

"""Offline benign-distance baseline. JSON only; never a malware verdict.

Training fits the location/scale. Independent benign calibration chooses an
empirical threshold. The test split is used only for final reported metrics.
"""
import math
import statistics

FEATURES=('entropy_bits','zero_fraction','log2_bytes','section_count',
          'max_section_entropy','writable_executable_fraction',
          'entrypoint_outside_sections','overlapping_section_pairs','trailing_fraction')


def validate(rows):
    if not isinstance(rows,list) or not 1<=len(rows)<=100000:
        raise ValueError('Expected 1..100000 feature rows')
    hashes=set()
    groups={}
    for row in rows:
        sha=row.get('sha256','')
        if len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha) or sha in hashes:
            raise ValueError('Invalid or duplicate sample hash')
        hashes.add(sha)
        group=row.get('group')
        split=row.get('split')
        if not isinstance(group,str) or not group.strip() or split not in ('train','calibration','test'):
            raise ValueError('Explicit related-family/build group and split required')
        if group in groups and groups[group]!=split:
            raise ValueError('Related group leaks across splits')
        groups[group]=split
        if row.get('label') not in ('benign','malware') or not row.get('provenance'):
            raise ValueError('Independent label and provenance required')
        if row.get('method')!='structural-analysis-v1' or row.get('format')!='PE':
            raise ValueError('This baseline accepts only version 1 PE features')
        if set(row.get('features',{}))!=set(FEATURES):
            raise ValueError('Feature schema mismatch')
        if any(type(row['features'][k]) not in (int,float) or not math.isfinite(row['features'][k]) for k in FEATURES):
            raise ValueError('Features must be finite numbers')


def score(model,features):
    contributions={}
    for key in FEATURES:
        value=features[key]
        if type(value) not in (int,float) or not math.isfinite(value):
            raise ValueError('Nonfinite feature')
        scale=model['scale'][key]
        deviation=abs(value-model['center'][key])
        # A constant training dimension has no fitted scale. Report novelty
        # separately; do not invent a weight or infinite anomaly distance.
        contributions[key]=deviation/scale if scale else 0.0
    distance=math.sqrt(sum(v*v for v in contributions.values())/len(FEATURES))
    return dict(distance=distance,contributions=contributions,
        constant_feature_novelty=[k for k in FEATURES if not model['scale'][k] and features[k]!=model['center'][k]],
        review=distance>model.get('threshold',math.inf),malware_probability=None,
        automatic_response_eligible=False)


def fit_evaluate(rows,target_fpr=0.01):
    validate(rows)
    if not 0<target_fpr<1: raise ValueError('Target false-positive fraction must be between 0 and 1')
    train=[r for r in rows if r['split']=='train' and r['label']=='benign']
    calibration=[r for r in rows if r['split']=='calibration' and r['label']=='benign']
    test=[r for r in rows if r['split']=='test']
    if len(train)<2 or len(calibration)<2 or not test:
        raise ValueError('Need at least two benign training/calibration rows and a frozen test split')
    model=dict(schema=1,algorithm='benign-standardized-distance-v1',feature_method='structural-analysis-v1',
        center={k:statistics.mean(r['features'][k] for r in train) for k in FEATURES},
        scale={k:statistics.pstdev(r['features'][k] for r in train) for k in FEATURES},
        target_calibration_fpr=target_fpr,calibration_resolution=1/len(calibration),
        training_hashes=[r['sha256'] for r in train],calibration_hashes=[r['sha256'] for r in calibration],
        automatic_response_eligible=False)
    distances=sorted(score(model,r['features'])['distance'] for r in calibration)
    model['threshold']=distances[max(0,math.ceil((1-target_fpr)*len(distances))-1)]
    predictions=[dict(sha256=r['sha256'],label=r['label'],**score(model,r['features'])) for r in test]
    metrics={}
    for label in ('benign','malware'):
        subset=[r for r in predictions if r['label']==label]
        flagged=sum(r['review'] for r in subset)
        metrics[label]=dict(total=len(subset),flagged_for_review=flagged,
            review_fraction=flagged/len(subset) if subset else None)
    return model,dict(metrics=metrics,predictions=predictions,
        warning='Anomaly review is not malware detection. Labels and group assignments require independent review. Small or unrepresentative corpora do not establish reliability.')

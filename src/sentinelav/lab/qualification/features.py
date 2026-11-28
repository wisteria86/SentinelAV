# Purpose: Read-only feature benchmarking. No model signing, activation or tuning.
# Works with: detection.pe_classifier, detection.pe_ensemble, lab.qualification.scoring, paths,
#   updates.artifacts
# Used by: lab.qualification.runner

"""Read-only feature benchmarking. No model signing, activation or tuning."""

import hashlib
import json
from pathlib import Path


def regression(work, cancelled, progress, resource_root=None):
    """Re-score the frozen 4,000-row .NET test set with the active model and report recall and false
    positives.

    This only measures; it never changes or signs a model.
    """
    from sentinelav.detection.pe_classifier import extractor_class
    from sentinelav.detection.pe_ensemble import predict_vector
    from sentinelav.updates.artifacts import active
    from sentinelav.paths import RESOURCE_ROOT
    from .scoring import upper_bound

    candidates = []
    for folder in (work / 'datasets').glob('prepared-Dot_Net-*'):
        path = folder / 'rows.jsonl'
        meta = folder / 'manifest.json'
        if (
            path.is_file()
            and meta.is_file()
            and json.loads(meta.read_text()).get('published_model')
        ):
            candidates.append(path)
    if len(candidates) != 1:
        raise FileNotFoundError(
            'Exactly one frozen published-model .NET regression inventory required'
        )
    resource_root = Path(resource_root) if resource_root else RESOURCE_ROOT
    path = candidates[0]
    model, manifest = active(
        resource_root / 'analysis-data', resource_root / 'trusted-update-keys.json', 'model'
    )
    extractor = extractor_class()()
    seen = set()
    tp = 0
    fp = 0
    mal = 0
    ben = 0
    misses = []
    false = []
    batches = {}
    records = [json.loads(line) for line in path.open(encoding='utf-8')]
    selected = [r for r in records if r['split'] == 'test']
    if len(selected) != 4000:
        raise ValueError('Previously examined 4,000-row regression set differs')
    thresholds = model.get('review_thresholds', {})
    for index, row in enumerate(selected):
        if cancelled():
            raise InterruptedError('Benchmark cancelled')
        sha = row['sha256']
        if sha in seen or row['label'] not in (0, 1):
            raise ValueError('Duplicate/invalid benchmark identity')
        seen.add(sha)
        kind = row['file_type']
        out = predict_vector(model, extractor.process_raw_features(row['features']), kind)
        flag = out['review']
        label = row['label']
        mal += label == 1
        ben += label == 0
        tp += label == 1 and flag
        fp += label == 0 and flag
        entry = dict(
            sha256=sha,
            label=label,
            score=out['model_score'],
            member_scores=out['member_scores'],
            file_type=kind,
        )
        if label and not flag:
            misses.append(entry)
        if not label and flag:
            false.append(entry)
        if index % 100 == 0:
            progress(f'Feature regression {index}/{len(selected)}')
    return dict(
        benchmark_completed=True,
        format='Dot_Net',
        malware=mal,
        benign=ben,
        true_positives=tp,
        false_positives=fp,
        recall=tp / mal if mal else None,
        fpr_upper_95=upper_bound(fp, ben),
        missed_examples=misses,
        false_alarm_examples=false,
        thresholds=thresholds,
        model_id=out['model_id'],
        dataset_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        untouched_holdout=False,
        temporal_separation=True,
        automatic_actions=False,
        regression_only=True,
    )

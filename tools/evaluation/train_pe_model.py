# Purpose: Train local native-text models from declared, nonexecutable feature rows.
# Works with: detection.helpers.pe_classifier, workspace
# Used by: the Python module loader or CLI entry point

"""Train local native-text models from declared, nonexecutable feature rows."""

import argparse
import hashlib
import json
from pathlib import Path
import math
from sentinelav.detection.helpers.pe_classifier import FEATURE_REVISION, validate
from sentinelav.workspace import Workspace, unlinked


def train(path, maximum=60000):
    import numpy as np
    import lightgbm as lgb
    from sklearn.linear_model import LogisticRegression
    from scipy.stats import beta
    from thrember.features import PEFeatureExtractor

    extractor = PEFeatureExtractor()
    groups = {}
    hashes = set()
    sets = {s: [] for s in ('train', 'calibration', 'test')}
    formats = set()
    provenance = hashlib.sha256()
    with unlinked(path).open('rb') as stream:
        for raw in stream:
            provenance.update(raw)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError('Feature row too large')
            row = json.loads(raw)
            split = row.get('split')
            sha = row.get('sha256')
            group = row.get('group')
            if (
                split not in sets
                or not isinstance(sha, str)
                or len(sha) != 64
                or any(c not in '0123456789abcdef' for c in sha)
            ):
                raise ValueError('Explicit split and lowercase SHA-256 required')
            if sha in hashes or not isinstance(group, str) or not group:
                raise ValueError('Duplicate identity or missing related-build group')
            if group in groups and groups[group] != split:
                raise ValueError('Related group crosses dataset splits')
            if not row.get('provenance') or row.get('label') not in (0, 1):
                raise ValueError('Independent label/provenance required')
            groups[group] = split
            hashes.add(sha)
            if row.get('file_type') not in ('Win32', 'Win64', 'Dot_Net'):
                raise ValueError('Explicit supported file_type required')
            formats.add(row['file_type'])
            if len(sets[split]) >= maximum:
                raise ValueError('Training/evaluation row budget exceeded')
            vector = extractor.process_raw_features(row['features'])
            if not np.isfinite(vector).all():
                raise ValueError('Nonfinite features')
            # Vectors plus stacked arrays coexist until training starts. Reserve
            # additional memory for LightGBM bins and calibration work arrays.
            if (len(hashes) * int(vector.nbytes) * 3) > 2 * 1024**3:
                raise ValueError(
                    'In-memory feature budget exceeded; prepare a smaller independent subset'
                )
            sets[split].append((vector, row['label'], sha))
    if any(len({row[1] for row in rows}) != 2 for rows in sets.values()):
        raise ValueError('Each independent split requires both classes')
    arrays = {
        key: (np.vstack([r[0] for r in rows]), np.array([r[1] for r in rows]))
        for key, rows in sets.items()
    }
    classifier = lgb.LGBMClassifier(
        n_estimators=300, num_leaves=31, learning_rate=0.05, n_jobs=4, random_state=23, verbosity=-1
    )
    classifier.fit(*arrays['train'])

    def logit(scores):
        return np.log(
            np.clip(scores, 1e-12, 1 - 1e-12) / (1 - np.clip(scores, 1e-12, 1 - 1e-12))
        ).reshape(-1, 1)

    cal_score = classifier.predict_proba(arrays['calibration'][0])[:, 1]
    calibrator = LogisticRegression(random_state=23).fit(logit(cal_score), arrays['calibration'][1])
    cal = calibrator.predict_proba(logit(cal_score))[:, 1]
    threshold = float(
        np.nextafter(np.quantile(cal[arrays['calibration'][1] == 0], 0.999, method='higher'), 1.0)
    )
    threshold = min(1, threshold)
    score = calibrator.predict_proba(logit(classifier.predict_proba(arrays['test'][0])[:, 1]))[:, 1]
    labels = arrays['test'][1]
    predicted = score >= threshold
    benign = int(sum(labels == 0))
    malware = int(sum(labels == 1))
    fp = int(sum(predicted & (labels == 0)))
    tp = int(sum(predicted & (labels == 1)))
    upper = float(beta.ppf(0.95, fp + 1, benign - fp)) if fp < benign else 1.0
    validation = dict(
        test_benign=benign,
        test_malware=malware,
        false_positives=fp,
        true_positives=tp,
        fpr_upper_95=upper,
        recall=tp / malware,
        review_gate_passed=upper <= 0.001 and tp / malware >= 0.9,
        automatic_action_gate_passed=False,
        independent_family_evaluation=False,
    )
    text = classifier.booster_.model_to_string()
    model = dict(
        schema=2,
        algorithm='lightgbm-pe-v1',
        extractor='ember2024-v3',
        extractor_revision=FEATURE_REVISION,
        feature_count=extractor.dim,
        formats=sorted(formats),
        model_text=text,
        model_sha256=hashlib.sha256(text.encode()).hexdigest(),
        review_threshold=threshold,
        calibration=dict(
            method='platt', a=float(calibrator.coef_[0, 0]), b=float(calibrator.intercept_[0])
        ),
        dataset_sha256=provenance.hexdigest(),
        validation=validation,
        validated=False,
        split_identity_sha256={
            key: hashlib.sha256(''.join(r[2] for r in rows).encode()).hexdigest()
            for key, rows in sets.items()
        },
    )
    validate(model)
    return model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    model = train(args.dataset)
    output = (
        unlinked(args.output)
        if args.output
        else Workspace().run('models', 'pe-classifier') / 'model.json'
    )
    with output.open('x', encoding='utf-8') as stream:
        json.dump(model, stream, allow_nan=False)
    print(
        json.dumps(
            dict(output=str(output), validation=model['validation'], activated=False), indent=2
        )
    )


if __name__ == '__main__':
    main()

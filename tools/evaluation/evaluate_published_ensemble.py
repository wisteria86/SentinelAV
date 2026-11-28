# Purpose: Calibrate threshold on reserved features, then evaluate separate held-out rows.
# Works with: detection.helpers.pe_ensemble, paths, response.response, updates.artifacts, workspace
# Used by: the Python module loader or CLI entry point

"""Calibrate threshold on reserved features, then evaluate separate held-out rows."""

import argparse
import base64
import hashlib
import json
import time
import numpy as np
from scipy.stats import beta
from thrember.features import PEFeatureExtractor
from sentinelav.detection.helpers.pe_ensemble import booster, combine, validate
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.updates.artifacts import active, canonical, activate
from sentinelav.response.response import dpapi
from sentinelav.workspace import Workspace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('dataset')
    parser.add_argument(
        '--activate',
        action='store_true',
        help='Explicitly activate the research candidate after evaluation',
    )
    args = parser.parse_args()
    model, _ = active(
        RESOURCE_ROOT / 'analysis-data', RESOURCE_ROOT / 'trusted-update-keys.json', 'model'
    )
    validate(model)
    groups = {'calibration': [], 'test': []}
    seen = set()
    extractor = PEFeatureExtractor()
    with open(args.dataset, encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row['split'] not in groups:
                continue
            if row['sha256'] in seen:
                raise ValueError('Duplicate calibration/test identity')
            seen.add(row['sha256'])
            groups[row['split']].append(
                (extractor.process_raw_features(row['features']), row['label'], row['file_type'])
            )

    def scores(rows):
        output = np.zeros(len(rows))
        for kind in ('Win32', 'Win64', 'Dot_Net'):
            indices = [i for i, row in enumerate(rows) if row[2] == kind]
            if not indices:
                continue
            x = np.vstack([rows[i][0] for i in indices])
            predictions = []
            for expert in (kind, 'PE'):
                member = model['members'][expert]
                predictions.append(
                    booster(member['model_sha256'], member['model_text']).predict(x, num_threads=2)
                )
            for position, index in enumerate(indices):
                output[index] = combine([float(p[position]) for p in predictions])
        return output

    cal = scores(groups['calibration'])
    labels = np.array([row[1] for row in groups['calibration']])
    threshold = float(np.nextafter(np.quantile(cal[labels == 0], 0.999, method='higher'), 1.0))
    model['review_threshold'] = min(1, threshold)
    kinds = {row[2] for row in groups['calibration']}
    if len(kinds) != 1:
        raise ValueError('Calibrate one format at a time')
    model['review_thresholds'] = dict(
        model.get('review_thresholds', dict(Win32=0.99, Win64=0.99, Dot_Net=0.99))
    )
    model['review_thresholds'][next(iter(kinds))] = min(1, threshold)
    test = scores(groups['test'])
    labels = np.array([row[1] for row in groups['test']])
    positive = test >= threshold
    n = int(sum(labels == 0))
    m = int(sum(labels == 1))
    fp = int(sum(positive & (labels == 0)))
    tp = int(sum(positive & (labels == 1)))
    report = dict(
        schema=1,
        algorithm=model['algorithm'],
        calibration_rows=len(cal),
        test_rows=len(test),
        threshold=threshold,
        benign=n,
        malware=m,
        false_positives=fp,
        true_positives=tp,
        recall=tp / m,
        fpr_upper_95=float(beta.ppf(0.95, fp + 1, n - fp)) if fp < n else 1,
        validation_scope='Published .NET feature holdout; no raw specimens, no family-disjoint claim, native-PE validation pending',
        dataset_sha256=hashlib.sha256(open(args.dataset, 'rb').read()).hexdigest(),
        automatic_actions=False,
    )
    model['validation'] = report
    model['validated'] = False
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(
        dpapi(
            (Workspace().root / 'models/ember2024-published/publisher-private.dpapi').read_bytes(),
            True,
        )
    )
    now = int(time.time())
    manifest = dict(
        kind='model',
        key_id='sentinelav-local-research',
        revision=now,
        issued=now - 1,
        expires=now + 90 * 86400,
        payload_sha256=hashlib.sha256(canonical(model)).hexdigest(),
    )
    envelope = dict(
        schema=1,
        manifest=manifest,
        payload=model,
        signature=base64.b64encode(key.sign(canonical(manifest))).decode(),
    )
    folder = Workspace().run('models', 'calibrated-ensemble')
    path = folder / 'model.json'
    path.write_bytes(canonical(envelope))
    if args.activate:
        activate(
            path,
            RESOURCE_ROOT / 'analysis-data',
            RESOURCE_ROOT / 'trusted-update-keys.json',
            'model',
        )
    receipt = Workspace().immutable_report(report, 'published-ensemble-evaluation')
    print(json.dumps(dict(report=str(receipt), **report), indent=2))


if __name__ == '__main__':
    main()

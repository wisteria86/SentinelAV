# Purpose: Published PE boosting specialists plus a general model, all inference local.
# Works with: data.contracts, detection.pe_classifier
# Used by: detection.advanced_pipeline, detection.classifier, lab.qualification.features,
#   lab.qualification.inventories

"""Published PE boosting specialists plus a general model, all inference local."""

from functools import lru_cache
import hashlib
import math
from sentinelav.data.contracts import fingerprint
from sentinelav.detection.pe_classifier import FEATURE_REVISION, features


def validate(model):
    """Check that an ensemble model has all four experts (general, 32-bit, 64-bit, .NET), that each one
    is untampered, and that the thresholds are sane.
    """
    if model.get('schema') != 3 or model.get('algorithm') != 'lightgbm-pe-ensemble-v1':
        raise ValueError('Invalid PE ensemble')
    if model.get('extractor_revision') != FEATURE_REVISION:
        raise ValueError('Ensemble extractor mismatch')
    if type(model.get('feature_count')) is not int or model['feature_count'] != 2568:
        raise ValueError('Unexpected EMBER v3 dimensions')
    if set(model.get('members', {})) != {'PE', 'Win32', 'Win64', 'Dot_Net'}:
        raise ValueError('Four PE experts required')
    total = 0
    for member in model['members'].values():
        text = member.get('model_text', '')
        total += len(text)
        if not text.startswith('tree\n') or len(text) > 5 * 1024 * 1024:
            raise ValueError('Invalid bounded model text')
        if hashlib.sha256(text.encode()).hexdigest() != member.get('model_sha256'):
            raise ValueError('Ensemble member digest mismatch')
        if member.get('feature_count') != model.get('feature_count'):
            raise ValueError('Ensemble feature dimensions differ')
    if total > 16 * 1024 * 1024:
        raise ValueError('Ensemble budget exceeded')
    if 'confirm_threshold' in model and (
        type(model['confirm_threshold']) not in (int, float)
        or not 0 < model['confirm_threshold'] < 1
    ):
        raise ValueError('Invalid confirmation threshold')
    value = model.get('review_threshold')
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 1:
        raise ValueError('Invalid ensemble threshold')
    for kind, value in model.get('review_thresholds', {}).items():
        if (
            kind not in ('Win32', 'Win64', 'Dot_Net')
            or type(value) not in (int, float)
            or not math.isfinite(value)
            or not 0 < value <= 1
        ):
            raise ValueError('Invalid specialist threshold')
    return model


@lru_cache(maxsize=4)
def booster(digest, text):
    """Build (and cache) a LightGBM model from its text, checking the text against its hash first."""
    import lightgbm

    if hashlib.sha256(text.encode()).hexdigest() != digest:
        raise ValueError('Model changed')
    return lightgbm.Booster(model_str=text)


def combine(scores):
    """Merge several 0..1 scores by averaging them in log-odds space, so confident experts weigh more
    than a plain average would give them.
    """
    if not scores or any(not math.isfinite(s) or not 0 <= s <= 1 for s in scores):
        raise ValueError('Invalid expert score')
    logits = [math.log(max(1e-12, s) / max(1e-12, 1 - s)) for s in scores]
    z = max(-700, min(700, sum(logits) / len(logits)))
    return 1 / (1 + math.exp(-z))


def predict_vector(model, vector, kind):
    """Score one feature vector with the matching specialist and the general model, and combine the two
    opinions.
    """
    if kind not in ('Win32', 'Win64', 'Dot_Net'):
        raise ValueError('Unsupported PE class')
    if len(vector) != model['feature_count']:
        raise ValueError('Ensemble input dimension mismatch')
    scores = {}
    for name in (kind, 'PE'):
        member = model['members'][name]
        tree = booster(member['model_sha256'], member['model_text'])
        if tree.num_feature() != len(vector):
            raise ValueError('Native model feature mismatch')
        scores[name] = float(tree.predict(vector.reshape(1, -1), num_threads=1)[0])
    score = combine(list(scores.values()))
    return dict(
        model_score=score,
        member_scores=scores,
        file_type=kind,
        calibrated_probability=False,
        review=score >= model.get('review_thresholds', {}).get(kind, model['review_threshold']),
        classification=(
            'Likely malicious'
            if score >= model.get('review_thresholds', {}).get(kind, model['review_threshold'])
            else 'Below review threshold'
        ),
        automatic_response_eligible=False,
        validation=model.get('validation', {}),
        model_id=fingerprint(
            dict(
                weights={k: v['model_sha256'] for k, v in model['members'].items()},
                threshold=model['review_threshold'],
                thresholds=model.get('review_thresholds', {}),
                extractor=FEATURE_REVISION,
                pooling='equal-logit-mean',
            )
        ),
        correlation_group='static-pe-features',
        feature_revision=FEATURE_REVISION,
        algorithm='Routed gradient-boosted specialists with logit pooling',
    )


def predict(model, data, confirm=None):
    """Score a Windows program with the ensemble.

    If `confirm` (a second, independently trained model) is given and the first verdict is 'review',
    the second model must agree before the result counts as confirmed.
    """
    import pefile

    validate(model)
    image = pefile.PE(data=bytes(data), fast_load=True)
    try:
        directories = image.OPTIONAL_HEADER.DATA_DIRECTORY
        kind = (
            'Dot_Net'
            if len(directories) > 14 and directories[14].VirtualAddress
            else 'Win64' if image.OPTIONAL_HEADER.Magic == 0x20B else 'Win32'
        )
    finally:
        image.close()
    vector = features(data)
    output = predict_vector(model, vector, kind)
    if confirm and output['review']:
        # A second, independently retrained model must agree; otherwise the file is shown for review, not convicted.
        second = predict_vector(confirm, vector, kind)['model_score']
        output.update(
            confirm_score=second, confirmed=second >= confirm.get('confirm_threshold', 0.5)
        )
        if not output['confirmed']:
            output['classification'] = 'Suspicious - review (not confirmed by second model)'
    return output

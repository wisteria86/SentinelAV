# Purpose: Signed plain-text LightGBM model inference with exact EMBER2024 features.
# Works with: sibling modules in detection
# Used by: detection.advanced_pipeline, detection.classifier, detection.pe_ensemble, lab.qualification.features

"""Signed plain-text LightGBM model inference with exact EMBER2024 features."""
import hashlib
import math
from functools import lru_cache

FEATURE_REVISION='0ef753e81d98bf209f71b03cd331dfc190b5b54d'
FEATURE_SOURCE_SHA256='aa9b29e2267a037ebec0b234234edfc2f8d2316e579ab1a0fba6878e70288eca'


@lru_cache(maxsize=1)
def extractor_class():
    # Importing thrember.features normally first runs thrember.__init__, which
    # imports training, dataset download and Polars. Those are unnecessary for
    # inference and consume memory needed by the bounded virtual emulator.
    # Load only the exact pinned upstream feature module, without changing its
    # feature semantics or introducing a reduced substitute extractor.
    import importlib.util
    from pathlib import Path
    package=importlib.util.find_spec('thrember')
    if package is None or not package.origin:raise ValueError('EMBER extractor unavailable')
    path=Path(package.origin).parent/'features.py'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=FEATURE_SOURCE_SHA256:
        raise ValueError('EMBER extractor source identity differs from pinned revision')
    spec=importlib.util.spec_from_file_location('sentinelav_ember_v3_features',path)
    if spec is None or spec.loader is None:raise ValueError('EMBER feature loader unavailable')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PEFeatureExtractor


def validate(model):
    if model.get('schema')!=2 or model.get('algorithm')!='lightgbm-pe-v1':raise ValueError('Unsupported PE classifier')
    if model.get('extractor')!='ember2024-v3' or model.get('extractor_revision')!=FEATURE_REVISION:raise ValueError('Feature extractor mismatch')
    text=model.get('model_text')
    if not isinstance(text,str) or len(text)>12*1024*1024 or not text.startswith('tree\n'):raise ValueError('Invalid bounded native model text')
    if hashlib.sha256(text.encode()).hexdigest()!=model.get('model_sha256'):raise ValueError('Model text digest mismatch')
    if type(model.get('feature_count')) is not int or not 1<=model['feature_count']<=10000:raise ValueError('Invalid feature dimension')
    if not isinstance(model.get('formats'),list) or not model['formats'] or set(model['formats'])-{'Dot_Net','Win32','Win64'}:raise ValueError('Model must declare supported PE formats')
    threshold=model.get('review_threshold')
    if type(threshold) not in (float,int) or not math.isfinite(threshold) or not 0<=threshold<=1:raise ValueError('Invalid classifier threshold')
    return model


def features(data):
    import numpy as np
    if len(data)>100*1024*1024:raise ValueError('Feature extraction input cap')
    vector=extractor_class()().feature_vector(bytes(data))
    if not np.isfinite(vector).all():raise ValueError('Nonfinite PE feature')
    return vector


def predict(model,data):
    validate(model)
    import pefile
    image=pefile.PE(data=bytes(data),fast_load=True)
    directories=image.OPTIONAL_HEADER.DATA_DIRECTORY
    kind='Dot_Net' if len(directories)>14 and directories[14].VirtualAddress else 'Win64' if image.OPTIONAL_HEADER.Magic==0x20b else 'Win32'
    if kind not in model['formats']:raise ValueError('No trained model coverage for '+kind)
    import lightgbm
    vector=features(data)
    if len(vector)!=model['feature_count']:raise ValueError('Feature dimension mismatch')
    classifier=lightgbm.Booster(model_str=model['model_text'])
    if classifier.num_feature()!=len(vector):raise ValueError('Native model dimension mismatch')
    score=float(classifier.predict(vector.reshape(1,-1),num_threads=1)[0])
    if not math.isfinite(score) or not 0<=score<=1:raise ValueError('Classifier returned invalid score')
    calibration=model.get('calibration',{})
    calibrated=False
    if calibration.get('method')=='platt':
        a,b=calibration.get('a'),calibration.get('b')
        if any(type(v) not in (int,float) or not math.isfinite(v) for v in (a,b)):raise ValueError('Invalid calibration')
        z=max(-700,min(700,a*math.log(max(1e-12,score)/max(1e-12,1-score))+b))
        score=1/(1+math.exp(-z));calibrated=True
    return dict(model_score=score,calibrated_probability=calibrated,
        review=score>=model['review_threshold'],automatic_response_eligible=False,
        validation=model.get('validation',{}),model_id=model['model_sha256'],
        correlation_group='static-pe-features',feature_revision=FEATURE_REVISION)

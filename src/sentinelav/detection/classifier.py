# Purpose: Portable standardized logistic regression. Plain JSON; no executable models.
# Works with: detection.anomaly_model, detection.pe_classifier, detection.pe_ensemble
# Used by: detection.advanced_pipeline, updates.artifacts, tests.unit.test_analysis_artifacts,
#   tools.evaluation.train_classifier

"""Portable standardized logistic regression. Plain JSON; no executable models."""
import math
import statistics
from sentinelav.detection.anomaly_model import FEATURES,validate


def sigmoid(value):
    """Squash any number into the range 0..1 (the logistic function), written so large inputs never
    overflow.
    """
    if value>=0: return 1/(1+math.exp(-value))
    exp=math.exp(value)
    return exp/(1+exp)


def validate_model(model):
    """Check that a model dictionary is complete and sane before it is used, raising ValueError if not.

    The newer LightGBM model types have their own validators; this function routes to them, and
    otherwise checks the simple logistic-regression format.
    """
    if isinstance(model,dict) and model.get('algorithm')=='lightgbm-pe-ensemble-v1':
        from sentinelav.detection.pe_ensemble import validate as validate_ensemble
        return validate_ensemble(model)
    if isinstance(model,dict) and model.get('algorithm')=='lightgbm-pe-v1':
        from sentinelav.detection.pe_classifier import validate
        return validate(model)
    if not isinstance(model,dict) or model.get('schema')!=1: raise ValueError('Invalid classifier object')
    if model.get('algorithm')!='logistic-static-v1' or model.get('features')!=list(FEATURES):
        raise ValueError('Unsupported classifier schema')
    if any(not isinstance(model.get(k),list) or len(model[k])!=len(FEATURES) for k in ('weights','center','scale')):
        raise ValueError('Invalid classifier vector dimensions')
    if 'bias' not in model: raise ValueError('Missing classifier bias')
    parameters=[model['bias'],*model['weights'],*model['center'],*model['scale']]
    if any(type(v) not in (float,int) or not math.isfinite(v) for v in parameters): raise ValueError('Invalid model parameters')
    if any(len(model[k])!=len(FEATURES) for k in ('weights','center','scale')) or any(v<=0 for v in model['scale']):
        raise ValueError('Invalid model dimensions/scale')
    if type(model.get('review_threshold')) not in (int,float) or not 0<=model['review_threshold']<=1:
        raise ValueError('Invalid model review threshold')
    return model


def predict(model,features):
    """Score one file's features with the logistic model.

    Each feature is standardised (centred and scaled), multiplied by its weight, and the sum is
    turned into a 0..1 score. The per-feature contributions are returned too, so the result can be
    explained. A high score only asks for review; it never authorises automatic action.
    """
    validate_model(model)
    terms={}
    for index,key in enumerate(FEATURES):
        value=features[key]
        if type(value) not in (int,float) or not math.isfinite(value): raise ValueError('Nonfinite feature')
        terms[key]=model['weights'][index]*(value-model['center'][index])/model['scale'][index]
    if any(not math.isfinite(v) for v in terms.values()): raise ValueError('Model arithmetic overflow')
    probability=sigmoid(model['bias']+sum(terms.values()))
    return dict(model_score=probability,calibrated_probability=False,contributions=terms,
        review=probability>=model['review_threshold'],automatic_response_eligible=False)


def train(rows,epochs=300,learning_rate=.05,l2=.01,target_fpr=.01):
    """Train a small logistic-regression model with plain gradient descent, then pick its review
    threshold.

    The threshold is chosen on separate benign calibration files so that roughly target_fpr of
    ordinary files would be flagged. l2 is a gentle penalty that keeps the weights from growing too
    large.
    """
    validate(rows)
    if not 1<=epochs<=2000 or not 0<learning_rate<=1 or not 0<=l2<=10 or not 0<target_fpr<1:
        raise ValueError('Invalid training configuration')
    training=[r for r in rows if r['split']=='train']
    calibration=[r for r in rows if r['split']=='calibration' and r['label']=='benign']
    if not all(any(r['label']==label for r in training) for label in ('benign','malware')) or len(calibration)<2:
        raise ValueError('Need both training classes and independent benign calibration rows')
    if len(training)>10000: raise ValueError('Pure-Python training row budget exceeded')
    center=[statistics.mean(r['features'][k] for r in training) for k in FEATURES]
    scale=[statistics.pstdev(r['features'][k] for r in training) or 1.0 for k in FEATURES]
    vectors=[([(r['features'][k]-center[i])/scale[i] for i,k in enumerate(FEATURES)],int(r['label']=='malware')) for r in training]
    weights=[0.0]*len(FEATURES); bias=0.0
    # Plain batch gradient descent: measure the average error over all rows, then nudge the weights
    # against it.
    for _ in range(epochs):
        gradient=[0.0]*len(weights); error_sum=0.0
        for vector,label in vectors:
            error=sigmoid(bias+sum(a*b for a,b in zip(weights,vector)))-label
            error_sum+=error
            for i,value in enumerate(vector): gradient[i]+=error*value
        bias-=learning_rate*error_sum/len(vectors)
        weights=[w-learning_rate*(gradient[i]/len(vectors)+l2*w) for i,w in enumerate(weights)]
    model=dict(schema=1,algorithm='logistic-static-v1',features=list(FEATURES),center=center,scale=scale,
        weights=weights,bias=bias,review_threshold=1.0,validated=False,
        training_hashes=[r['sha256'] for r in training],calibration_hashes=[r['sha256'] for r in calibration],
        target_fpr=target_fpr,calibration_resolution=1/len(calibration))
    scores=sorted(predict(model,r['features'])['model_score'] for r in calibration)
    model['review_threshold']=min(1.0,math.nextafter(scores[max(0,math.ceil((1-target_fpr)*len(scores))-1)],1.0))
    return model

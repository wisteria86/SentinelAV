# Purpose: Bounded NumPy CPU inference for the published MalConv2 GCG architecture.
# Works with: paths
# Used by: detection.advanced_pipeline, tests.unit.test_learned_detectors, tools.feeds.install_neural_model

"""Bounded NumPy CPU inference for the published MalConv2 GCG architecture.

Apache-2.0 architecture: FutureComputing4AI/MalConv2. Runtime tensors are loaded
without pickle. All stride-aligned windows in the bounded prefix are pooled.
No executable sample or upstream training code is invoked.
"""
from functools import lru_cache
import hashlib
import math
from sentinelav.paths import RESOURCE_ROOT

WEIGHTS_SHA256='32e9df3330aaf045a7ab68b3f17c4d319b1ffc6ba31b8107c9d6f109540622fd'
MAX_INPUT=4000000


@lru_cache(maxsize=1)
def weights():
    """Load the MalConv2 network weights, checking their SHA-256 first. Cached after the first call.
    """
    import numpy as np
    path=RESOURCE_ROOT/'analysis-data/malconv2-state.npz'
    if path.stat().st_size>16*1024*1024 or hashlib.sha256(path.read_bytes()).hexdigest()!=WEIGHTS_SHA256:raise ValueError('MalConv2 artifact integrity failed')
    with np.load(path,allow_pickle=False) as source:state={key:source[key] for key in source.files}
    if any(t.dtype!=np.float32 or not np.isfinite(t).all() for t in state.values()):raise ValueError('Invalid neural tensors')
    return state


def sigmoid(x):
    """Element-wise logistic function, clipped so large values never overflow."""
    import numpy as np
    return 1/(1+np.exp(-np.clip(x,-80,80)))


def pool(tokens,state,context=None,windows=256):
    """Slide the convolutional network over the byte sequence and keep, for each feature, its strongest
    response anywhere in the file.

    The file is processed in batches of windows to keep memory bounded. When `context` is given, the
    second (gated) pass uses it to decide which windows deserve attention.
    """
    import numpy as np
    if not 1<=windows<=4096:raise ValueError('Invalid neural chunk size')
    if len(tokens)<256:tokens=np.pad(tokens,(0,256-len(tokens)))
    count=(len(tokens)-256)//64+1;best=None;prefix='context_net.' if context is None else ''
    conv=state[prefix+'convs.0.weight'].reshape(512,-1)
    gate_context=None if context is None else np.tanh(context@state['linear_atn.0.weight'].T+state['linear_atn.0.bias'])
    for offset in range(0,count,windows):
        number=min(windows,count-offset);start=offset*64
        embedded=state[prefix+'embd.weight'][tokens[start:start+(number-1)*64+256]]
        view=np.lib.stride_tricks.sliding_window_view(embedded,256,axis=0)[::64]
        x=view.reshape(number,-1)@conv.T+state[prefix+'convs.0.bias']
        x=x[:,:256]*sigmoid(x[:,256:])
        share=prefix+'convs_1.0.' if context is None else 'convs_share.0.'
        x=x@state[share+'weight'][:,:,0].T+state[share+'bias'];x=np.where(x>=0,x,x*.01)
        if gate_context is not None:x=x*sigmoid(x@gate_context).reshape(-1,1)
        current=x.max(axis=0);best=current if best is None else np.maximum(best,current)
    return best


def logits(data,state,windows=256):
    """Run the full MalConv2 network on the bytes and return its two raw output scores (benign,
    malicious).
    """
    import numpy as np
    from threadpoolctl import threadpool_limits
    tokens=np.frombuffer(data,dtype=np.uint8).astype(np.int64)+1
    with threadpool_limits(limits=2):
        context=pool(tokens,state,windows=windows);pooled=pool(tokens,state,context,windows)
        hidden=pooled@state['fc_1.weight'].T+state['fc_1.bias'];hidden=np.where(hidden>=0,hidden,hidden*.01)
        return hidden@state['fc_2.weight'].T+state['fc_2.bias']


def predict(data):
    """Score a file with the raw-byte neural network and return a result dictionary.

    Only the first 4,000,000 bytes are examined. A score of 0.99 or more asks for review; the score
    alone never convicts a file.
    """
    import numpy as np
    if not data:raise ValueError('Empty neural input')
    used=bytes(data[:MAX_INPUT]);output=logits(used,weights())
    shifted=np.exp(output-output.max());score=float(shifted[1]/shifted.sum())
    if not math.isfinite(score):raise ValueError('Nonfinite neural result')
    return dict(status='Complete' if len(data)<=MAX_INPUT else 'Partial',algorithm='MalConv2-GCG',model_score=score,
        review=score>=.99,calibrated_probability=False,model_id=WEIGHTS_SHA256,bytes_examined=len(used),bytes_total=len(data),
        correlation_group='learned-byte-sequence',automatic_response_eligible=False,
        scope='Published raw-byte neural classifier; local efficacy/false-positive gates not established')

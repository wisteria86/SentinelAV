# Purpose: Reproduce the pinned MalConv2 tensor-only runtime artifact (no samples).
# Works with: detection.neural_bytes, paths, workspace
# Used by: the Python module loader or CLI entry point

"""Reproduce the pinned MalConv2 tensor-only runtime artifact (no samples)."""
import hashlib
import json
import shutil
import urllib.request
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.workspace import Workspace

REV='b5a865420e984b22a2474834bd1748318e84b553'
CHECKPOINT_SHA='28ea9a22e2389abaff7559ca1e78be908b7a43fb4cd3e56148d34dbc55f29e1b'


def main():
    import numpy as np
    import torch
    from sentinelav.detection.neural_bytes import WEIGHTS_SHA256
    folder=Workspace().area('models')/'malconv2';folder.mkdir(exist_ok=True)
    for name,limit in [('malconvGCT_nocat.checkpoint',33134696),('LICENSE',11358)]:
        path=folder/name
        if not path.exists():
            Workspace().check(limit)
            with urllib.request.urlopen(f'https://raw.githubusercontent.com/FutureComputing4AI/MalConv2/{REV}/{name}',timeout=90) as response:raw=response.read(limit+1)
            if len(raw)!=limit:raise ValueError('Neural download size mismatch')
            with path.open('xb') as stream:stream.write(raw)
    checkpoint=folder/'malconvGCT_nocat.checkpoint'
    if hashlib.sha256(checkpoint.read_bytes()).hexdigest()!=CHECKPOINT_SHA:raise ValueError('Checkpoint digest mismatch')
    state=torch.load(checkpoint,map_location='cpu',weights_only=True)['model_state_dict']
    destination=RESOURCE_ROOT/'analysis-data';destination.mkdir(exist_ok=True)
    candidate=folder/'converted-state.npz';np.savez(candidate,**{k:v.cpu().numpy() for k,v in state.items()})
    if hashlib.sha256(candidate.read_bytes()).hexdigest()!=WEIGHTS_SHA256:raise ValueError('Converted tensor artifact differs from the reviewed version')
    shutil.copyfile(candidate,destination/'malconv2-state.npz')
    shutil.copyfile(folder/'LICENSE',RESOURCE_ROOT/'licenses/MalConv2-Apache-2.0.txt')
    (destination/'malconv2.json').write_text(json.dumps(dict(schema=1,algorithm='malconv2-gcg-v1',sha256=WEIGHTS_SHA256,source_revision=REV,license='Apache-2.0')))
    print('Installed hash-verified neural tensors. Runtime uses NumPy; PyTorch is only required for conversion.')


if __name__=='__main__':main()

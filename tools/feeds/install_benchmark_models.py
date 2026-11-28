# Purpose: Install the original authors' pinned nonexecutable PE model weights locally.
# Works with: detection.helpers.pe_classifier, detection.helpers.pe_ensemble, paths, response.response, updates.analysis_trust
# Used by: the Python module loader or CLI entry point

"""Install the original authors' pinned nonexecutable PE model weights locally."""

import base64
import hashlib
import json
from pathlib import Path
import time
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sentinelav.workspace import Workspace
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.response.response import dpapi
from sentinelav.updates.artifacts import canonical, activate
from sentinelav.updates.analysis_trust import update_pin

REV = 'e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2'
FILES = {
    'PE': (3756042, '4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99'),
    'Win32': (3741926, 'b1e9fc174e4fcc6c0aba3ff29eb6d96ee9e240057f76940a8a1d6009ac0a4267'),
    'Win64': (3729014, '8eddddc26eb346d74810a0dfcc672342eca5709ece4da259934d6d3c77ca971b'),
    'Dot_Net': (3697641, 'cbd91b4a823d5dac3f56f38640a5599836501ccbd4fcce273d28c9aed0afc24c'),
}


def main():
    import lightgbm
    from sentinelav.detection.helpers.pe_classifier import FEATURE_REVISION

    folder = Workspace().area('models') / 'ember2024-published'
    folder.mkdir(exist_ok=True)
    members = {}
    for kind, (size, digest) in FILES.items():
        name = 'EMBER2024_' + kind + '.model'
        target = folder / name
        if not target.exists():
            Workspace().check(size)
            url = f'https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/{REV}/{name}'
            with urllib.request.urlopen(url, timeout=60) as source:
                raw = source.read(size + 1)
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('Published model integrity failed')
            with target.open('xb') as stream:
                stream.write(raw)
        raw = target.read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Cached model integrity failed')
        text = raw.decode()
        booster = lightgbm.Booster(model_str=text)
        members[kind] = dict(
            model_text=text, model_sha256=digest, feature_count=booster.num_feature()
        )
        print('Verified published model:', kind, booster.num_feature(), flush=True)
    dimensions = {m['feature_count'] for m in members.values()}
    if len(dimensions) != 1:
        raise ValueError('Feature dimensions disagree')
    model = dict(
        schema=3,
        algorithm='lightgbm-pe-ensemble-v1',
        extractor='ember2024-v3',
        extractor_revision=FEATURE_REVISION,
        formats=['Win32', 'Win64', 'Dot_Net'],
        feature_count=dimensions.pop(),
        members=members,
        review_threshold=0.99,
        validated=False,
        validation=dict(source='Published research benchmark; local efficacy not yet established'),
        provenance=dict(
            repository='joyce8/EMBER2024-benchmark-models', revision=REV, license='Apache-2.0'
        ),
        fusion='Equal mean of specialist/general PE logits; correlated evidence, no automatic actions',
    )
    sign_and_activate(model, 'model', folder)
    (folder / 'provenance.json').write_text(
        json.dumps(
            dict(
                revision=REV,
                files=FILES,
                license='Apache-2.0',
                activated=True,
                automatic_actions=False,
            ),
            indent=2,
        )
    )
    print('Installed signed local ensemble. Research model; automatic response remains disabled.')


def sign_and_activate(model, kind, folder):
    """Sign a validated ensemble payload with the local research key and make it the active artifact of this kind."""
    from sentinelav.detection.helpers.pe_ensemble import validate

    validate(model)
    keypath = Workspace().area('models') / 'ember2024-published' / 'publisher-private.dpapi'
    if keypath.exists():
        key = Ed25519PrivateKey.from_private_bytes(dpapi(keypath.read_bytes(), True))
    else:
        key = Ed25519PrivateKey.generate()
        with keypath.open('xb') as stream:
            stream.write(
                dpapi(
                    key.private_bytes(
                        serialization.Encoding.Raw,
                        serialization.PrivateFormat.Raw,
                        serialization.NoEncryption(),
                    )
                )
            )
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    trust = RESOURCE_ROOT / 'trusted-update-keys.json'
    update_pin(trust, 'sentinelav-local-research', public)
    store = RESOURCE_ROOT / 'analysis-data'
    revision = int(time.time())
    # No end date: the model stays usable until a newer signed model replaces it.
    manifest = dict(
        kind=kind,
        key_id='sentinelav-local-research',
        revision=revision,
        issued=revision - 1,
        expires=None,
        payload_sha256=hashlib.sha256(canonical(model)).hexdigest(),
    )
    envelope = dict(
        schema=1,
        manifest=manifest,
        payload=model,
        signature=base64.b64encode(key.sign(canonical(manifest))).decode(),
    )
    output = folder / (kind + '-' + str(revision) + '.json')
    with output.open('xb') as stream:
        stream.write(canonical(envelope))
    return activate(output, store, trust, kind)


if __name__ == '__main__':
    main()

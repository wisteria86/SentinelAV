# Purpose: Enable the installed signed classifiers for the current SentinelAV profile.
# Works with: data.storage, paths, platform.engine_policy, updates.analysis_trust, updates.artifacts
# Used by: the Python module loader or CLI entry point

"""Enable the installed signed classifiers for the current SentinelAV profile."""

import json
import os
from pathlib import Path
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.data.storage import Store
from sentinelav.updates.artifacts import active, activate, bounded_json
from sentinelav.updates.analysis_trust import update_pin
from sentinelav.platform.engine_policy import inspection_options
from sentinelav.workspace import Workspace


def main():
    source = RESOURCE_ROOT / 'analysis-data'
    trust = RESOURCE_ROOT / 'trusted-update-keys.json'
    model, manifest = active(source, trust, 'model')
    if model['algorithm'] != 'lightgbm-pe-ensemble-v1':
        raise ValueError('Published ensemble is not installed')
    root = Path(os.environ['LOCALAPPDATA']) / 'SentinelAV'
    root.mkdir(exist_ok=True)
    public = bounded_json(trust, 65536)['keys'][manifest['key_id']]
    update_pin(root / 'analysis-trust.json', manifest['key_id'], public)
    store_path = root / 'analysis-data'
    index = bounded_json(source / 'active.json', 65536)
    current = (
        bounded_json(store_path / 'active.json', 65536)
        if (store_path / 'active.json').exists()
        else {}
    )
    if current.get('model', {}).get('revision', 0) < manifest['revision']:
        activate(source / index['model']['file'], store_path, root / 'analysis-trust.json', 'model')
    store = Store(root / 'sentinelav.db')
    try:
        previous = store.get('inspection_options', {})
        options = inspection_options(
            dict(
                previous,
                advanced=True,
                model=True,
                neural=True,
                analysis_store=str(store_path),
                analysis_trust=str(root / 'analysis-trust.json'),
            )
        )
        store.set('inspection_options', options)
    finally:
        store.db.close()
    receipt = Workspace().immutable_report(
        dict(
            kind='LearnedDetectorInstallation',
            profile=str(root),
            model_algorithm=model['algorithm'],
            model_revision=manifest['revision'],
            model_enabled=True,
            neural_enabled=True,
            previous_options=previous,
            automatic_response_changed=False,
            windows_security_changed=False,
        ),
        'learned-detectors-installed',
    )
    print(
        'Both learned classifiers enabled. Restart an open app/monitor to reload its configuration. Receipt:',
        receipt,
    )


if __name__ == '__main__':
    main()

# Purpose: Verify packaged learned inference using a benign Windows utility, never launched.
# Works with: detection.helpers.pe_ensemble, paths, updates.artifacts, workspace
# Used by: the Python module loader or CLI entry point

"""Verify packaged learned inference using a benign Windows utility, never launched."""

import hashlib
import json
from pathlib import Path
import subprocess
from sentinelav.workspace import Workspace
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.updates.artifacts import active
from sentinelav.detection.helpers.pe_ensemble import predict


def main():
    work = Workspace()
    root = work.run('evaluations', 'learned-package-check')
    corpus = root / 'corpus'
    corpus.mkdir()
    path = corpus / 'whoami.exe'
    path.write_bytes(Path('C:/Windows/System32/whoami.exe').read_bytes())
    manifest = corpus / 'manifest.json'
    manifest.write_text(
        json.dumps(
            dict(
                schema=1,
                files=[
                    dict(
                        path=path.name,
                        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        label='benign',
                        provenance='Local Microsoft Windows utility; never launched',
                    )
                ],
            )
        )
    )
    executable = work.root / 'builds/dist/SentinelAV/SentinelAV.exe'
    process = subprocess.run(
        [
            str(executable),
            '--evaluate-corpus',
            str(manifest),
            '--evaluation-output',
            str(root / 'report'),
            '--signature-free',
        ],
        timeout=100,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    report = json.loads((root / 'report/report.json').read_text())
    row = report['rows'][0]
    coverage = row['scan'].get('advanced_analysis', {}).get('coverage', {})
    for name in ('model', 'neural'):
        if coverage.get(name, {}).get('status') != 'Complete':
            raise RuntimeError(
                name + ' unavailable in package: ' + str(row['scan'].get('errors', [])[:3])
            )
    emulator = coverage.get('emulation', {})
    if emulator.get('termination_reason') in (
        None,
        'not_started',
        'backend_error',
    ) or not emulator.get('api_attempts'):
        raise RuntimeError(
            'Packaged emulator failed to reach modeled APIs with learned models enabled: '
            + str(row['scan'].get('errors', [])[:3])
        )
    model, _ = active(
        RESOURCE_ROOT / 'analysis-data', RESOURCE_ROOT / 'trusted-update-keys.json', 'model'
    )
    if coverage['model']['model_id'] != predict(model, path.read_bytes())['model_id']:
        raise ValueError('Packaged/source model identities differ')
    if row['definitions']['count'] != 0 or row['yara']['status'] != 'Disabled':
        raise ValueError('Saved signatures enabled in learned check')
    normal = subprocess.run(
        [str(executable), '--self-test', '--data-dir', str(root / 'normal-selftest')],
        timeout=100,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if normal.returncode:
        raise RuntimeError('Normal packaged protection self-test failed')
    result = dict(
        schema=1,
        status='PASS',
        root=str(root),
        ensemble=coverage['model'],
        neural=coverage['neural'],
        emulation=emulator,
        saved_signatures_disabled=True,
        normal_protection_selftest=True,
        sample_launched=False,
        zoo_test=False,
    )
    print(work.immutable_report(result, 'learned-package-acceptance'))


if __name__ == '__main__':
    main()

# Purpose: Connect the native test harness to an inert, random local broker endpoint.
# Works with: paths, platform.core.amsi_broker
# Used by: unittest discovery

"""Connect the native test harness to an inert, random local broker endpoint."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from unittest.mock import patch

from sentinelav.paths import PROJECT_ROOT, RESOURCE_ROOT
from sentinelav.platform.core.amsi_broker import AmsiBroker

harness = PROJECT_ROOT / 'artifacts/native/amsi/AmsiHarness.exe'
if not harness.is_file():
    raise RuntimeError('Run scripts/build-amsi.ps1 -Test first')
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    shutil.copytree(RESOURCE_ROOT / 'rules', root / 'rules')
    fixture = b'SentinelAV native broker exact hash fixture'
    (root / 'signatures.json').write_text(
        json.dumps({hashlib.sha256(fixture).hexdigest(): 'Native inert fixture'})
    )
    endpoint = r'\\.\pipe\SentinelAV.Test.Amsi.' + uuid.uuid4().hex
    broker = AmsiBroker(root, endpoint).start()
    try:
        subprocess.run(
            [str(harness), '--broker', endpoint, str(os.getpid())], check=True, timeout=30
        )
        if broker.completed < 4:
            raise AssertionError('Expected broker scans did not complete')
        if broker.error:
            raise AssertionError(broker.error)
        with patch(
            'sentinelav.platform.core.amsi_broker.IsolatedScanner.scan_buffer',
            return_value=dict(kind='buffer', detected=False, complete=False),
        ):
            subprocess.run(
                [str(harness), '--unavailable', endpoint, str(os.getpid())], check=True, timeout=10
            )

        def slow_result(*args):
            time.sleep(3.5)
            return dict(kind='buffer', detected=False, complete=True)

        with patch(
            'sentinelav.platform.core.amsi_broker.IsolatedScanner.scan_buffer',
            side_effect=slow_result,
        ):
            subprocess.run(
                [str(harness), '--timeout', endpoint, str(os.getpid())], check=True, timeout=10
            )
    finally:
        broker.close()
    assert not broker.thread.is_alive()
print(
    'PASS: native provider -> local test broker -> isolated real hash/YARA engine; no registration/content persistence'
)

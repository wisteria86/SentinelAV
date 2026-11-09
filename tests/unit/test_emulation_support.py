# Purpose: Verify test emulation support behavior using controlled fixtures.
# Works with: platform.emulation_support
# Used by: unittest discovery

import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from sentinelav.platform.emulation_support import compatibility, validated_native_build


class EmulationBuildTests(unittest.TestCase):
    def test_cfg_requires_verified_build_even_for_future_version(self):
        with patch('sentinelav.platform.emulation_support.control_flow_guard_enabled',return_value=True), \
             patch('sentinelav.platform.emulation_support.validated_native_build',return_value=False):
            self.assertFalse(compatibility('2.1.4')['available'])
            self.assertFalse(compatibility('2.2.0')['available'])

    def test_verified_build_can_run_with_cfg(self):
        with patch('sentinelav.platform.emulation_support.control_flow_guard_enabled',return_value=True), \
             patch('sentinelav.platform.emulation_support.validated_native_build',return_value=True):
            self.assertTrue(compatibility('2.1.4')['available'])

    def test_receipt_checks_actual_loaded_path_and_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); dll=root/'unicorn/lib/unicorn.dll'
            dll.parent.mkdir(parents=True); dll.write_bytes(b'test-library-identity-only')
            manifest=dict(schema=1,backend='unicorn-windows-unwind-v1',version='2.1.4',
                upstream_revision='8028ec436f2d9376525352dd38ed9ed6b9f6be10',
                dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest())
            (root/'emulator-build.json').write_text(json.dumps(manifest))
            with patch('sys.frozen',True,create=True),patch('sys._MEIPASS',str(root),create=True), \
                 patch('unicorn.unicorn_py3.unicorn.uclib',types.SimpleNamespace(_name=str(dll))):
                self.assertTrue(validated_native_build())
                dll.write_bytes(b'changed')
                self.assertFalse(validated_native_build())
            outside=root/'other.dll'; outside.write_bytes(b'test-library-identity-only')
            with patch('sys.frozen',True,create=True),patch('sys._MEIPASS',str(root),create=True), \
                 patch('unicorn.unicorn_py3.unicorn.uclib',types.SimpleNamespace(_name=str(outside))):
                self.assertFalse(validated_native_build())

# Purpose: Harmless content and emulated instructions; never launch fixture executables.
# Works with: detection.helpers.active_content, detection.helpers.content_analysis, detection.engine, detection.core.file_formats,
#   detection.helpers.windows_emulation
# Used by: tools.evaluation.verify_frozen_emulator

"""Harmless content and emulated instructions; never launch fixture executables."""

import base64
import gzip
import hashlib
import json
import struct
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from tests.unit.test_pe_imports import imported_fixture
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.detection.engine import Scanner
from sentinelav.detection.core.file_formats import pe_metadata
from sentinelav.detection.helpers.windows_emulation import emulate_windows
from sentinelav.detection.helpers.content_analysis import normalized_variants, inspect_containers
from sentinelav.detection.helpers.active_content import active_sources

MARKER = b'SENTINELAV_DEMO_THREAT_7C23A'


def emulated_fixture(names, code, wide=False):
    data = imported_fixture(wide)
    struct.pack_into('<H', data, 68, 0x8664 if wide else 0x14C)
    struct.pack_into('<Q' if wide else '<I', data, 88 + (24 if wide else 28), 0x400000)
    struct.pack_into('<I', data, 144, 0x3000)
    struct.pack_into('<I', data, 104, 0x1400)
    for index, name in enumerate(names):
        raw = 1024 + index * 64
        data[raw : raw + 64] = bytes(64)
        encoded = name.encode() + b'\0'
        data[raw + 2 : raw + 2 + len(encoded)] = encoded
    struct.pack_into('<Q' if wide else '<I', data, 768 + len(names) * (8 if wide else 4), 0)
    data[1536 : 1536 + len(code)] = code
    return data


class IntegratedAnalysisTests(unittest.TestCase):
    def test_cfg_incompatibility_is_reported_before_native_execution(self):
        data = emulated_fixture(['ExitProcess'], b'\xc3')
        with (
            patch(
                'sentinelav.platform.core.emulation_support.control_flow_guard_enabled',
                return_value=True,
            ),
            patch('unicorn.Uc') as engine,
        ):
            report = emulate_windows(data, pe_metadata(data), lambda payload: ([], [], []))
        self.assertEqual(report['status'], 'Unavailable')
        self.assertTrue(any('CFG' in value for value in report['omissions']))
        engine.assert_not_called()

    def test_normalization_decodes_without_evaluating_commands(self):
        encoded = base64.b64encode(MARKER.decode().encode('utf-16le'))
        variants, _ = normalized_variants(b'powershell -EncodedCommand ' + encoded, '.ps1')
        self.assertTrue(any(MARKER in payload for _, payload in variants))

    def test_content_signature_becomes_detection_with_outer_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'signatures.json').write_text('{}')
            target = root / 'encoded.ps1'
            target.write_bytes(base64.b64encode(MARKER))
            scanner = Scanner(
                root / 'signatures.json', RESOURCE_ROOT / 'rules', options={'advanced': True}
            )
            try:
                report = scanner.scan([target], lambda: False, lambda *args: None)
                self.assertEqual(report['decision']['verdict'], 'Detected')
                self.assertEqual(report['errors'], [])
                self.assertEqual(
                    report['detections'][0]['sha256'],
                    hashlib.sha256(target.read_bytes()).hexdigest(),
                )
                self.assertEqual(report['detections'][0]['detection_scope'], 'derived content')
                self.assertFalse(report['detections'][0]['automatic_response_eligible'])
            finally:
                scanner.signatures.close()

    def test_gzip_expansion_is_bounded_and_checked(self):
        analyze = lambda payload: (['fixture'] if MARKER in payload else [], [], [])
        findings, _, _ = inspect_containers(gzip.compress(MARKER), analyze)
        self.assertEqual(findings[0]['reasons'], ['fixture'])
        findings, omissions, _ = inspect_containers(
            gzip.compress(b'A' * (5 * 1024 * 1024)), analyze
        )
        self.assertFalse(findings)
        self.assertTrue(omissions)

    def test_active_document_extraction_does_not_fetch_or_execute(self):
        html = b'<html><script src="https://example.invalid/a.js">' + MARKER + b'</script></html>'
        sources, omissions = active_sources(html, '.html')
        self.assertTrue(any(MARKER in data for _, data in sources))
        self.assertTrue(any('not fetched' in item for item in omissions))
        sources, _ = active_sources(
            b'{\\rtf1{\\object{\\objdata ' + MARKER.hex().encode() + b'}}}', '.rtf'
        )
        self.assertEqual(sources[0][1], MARKER)

    def test_win32_exit_dispatch_for_both_abis(self):
        for wide in (False, True):
            code = (
                (b'\x48\x83\xec\x28\x31\xc9\xff\x15' + struct.pack('<i', 0x1100 - 0x140C))
                if wide
                else b'\x6a\x00\xff\x15' + struct.pack('<I', 0x401100)
            )
            data = emulated_fixture(['ExitProcess'], code, wide)
            report = emulate_windows(data, pe_metadata(data), lambda payload: ([], [], []))
            with self.subTest(wide=wide):
                self.assertEqual(report.get('api_calls'), 1, report)
                self.assertIn({'kind': 'exit', 'code': 0}, report['api_events'])
                self.assertFalse(
                    any(
                        'CPU stopped' in text or 'API model stopped' in text
                        for text in report['omissions']
                    ),
                    report,
                )

    def test_emulated_allocation_and_writes_are_scanned(self):
        code = (
            b'\x6a\x40\x68\x00\x30\x00\x00\x6a\x10\x6a\x00\xff\x15'
            + struct.pack('<I', 0x401100)
            + b'\xc7\x00DECO\xc7\x40\x04DED!\x6a\x00\xff\x15'
            + struct.pack('<I', 0x401104)
        )
        data = emulated_fixture(['VirtualAlloc', 'ExitProcess'], code)
        report = emulate_windows(
            data,
            pe_metadata(data),
            lambda payload: (['decoded fixture'] if b'DECODED!' in payload else [], [], []),
        )
        self.assertEqual(report.get('api_calls'), 2, report)
        self.assertTrue(report['findings'], report)

    def test_unknown_api_is_an_omission_not_success(self):
        data = emulated_fixture(['CreateThread'], b'\xff\x15' + struct.pack('<I', 0x401100))
        report = emulate_windows(data, pe_metadata(data), lambda payload: ([], [], []))
        self.assertTrue(any('CreateThread' in item for item in report['omissions']), report)
        self.assertFalse(report['findings'])

    def test_tls_callback_returns_to_main_entry(self):
        data = emulated_fixture(['ExitProcess'], b'\x6a\x00\xff\x15' + struct.pack('<I', 0x401100))
        struct.pack_into('<I', data, 180, 10)
        struct.pack_into('<II', data, 88 + 96 + 9 * 8, 0x1340, 24)
        struct.pack_into('<IIIIII', data, 512 + 0x340, 0, 0, 0, 0x401300, 0, 0)
        struct.pack_into('<II', data, 512 + 0x300, 0x401380, 0)
        data[512 + 0x380 : 512 + 0x383] = b'\xc2\x0c\x00'
        report = emulate_windows(data, pe_metadata(data), lambda payload: ([], [], []))
        self.assertEqual(report.get('tls_callbacks_declared'), 1, report)
        self.assertEqual(report.get('api_calls'), 1, report)

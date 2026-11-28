# Purpose: Verify test amsi buffers behavior using controlled fixtures.
# Works with: detection.core.buffer_scan, detection.engine, detection.inspection, paths, platform.core.amsi_broker
# Used by: unittest discovery

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinelav.detection.core.buffer_scan import MAX_BUFFER, inspect_buffer
from sentinelav.detection.engine import Scanner
from sentinelav.detection.inspection import IsolatedScanner
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.platform.core.amsi_broker import AmsiBroker, response_status


class BufferTests(unittest.TestCase):
    def test_harmless_demo_marker_supports_utf16_host_buffers(self):
        scanner = Scanner(RESOURCE_ROOT / 'signatures.json', RESOURCE_ROOT / 'rules')
        try:
            result = inspect_buffer(scanner, 'SENTINELAV_DEMO_THREAT_7C23A'.encode('utf-16-le'))
            self.assertTrue(result['detected'])
            self.assertTrue(any(match['demo'] for match in result['yara_matches']))
            self.assertFalse(
                inspect_buffer(scanner, 'ordinary harmless text'.encode('utf-16-le'))['detected']
            )
        finally:
            scanner.signatures.close()

    def test_isolated_binary_hash_and_yara_without_file_or_amsi_recursion(self):
        content = b'SentinelAV buffer hash fixture\x00\xff'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            signatures = root / 'signatures.json'
            signatures.write_text(
                json.dumps({hashlib.sha256(content).hexdigest(): 'Inert buffer fixture'})
            )
            scanner = IsolatedScanner(
                signatures, RESOURCE_ROOT / 'rules', options=dict(amsi=True), persistent=True
            )
            try:
                result = scanner.scan_buffer(content)
                self.assertTrue(result['detected'])
                self.assertEqual(result['verdict'], 'Detected')
                self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
                self.assertNotIn('path', result)
                self.assertTrue(
                    scanner.scan_buffer(b'SENTINELAV_DEMO_THREAT_7C23A')['yara_matches']
                )
                self.assertEqual(scanner.scan_buffer(b'ordinary text')['verdict'], 'No match')
                self.assertEqual(scanner.scan_buffer(b'')['bytes'], 0)
                self.assertEqual(scanner.scan_buffer(b'x' * MAX_BUFFER)['bytes'], MAX_BUFFER)
                with self.assertRaises(ValueError):
                    scanner.scan_buffer(b'x' * (MAX_BUFFER + 1))
                with self.assertRaises(TypeError):
                    scanner.scan_buffer('not bytes')
                with self.assertRaises(RuntimeError):
                    scanner.exchange(
                        dict(command='buffer', content='%%%'), lambda: False, lambda *a: None, 3
                    )
                with self.assertRaises(RuntimeError):
                    scanner.exchange(
                        dict(
                            command='buffer',
                            content=base64.b64encode(b'x').decode(),
                            path='C:/ignored',
                        ),
                        lambda: False,
                        lambda *a: None,
                        3,
                    )
            finally:
                scanner.close()
            self.assertEqual(list(root.iterdir()), [signatures])

    def test_partial_detection_survives_parser_error_and_no_match_remains_unknown(self):
        scanner = Scanner(RESOURCE_ROOT / 'signatures.json', RESOURCE_ROOT / 'rules')
        try:
            with patch.object(scanner, 'analyze_bytes', return_value=([], [], ['YARA timeout'])):
                result = inspect_buffer(scanner, b'fixture')
                self.assertEqual(result['verdict'], 'Indeterminate')
                self.assertEqual(response_status(result), 2)
            with patch.object(
                scanner, 'analyze_bytes', return_value=(['SHA-256: fixture'], [], ['YARA timeout'])
            ):
                result = inspect_buffer(scanner, b'fixture')
                self.assertEqual(result['verdict'], 'Detected')
                self.assertFalse(result['complete'])
                self.assertEqual(response_status(result), 1)
        finally:
            scanner.signatures.close()

    def test_production_endpoint_refuses_source_user_and_random_endpoint_required(self):
        with self.assertRaises(RuntimeError):
            AmsiBroker(RESOURCE_ROOT)
        for name in (
            'anything',
            r'\\.\pipe\SentinelAV.Test.Amsi.not-random',
            r'\\remote\pipe\SentinelAV.Test.Amsi.' + 'a' * 32,
        ):
            with self.assertRaises(ValueError):
                AmsiBroker(RESOURCE_ROOT, name)


if __name__ == '__main__':
    unittest.main()

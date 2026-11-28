# Purpose: Verify test pe imports behavior using controlled fixtures.
# Works with: detection.file_formats, detection.pe_imports, tests.unit.test_static_analysis
# Used by: tests.unit.test_integrated_analysis

import struct
import unittest
from tests.unit.test_static_analysis import fixture
from sentinelav.detection.file_formats import pe_metadata, static_analysis
from sentinelav.detection.pe_imports import inspect_imports


def imported_fixture(wide=False):
    data = fixture() + bytearray(1024)
    struct.pack_into('<II', data, 320, 1536, 0x1000)
    struct.pack_into('<I', data, 328, 1536)
    data[512:] = bytes(1536)
    struct.pack_into('<H', data, 88, 0x20B if wide else 0x10B)
    struct.pack_into('<I', data, 148, 512)
    struct.pack_into('<I', data, 88 + (108 if wide else 92), 2)
    struct.pack_into('<II', data, 88 + (112 if wide else 96) + 8, 0x1000, 40)
    struct.pack_into('<IIIII', data, 512, 0x1100, 0, 0, 0x1060, 0x1100)
    data[608:621] = b'kernel32.dll\0'
    names = ('OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread')
    for index, name in enumerate(names):
        rva = 0x1200 + index * 64
        struct.pack_into('<Q' if wide else '<I', data, 768 + index * (8 if wide else 4), rva)
        raw = 1024 + index * 64
        value = name.encode() + b'\0'
        data[raw + 2 : raw + 2 + len(value)] = value
    return data


class ImportTests(unittest.TestCase):
    def test_pe32_and_pe64_decode_and_explain_combined_capabilities(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                result = static_analysis(imported_fixture(wide))
                self.assertEqual(result['imports']['status'], 'Complete')
                self.assertEqual(result['imports']['functions'], 4)
                self.assertEqual(
                    {c['capability'] for c in result['capabilities']},
                    {'cross_process_memory', 'remote_thread'},
                )
                self.assertIn(
                    'cross_process_execution_capability', [s['code'] for s in result['signals']]
                )
                self.assertFalse(result['automatic_response_eligible'])

    def test_unmapped_and_ambiguous_rvas_are_omissions(self):
        data = imported_fixture()
        struct.pack_into('<I', data, 524, 0xFFFFFFF0)
        result = static_analysis(data)
        self.assertEqual(result['imports']['status'], 'Incomplete')
        data = imported_fixture()
        struct.pack_into('<H', data, 70, 2)
        data[352:392] = data[312:352]
        self.assertEqual(static_analysis(data)['imports']['status'], 'Incomplete')

    def test_single_import_cannot_imply_combined_remote_execution(self):
        data = imported_fixture()
        struct.pack_into('<I', data, 772, 0)
        result = static_analysis(data)
        self.assertEqual(result['capabilities'], [])
        self.assertNotIn(
            'cross_process_execution_capability', [s['code'] for s in result['signals']]
        )

    def test_ordinal_imports_are_retained(self):
        data = imported_fixture(True)
        struct.pack_into('<Q', data, 768, (1 << 63) | 42)
        info = inspect_imports(data, pe_metadata(data))
        self.assertEqual(info['libraries'][0]['symbols'][0], {'ordinal': 42})

    def test_unterminated_name_is_not_silently_truncated(self):
        data = imported_fixture()
        data[608:1120] = b'A' * 512
        self.assertEqual(static_analysis(data)['imports']['status'], 'Incomplete')

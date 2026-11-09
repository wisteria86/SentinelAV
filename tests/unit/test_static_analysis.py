# Purpose: Inert headers exercise generic properties without malware/sample identifiers.
# Works with: detection.engine, detection.file_formats, paths
# Used by: tests.unit.test_pe_imports

"""Inert headers exercise generic properties without malware/sample identifiers."""
import struct
import tempfile
import unittest
from pathlib import Path
from sentinelav.detection.file_formats import byte_statistics, pe_metadata, static_analysis
from sentinelav.detection.engine import Scanner
from sentinelav.paths import RESOURCE_ROOT


def fixture(flags=0x60000020, entry=0x1000):
    data=bytearray(1024)
    data[:2]=b'MZ'
    struct.pack_into('<I',data,0x3c,64)
    data[64:68]=b'PE\0\0'
    struct.pack_into('<HH',data,68,0x14c,1)
    struct.pack_into('<H',data,84,224)
    struct.pack_into('<H',data,88,0x10b)
    struct.pack_into('<I',data,104,entry)
    data[312:320]=b'.text\0\0\0'
    struct.pack_into('<IIII',data,320,512,0x1000,512,512)
    struct.pack_into('<I',data,348,flags)
    data[512:]=bytes(range(256))*2
    return data


class StaticAnalysisTests(unittest.TestCase):
    def test_entropy_reference_values_and_empty_input(self):
        self.assertEqual(byte_statistics(b'')['entropy_bits'],0)
        self.assertEqual(byte_statistics(b'A'*100)['entropy_bits'],0)
        self.assertEqual(byte_statistics(bytes(range(256)))['entropy_bits'],8)

    def test_entropy_is_not_a_malware_verdict(self):
        analysis=static_analysis(fixture())
        self.assertEqual(analysis['signals'],[])
        self.assertFalse(analysis['calibrated'])
        self.assertIsNone(analysis['malware_probability'])

    def test_structural_properties_independent_of_names(self):
        data=fixture(0xe0000020,0x9000)
        a=static_analysis(data)
        data[312:320]=b'random!!'
        b=static_analysis(data)
        self.assertEqual(a['signals'],b['signals'])
        self.assertEqual({s['code'] for s in a['signals']},
                         {'writable_executable_section','entrypoint_outside_sections'})

    def test_truncated_section_is_not_silently_analyzed(self):
        with self.assertRaises(ValueError): pe_metadata(fixture()[:-1])

    def test_overlapping_ranges_and_shared_entrypoint_are_preserved(self):
        data=fixture()
        struct.pack_into('<H',data,70,2)
        data[352:392]=data[312:352]
        info=pe_metadata(data)
        self.assertEqual(info['entrypoint_sections'],[0,1])
        self.assertEqual(info['raw_overlaps'],[[0,1]])
        self.assertIn('overlapping_raw_sections',
                      [s['code'] for s in static_analysis(data,info)['signals']])

    def test_review_never_becomes_signature_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            signatures=root/'signatures.json'
            signatures.write_text('{}')
            target=root/'inert.bin'
            target.write_bytes(fixture(0xe0000020))
            scanner=Scanner(signatures,RESOURCE_ROOT/'rules',options={'archives':False})
            try:
                report=scanner.scan([target],lambda:False,lambda *args:None)
                self.assertEqual(report['detections'],[])
                self.assertEqual(report['structural_review_total'],1)
                self.assertFalse(report['static_analysis']['automatic_response_eligible'])
            finally: scanner.signatures.close()

# Purpose: Run every indicator module on real-typed bytes, so a type slip cannot silently disable a format.
# Works with: detection.indicators, detection.file_types
# Used by: test.ps1

"""Run every indicator module on real-typed bytes, so a type slip cannot silently disable a format.

An analyzer that raises is reported only as a coverage omission, which can hide a bug
for every file of that type. These fixtures are inert and are never executed.
"""
import io
import struct
import unittest
import zipfile

from sentinelav.detection.file_types import classify
from sentinelav.detection.indicators import collect, documents

OLE_HEADER=bytes.fromhex('d0cf11e0a1b11ae1')


def zipped(*entries):
    raw=io.BytesIO()
    with zipfile.ZipFile(raw,'w') as archive:
        for name,value in entries:archive.writestr(name,value)
    return raw.getvalue()


def fixtures():
    elf=b'\x7fELF\x01\x01\x01'+b'\0'*9+struct.pack('<H',2)+b'\0'*60+b'/bin/busybox /dev/watchdog udp flood'
    return dict(ole=(OLE_HEADER+b'\0'*600+b'AutoOpen macrocopy normal.dot','.doc'),ooxml=(zipped(('[Content_Types].xml','x'),('word/document.xml','y')),'.docx'),
        pdf=(b'%PDF-1.7\n<< /OpenAction 1 0 R /JavaScript 2 0 R >>','.pdf'),rtf=(b'{\\rtf1\\object\\objupdate\\objdata 0102}','.rtf'),
        elf=(elf,''),macho=(b'\xcf\xfa\xed\xfe'+b'\0'*64+b'library/launchagents','') ,apk=(zipped(('AndroidManifest.xml','x'),('classes.dex',b'dex\n035')),'.apk'),
        dex=(b'dex\n035\0'+b'\0'*64,''),jar=(zipped(('META-INF/MANIFEST.MF','x'),('a.class',b'\xca\xfe\xba\xbe')),'.jar'),
        dos_mz=(b'MZ'+b'\0'*200+b'*.COM\0\xcd\x21','.exe'),com=(b'\xe9\x00\x01'+b'\x90'*300,'.com'),lnk=(b'L\0\0\0\x01\x14\x02\0'+b'\0'*80,'.lnk'),
        html=(b'<html><script>eval(unescape("x"))</script></html>','.html'),powershell=(b'Write-Host done\n','.ps1'),vbscript=(b'Dim x\n','.vbs'),
        javascript=(b'var x = 1;\n','.js'),batch=(b'@echo off\r\n','.bat'),shell=(b'#!/bin/sh\necho hi\n','.sh'),python=(b'print(1)\n','.py'),php=(b'<?php echo 1; ?>','.php'))


class IndicatorInputTests(unittest.TestCase):
    def test_every_analyzed_format_runs_without_an_analyzer_error(self):
        for expected,(data,suffix) in fixtures().items():
            with self.subTest(kind=expected):
                file_type=classify(data,suffix)
                self.assertEqual(file_type['kind'],expected)
                omissions=[]
                collect(data,file_type,dict(format='Other'),None,'',omissions)
                self.assertEqual([item for item in omissions if 'indicator analysis incomplete' in item],[])

    def test_legacy_macro_names_and_embedded_programs_are_recognized_in_ole_files(self):
        codes=[item['code'] for item in documents.office_indicators(OLE_HEADER+b'\0'*600+b'AutoOpen macrocopy normal.dot')]
        self.assertIn('legacy_macro_triggers',codes)
        self.assertIn('legacy_macro_copy',codes)
        planted=OLE_HEADER+b'\0'*600+b'MZ'+b'\0'*70+b'This program cannot be run in DOS mode'
        self.assertIn('embedded_program_in_document',[item['code'] for item in documents.office_indicators(planted)])

    def test_rtf_objects_are_judged_on_lowercase_and_spaced_hex(self):
        codes=[item['code'] for item in documents.rtf_indicators(b'{\\rtf1\\object\\objupdate\\objdata 45 71 75 \n Equation.3 4D5A'+b'00'*60+b'}')]
        self.assertIn('rtf_object_auto_update',codes)
        self.assertIn('rtf_equation_object',codes)
        self.assertIn('rtf_embedded_program',codes)

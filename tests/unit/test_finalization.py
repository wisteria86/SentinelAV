from sentinelav.paths import RESOURCE_ROOT
import io
import tempfile
import unittest
from datetime import datetime,timedelta
from pathlib import Path
from unittest.mock import patch
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from sentinelav.platform.runtime import ZONE,next_daily,due,task_xml,run_scheduled,set_startup
from sentinelav.data.reporting import snapshot,render_report
from sentinelav.data.storage import Store
from sentinelav.detection.engine import Scanner

ROOT=RESOURCE_ROOT


class FinalizationTests(unittest.TestCase):
    def test_schedule_timezone_and_catchup(self):
        now=datetime(2026,10,15,18,30,tzinfo=ZONE)
        self.assertEqual(next_daily(18,0,now).day,16)
        self.assertEqual(next_daily(19,0,now).day,15)
        self.assertEqual(next_daily(19,0,now).utcoffset(),timedelta(hours=5))
        self.assertTrue(due(dict(enabled=True,next_run=(now-timedelta(days=3)).isoformat()),now))
        self.assertFalse(due(dict(enabled=False,next_run=now.isoformat()),now))

    def test_task_xml_quotes_paths_and_uses_low_privileges(self):
        schedule=dict(next_run='2026-10-16T18:00:00+05:00')
        tree=ET.fromstring(task_xml(schedule,Path('C:/Users/test/Folder & Space')))
        ns={'t':'http://schemas.microsoft.com/windows/2004/02/mit/task'}
        self.assertEqual(tree.find('.//t:RunLevel',ns).text,'LeastPrivilege')
        self.assertEqual(tree.find('.//t:LogonType',ns).text,'InteractiveToken')
        self.assertIn('--scheduled-scan',tree.find('.//t:Arguments',ns).text)
        self.assertIn('Folder & Space',tree.find('.//t:Arguments',ns).text)

    def test_headless_scheduled_scan_runs_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            folder=root/'files'
            folder.mkdir()
            (folder/'demo.txt').write_text('SENTINELAV_DEMO_THREAT_7C23A')
            state=root/'state'
            store=Store(state/'sentinelav.db')
            store.set('schedule',dict(enabled=True,kind='Folder',folder=str(folder),hour=18,minute=0,next_run=(datetime.now(ZONE)-timedelta(days=1)).isoformat()))
            result=run_scheduled(state)
            self.assertEqual(result['scanned'],1)
            self.assertEqual(len(result['detections']),1)
            self.assertEqual(run_scheduled(state)['status'],'Not due')
            self.assertEqual(len(store.history()),1)
            self.assertEqual(store.events()[0]['kind'],'Scheduled scan completed')
            store.db.close()

    def test_report_html_escapes_content_and_csv_neutralizes_formula(self):
        with tempfile.TemporaryDirectory() as temp:
            store=Store(Path(temp)/'state.db')
            store.save_scan(dict(started='2026-10-15',kind='=HYPERLINK("bad")',scanned=1,skipped=0,errors=[],detections=[],status='<script>alert(1)</script>'))
            report=snapshot(store)
            html=render_report(report,'html')
            self.assertNotIn('<script>',html)
            self.assertIn('&lt;script&gt;',html)
            self.assertIn("'=HYPERLINK",render_report(report,'csv'))
            self.assertIn('summary',render_report(report,'json'))
            store.db.close()

    def test_history_cache_invalidates_for_worker_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'cache.db'
            first,second=Store(path),Store(path)
            self.assertEqual(first.history(),[])
            second.save_scan(dict(scanned=1))
            self.assertEqual(first.history(),[dict(scanned=1)])
            first.save_scan(dict(scanned=2))
            self.assertEqual(first.history()[0]['scanned'],2)
            first.db.close()
            second.db.close()

    def test_eicar_detection_without_writing_test_signature_to_disk(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'safe-fixture.txt'
            target.write_bytes(b'placeholder')
            scanner=Scanner(ROOT/'signatures.json',ROOT/'rules')
            eicar=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$'+b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            stream=io.BytesIO(eicar)
            stream.fileno=lambda:123
            stat=target.stat()
            stat=SimpleNamespace(**{k:getattr(stat,k) for k in ['st_dev','st_ino','st_mtime_ns','st_ctime_ns','st_mode','st_file_attributes','st_reparse_tag']},st_size=len(eicar))
            with patch.object(Path,'open',return_value=stream),patch('sentinelav.detection.engine.os.fstat',return_value=stat),patch.object(Path,'stat',return_value=stat):
                result=scanner.scan([target],lambda:False,lambda *args:None)
            self.assertTrue(any('EICAR' in reason for reason in result['detections'][0]['reasons']))

    def test_startup_is_explicit_and_uses_quoted_command(self):
        with patch('winreg.CreateKey') as key, patch('winreg.SetValueEx') as write,patch('winreg.DeleteValue') as delete,patch('winreg.QueryValueEx',side_effect=FileNotFoundError):
            set_startup(True)
            self.assertEqual(write.call_args.args[1],'SentinelAV')
            self.assertIn('--startup',write.call_args.args[-1])
            set_startup(False)
            self.assertEqual(delete.call_args.args[1],'SentinelAV')


if __name__=='__main__':
    unittest.main()

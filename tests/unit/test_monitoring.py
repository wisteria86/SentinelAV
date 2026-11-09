# Purpose: Verify test monitoring behavior using controlled fixtures.
# Works with: monitoring.behavior, monitoring.monitoring, paths, tests.unit.test_sequences
# Used by: unittest discovery

from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
from sentinelav.monitoring.monitoring import Monitor, PendingFiles, SysmonReader

ROOT = RESOURCE_ROOT


class MonitoringTests(unittest.TestCase):
    def config(self, folder):
        return dict(folders=[str(folder)],processes=False,sysmon=False,
                    signatures=ROOT/'signatures.json',rules=ROOT/'rules',max_mb=10,exclusions=[])

    def test_watch_detects_changes_moves_exclusions_and_stops(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            excluded = root/'ignored'
            excluded.mkdir()
            events, statuses = [], []
            config = self.config(root)
            config['exclusions'] = [excluded]
            monitor = Monitor(config,events.append,statuses.append)
            thread = threading.Thread(target=monitor.run)
            thread.start()
            def wait_for(predicate):
                until = time.monotonic()+8
                while time.monotonic() < until:
                    if predicate():
                        return
                    time.sleep(.05)
                self.fail('Expected monitoring event not received')
            try:
                wait_for(lambda: bool(statuses))
                marker = 'SENTINELAV_DEMO_THREAT_7C23A'
                (excluded/'excluded.txt').write_text(marker)
                target = root/'clean.txt'
                target.write_text('clean')
                wait_for(lambda: monitor.checked >= 1)
                target.write_text(marker)
                wait_for(lambda: any(e['level']=='Alert' for e in events))
                moved = root/'renamed.txt'
                target.rename(moved)
                wait_for(lambda: any(e.get('path')==str(moved.resolve()) for e in events))
                alerts = [e for e in events if e['level']=='Alert']
                self.assertEqual(len(alerts),2)
                self.assertTrue(all('ignored' not in e['path'] for e in alerts))
                self.assertEqual(moved.read_text(),marker)
            finally:
                monitor.stop.set()
                thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(events[-1]['kind'],'Monitoring stopped')

    def test_bounded_debounce(self):
        queue = PendingFiles(capacity=1, delay=.02)
        with patch('sentinelav.monitoring.monitoring.time.monotonic',return_value=100) as clock:
            queue.add('one')
            queue.add('one')
            queue.add('two')
            self.assertIsNone(queue.pop())
            self.assertEqual(queue.dropped,1)
            clock.return_value=100.03
            self.assertTrue(queue.pop()[0].endswith('one'))
            self.assertIsNone(queue.pop())

    def test_incomplete_inspection_and_worker_recovery_are_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            target=root/'ordinary.txt'
            target.write_text('Inert content')
            events=[]
            monitor=Monitor(self.config(root),events.append,lambda _:None)
            monitor.allowed_roots=[root.resolve()]
            scanner=Mock()
            scanner.excluded.return_value=False
            scanner.scan.side_effect=[
                dict(status='Complete with omissions',scanned=0,detections=[],errors=['Worker exited'],skipped=0),
                dict(status='Complete',scanned=1,detections=[],errors=[],skipped=0,worker_restarted=True)]
            monitor.inspect(scanner,str(target),'Filesystem')
            self.assertTrue(monitor.inspection_error)
            self.assertTrue(any(e['kind']=='Inspection failed' for e in events))
            monitor.inspect(scanner,str(target),'Filesystem')
            self.assertFalse(monitor.inspection_error)
            self.assertTrue(any(e['kind']=='Inspection worker restarted' for e in events))

    def test_process_baseline_new_process_and_pid_reuse(self):
        events = []
        monitor = Monitor(self.config(ROOT),events.append,lambda _:None)
        monitor.config['processes'] = True
        def process(pid,stamp):
            return SimpleNamespace(info=dict(pid=pid,ppid=1,name='test',exe=str(PROJECT_ROOT/'app.py'),create_time=stamp))
        with patch('sentinelav.monitoring.monitoring.psutil.process_iter',side_effect=[[process(12,1)],[process(12,1),process(13,2)],[process(12,3)]]):
            monitor.processes()
            self.assertEqual(events,[])
            monitor.processes()
            monitor.processes()
        self.assertEqual([e['pid'] for e in events],[13,12])
        self.assertEqual(len(monitor.pending.items),1)

    def test_sysmon_baseline_and_incremental_cursor(self):
        reader = SysmonReader()
        first = SimpleNamespace(returncode=0,stdout=json.dumps([dict(RecordId=100,Id=1,Message='old')]),stderr='')
        second = SimpleNamespace(returncode=0,stdout=json.dumps([dict(RecordId=101,Id=11,Message='new')]),stderr='')
        with patch('sentinelav.monitoring.monitoring.subprocess.run',side_effect=[first,second]) as run:
            self.assertEqual(reader.poll(),[])
            self.assertEqual(reader.poll()[0]['RecordId'],101)
            self.assertIn('EventRecordID > 100', run.call_args.args[0][-1])
            self.assertEqual(reader.cursor,101)

    def test_structured_sysmon_records_reach_sequence_alerts_and_respect_exclusions(self):
        from tests.unit.test_sequences import event,xml_event
        from sentinelav.monitoring.behavior import BehaviorEngine
        events=[]
        config=self.config(ROOT)
        config['behavior']=True
        monitor=Monitor(config,events.append,lambda _:None)
        monitor.behavior=BehaviorEngine(events.append)
        monitor.exclusions=[]
        for record,kind in ((1,1),(2,13),(3,3)):
            monitor.sysmon_event(dict(RecordId=record,Id=kind,Xml=xml_event(event(record,kind))))
        self.assertEqual(sum(e['kind']=='Suspicious behavior sequence' for e in events),1)
        monitor.sysmon_event(dict(RecordId=4,Id=1,Xml='<broken'))
        self.assertEqual(events[-1]['kind'],'Sysmon correlation omitted')
        events.clear()
        monitor=Monitor(config,events.append,lambda _:None)
        monitor.behavior=BehaviorEngine(events.append)
        monitor.exclusions=[Path('C:/Windows').resolve()]
        for record,kind in ((1,1),(2,13),(3,3)):
            monitor.sysmon_event(dict(RecordId=record,Id=kind,Xml=xml_event(event(record,kind))))
        self.assertFalse(any(e['kind']=='Suspicious behavior sequence' for e in events))

    def test_network_runtime_failure_preserves_folder_monitoring(self):
        with tempfile.TemporaryDirectory() as temp:
            events, states = [], []
            config = self.config(Path(temp))
            config.update(network=True,behavior=True)
            monitor = Monitor(config,events.append,lambda state:(states.append(state),monitor.stop.set()))
            with patch('sentinelav.monitoring.monitoring.psutil.process_iter',return_value=[]), patch('sentinelav.monitoring.monitoring.psutil.net_connections',side_effect=RuntimeError('GetExtendedTcpTable failed')):
                monitor.run()
            self.assertTrue(any(e['kind']=='Network telemetry unavailable' for e in events))
            self.assertFalse(states[0]['network'])
            self.assertEqual(states[0]['folders'],1)
            self.assertIn('Network',states[0]['telemetry_error'])

    def test_worker_combines_network_and_process_context(self):
        with tempfile.TemporaryDirectory() as temp:
            events = []
            config = self.config(Path(temp))
            config.update(network=True,behavior=True,network_indicators=['192.0.2.1/32'])
            monitor = Monitor(config,events.append,lambda _:monitor.stop.set())
            info = dict(pid=42,ppid=1,name='demo.exe',exe='C:/Temp/demo.exe',create_time=1,cmdline=[])
            connection = SimpleNamespace(pid=42,status='ESTABLISHED',raddr=SimpleNamespace(ip='192.0.2.1',port=443))
            with patch('sentinelav.monitoring.monitoring.psutil.process_iter',return_value=[SimpleNamespace(info=info)]), patch('sentinelav.monitoring.monitoring.psutil.net_connections',return_value=[connection]), patch('sentinelav.monitoring.health.psutil.Process') as process:
                process.return_value.create_time.return_value=1
                monitor.run()
            event = next(e for e in events if e.get('score')==95)
            self.assertEqual(event['level'],'Alert')
            self.assertEqual(len(event['indicators']),2)


if __name__ == '__main__':
    unittest.main()

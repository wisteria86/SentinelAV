from sentinelav.paths import RESOURCE_ROOT
import json
from pathlib import Path
import tempfile
import unittest
import threading
import time
from unittest.mock import patch
from PySide6.QtCore import QCoreApplication
from sentinelav.monitoring.background import decode, endpoint, configuration, MAX_MESSAGE, EngineHost
from sentinelav.data.storage import Store


class BackgroundProtocolTests(unittest.TestCase):
    def test_rejects_arbitrary_commands_payloads_and_wrong_types(self):
        for payload in [[], {}, {'version': True, 'command': 'start'},
                        {'version': 1, 'command': ['start']},
                        {'version': 1, 'command': 'execute'},
                        {'version': 1, 'command': 'start', 'path': 'anything.exe'},
                        {'version': 1, 'command': 'poll', 'cursor': -1},
                        {'version': 1, 'command': 'poll', 'cursor': True},
                        {'version': 1, 'command': 'poll', 'epoch': 'x'*65}]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                decode(json.dumps(payload).encode())
        with self.assertRaises(ValueError):
            decode(b' '* (MAX_MESSAGE+1))

    def test_versioned_allowlist(self):
        for command in ('status', 'start', 'stop', 'shutdown', 'poll'):
            self.assertEqual(decode(json.dumps(dict(version=1, command=command)).encode())['command'], command)

    def test_endpoint_is_stable_and_separates_data_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(endpoint(temp), endpoint(Path(temp)/'.'))
            self.assertNotEqual(endpoint(temp), endpoint(Path(temp)/'other'))

    def test_engine_owns_resource_paths_and_validates_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            store=Store(root/'state'/'test.db')
            try:
                store.set('signatures','attacker-controlled.json')
                config=configuration(store,root)
                self.assertEqual(config['signatures'],root/'signatures.json')
                self.assertIn(str(store.path.parent),config['exclusions'])
                store.set('max_mb',True)
                with self.assertRaises(ValueError): configuration(store,root)
                store.set('max_mb',100)
                store.set('watch_folders',['relative-folder'])
                with self.assertRaises(ValueError): configuration(store,root)
                store.set('watch_folders',[])
                store.set('watch_network','yes')
                with self.assertRaises(ValueError): configuration(store,root)
            finally:
                store.db.close()


class EngineLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=QCoreApplication.instance() or QCoreApplication([])

    def test_duplicate_start_stop_and_failure_are_visible(self):
        class FixtureMonitor:
            count=0
            def __init__(self,config,emit,status):
                type(self).count+=1
                self.stop=threading.Event()
                self.emit,self.status=emit,status
            def run(self):
                self.status(dict(folders=0))
                self.stop.wait(2)
        with tempfile.TemporaryDirectory() as temp:
            host=EngineHost(temp,RESOURCE_ROOT,FixtureMonitor)
            try:
                host.start()
                host.start()
                self.assertEqual(FixtureMonitor.count,1)
                host.thread.join(.02)
                host.tick()
                self.assertEqual(host.state,'Active')
                host.stop()
                host.thread.join(2)
                host.tick()
                self.assertEqual(host.state,'Off')
                host.publish('error','Fixture source failed')
                host.tick()
                self.assertEqual(host.state,'Failed')
                self.assertEqual(host.handle(dict(command='status'))['error'],'Fixture source failed')
            finally:
                host.stop()
                if host.thread: host.thread.join(3)
                host.server.close()
                host.timer.stop()
                host.store.db.close()

    def test_replay_gaps_and_response_paging(self):
        with tempfile.TemporaryDirectory() as temp:
            host=EngineHost(temp,RESOURCE_ROOT)
            try:
                for n in range(205):
                    host.events.append((n+1,dict(details='x'*1000,level='Info')))
                host.sequence=205
                reply=host.handle(dict(command='poll',epoch=host.epoch,cursor=0))
                self.assertTrue(reply['gap'])
                self.assertLess(reply['cursor'],205)
                self.assertLess(len(json.dumps(reply).encode()),MAX_MESSAGE)
                next_reply=host.handle(dict(command='poll',epoch=host.epoch,cursor=reply['cursor']))
                self.assertFalse(next_reply['gap'])
                self.assertGreater(next_reply['cursor'],reply['cursor'])
            finally:
                host.server.close()
                host.timer.stop()
                host.store.db.close()

    def test_worker_surfaces_disconnection(self):
        from sentinelav.ui.background_ui import BackgroundWorker
        worker=BackgroundWorker(Path('unused'),attach_only=True)
        errors=[]
        worker.failed.connect(errors.append)
        with patch('sentinelav.ui.background_ui.request',side_effect=[dict(state='Active',epoch='fixture',cursor=0),ConnectionError('fixture disconnect')]):
            worker.run()
        self.assertEqual(len(errors),1)
        self.assertIn('status is unknown',errors[0])


if __name__=='__main__':
    unittest.main()

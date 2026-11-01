import argparse
import json
import os
from pathlib import Path
import sys
from PySide6.QtCore import QLockFile
from PySide6.QtWidgets import QApplication,QMessageBox


def prepare_self_test_dir(path):
    """Atomically reserve a fresh directory, never reuse application or user data."""
    path=path.absolute()
    for part in [path,*path.parents]:
        if part.is_symlink() or part.is_junction():
            raise ValueError('Self-test directory cannot contain linked path components')
    path.mkdir(parents=True,exist_ok=False)
    return path


def main():
    parser=argparse.ArgumentParser(description='SentinelAV desktop protection prototype')
    parser.add_argument('--startup',action='store_true')
    parser.add_argument('--scheduled-scan',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--data-dir',type=Path)
    parser.add_argument('--engine-host',action='store_true',help='Run the non-elevated per-user background engine')
    parser.add_argument('--inspection-worker',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--windows-service',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.windows_service:
        from sentinelav.platform.windows_service import run_service
        try: return run_service()
        except Exception as error:
            if sys.stderr: print(str(error),file=sys.stderr)
            return 1
    if args.inspection_worker:
        from sentinelav.detection.inspection import worker_main
        return worker_main()
    if args.engine_host:
        if args.self_test or args.scheduled_scan or args.startup:
            parser.error('--engine-host cannot be combined with other execution modes')
        from sentinelav.monitoring.background import main as engine_main
        data=args.data_dir or Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'SentinelAV'
        return engine_main(data)
    if args.self_test and not args.data_dir:
        parser.error('--self-test requires an isolated --data-dir')
    if args.self_test:
        try:
            args.data_dir=prepare_self_test_dir(args.data_dir)
        except (OSError,ValueError) as error:
            parser.error('Self-test requires a new, unused directory: '+str(error))
    if args.self_test or args.scheduled_scan:
        os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    app=QApplication(sys.argv[:1])
    data=args.data_dir or Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'SentinelAV'
    data.mkdir(parents=True,exist_ok=True)
    lock=QLockFile(str(data/'instance.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        if not args.scheduled_scan:
            QMessageBox.information(None,'SentinelAV is running','Another SentinelAV instance is using this data directory.')
        return 0
    try:
        if args.scheduled_scan:
            from sentinelav.platform.runtime import run_scheduled
            run_scheduled(data)
            return 0
        from sentinelav.ui.design import configure_app
        configure_app(app)
        from sentinelav.ui.application import Window,ROOT
        window=Window(data_dir=data)
        if args.self_test:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            verification_key=Ed25519PrivateKey.generate()
            verification_key.public_key().verify(verification_key.sign(b'SentinelAV packaging fixture'),b'SentinelAV packaging fixture')
            from sentinelav.detection.engine import Scanner
            from sentinelav.response.response import dpapi
            from sentinelav.data.reporting import snapshot,render_report
            from sentinelav.lab.lab import SimulationRunner,PROFILES
            fixture=data/'packaged-demo.txt'
            fixture.write_text('SENTINELAV_DEMO_THREAT_7C23A')
            result=Scanner(ROOT/'signatures.json',ROOT/'rules').scan([fixture],lambda:False,lambda *a:None)
            assert result['scanned']==1 and len(result['detections'])==1
            from sentinelav.detection.inspection import IsolatedScanner
            isolated_result=IsolatedScanner(ROOT/'signatures.json',ROOT/'rules').scan([fixture],lambda:False,lambda *a:None)
            assert isolated_result['scanned']==1 and len(isolated_result['detections'])==1 and isolated_result['status']=='Complete'
            buffer_result=IsolatedScanner(ROOT/'signatures.json',ROOT/'rules').scan_buffer(b'SENTINELAV_DEMO_THREAT_7C23A')
            assert buffer_result['kind']=='buffer' and buffer_result['detected'] and buffer_result['complete']
            assert dpapi(dpapi(b'packaged crypto test'),True)==b'packaged crypto test'
            lab_run=SimulationRunner(ROOT,data/'lab-workspaces').run(list(PROFILES))
            assert lab_run['status']=='Checks passed' and lab_run['workspace_reset']
            window.store.save_lab_run(lab_run)
            window.store.save_scan(result)
            window.refresh()
            window.show()
            app.processEvents()
            if window.rules_worker:
                if not window.rules_worker.wait(15000):
                    raise RuntimeError('Packaged YARA rule validation did not finish')
                app.processEvents()
            for index in range(window.stack.count()):
                window.navigate(index)
                app.processEvents()
            window.grab().save(str(data/'packaged-preview.png'))
            (data/'security-report.html').write_text(render_report(snapshot(window.store),'html'),encoding='utf-8')
            from sentinelav.detection.signature_db import SignatureIndex
            signature_index=SignatureIndex(ROOT/'signatures.json')
            signature_count=len(signature_index)
            signature_index.close()
            (data/'self-test.json').write_text(json.dumps(dict(status='PASS',signature_count=signature_count,scan=result,buffer=buffer_result,lab=lab_run,checks=['Qt UI','YARA','SHA-256','SQLite','DPAPI','Ed25519 verification','Isolated file and byte-only workers','HTML export','Four safe lab profiles','Fixture cleanup'])),encoding='utf-8')
            window.close()
            return 0
        window.show()
        return app.exec()
    except Exception as error:
        (data/'last-error.txt').write_text(str(error),encoding='utf-8')
        if not args.self_test and not args.scheduled_scan:
            QMessageBox.critical(None,'SentinelAV error',str(error))
        return 1
    finally:
        lock.unlock()

# Purpose: Dispatch desktop, scan-worker, background-engine, service, broker, and guest modes.
# Works with: ui/application.py; monitoring/background.py; detection/inspection.py; lab/qualification/guest.py
# Used by: __main__, ui.application, tests.unit.test_hardening

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
    """Program entry point: read the command line and start the requested mode.

    The same executable plays many roles. Besides the normal desktop window it can run as a headless
    scanner, the background engine, an isolated scan worker, the Windows service, the remediation
    broker, or one of several lab and evaluation jobs. Each mode is checked in turn below; most of
    them are exclusive and refuse to be combined with other options.

    Returns the process exit code (0 means success).
    """
    if '--decoy-role' in sys.argv:
        # A decoy process (see monitoring.deception.processes) runs only its idle body, never the app.
        from sentinelav.monitoring.deception.decoy_process import main as decoy_main
        raise SystemExit(decoy_main())
    parser=argparse.ArgumentParser(description='SentinelAV malware detection, protection and removal')
    parser.add_argument('--startup',action='store_true')
    parser.add_argument('--scheduled-scan',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--data-dir',type=Path)
    parser.add_argument('--scan',metavar='quick|full|PATH',help='Run a headless scan and print JSON; exit 1 if anything is flagged')
    parser.add_argument('--evaluate-corpus',type=Path,help='Read-only manifest-based static evaluation')
    parser.add_argument('--signature-free',action='store_true',help='Strict signature-free corpus evaluation only')
    parser.add_argument('--batch-offset',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--runtime-job',type=Path,help='Explicit offline-guest runtime job; never allowed on the host')
    parser.add_argument('--qualification-job',type=Path,help=argparse.SUPPRESS)
    parser.add_argument('--evaluation-output',type=Path,help='New directory for static evaluation reports')
    parser.add_argument('--static-pilot-key',help=argparse.SUPPRESS)
    parser.add_argument('--static-corpus-key',help=argparse.SUPPRESS)
    parser.add_argument('--static-holdout-key',help=argparse.SUPPRESS)
    parser.add_argument('--zeus-validation-key',help=argparse.SUPPRESS)
    parser.add_argument('--engine-host',action='store_true',help='Run the non-elevated per-user background engine')
    parser.add_argument('--inspection-worker',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--windows-service',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--remediation-broker',help=argparse.SUPPRESS)
    args=parser.parse_args()
    # Lab qualification jobs run inside a disposable test VM and must not mix with any other mode.
    if args.qualification_job:
        if any(value for key,value in vars(args).items() if key!='qualification_job'):
            parser.error('Qualification job mode is exclusive')
        from sentinelav.lab.qualification.guest import main as qualification_main
        return qualification_main(args.qualification_job)
    if args.signature_free and not any((args.evaluate_corpus,args.static_corpus_key,args.static_holdout_key,args.zeus_validation_key)):parser.error('--signature-free requires a corpus evaluation mode')
    if args.batch_offset is not None and not args.evaluate_corpus:parser.error('--batch-offset requires --evaluate-corpus')
    # The remediation broker is a small privileged helper that carries out approved clean-up steps.
    if args.remediation_broker:
        if any(value for key,value in vars(args).items() if key!='remediation_broker'):parser.error('Broker mode is exclusive')
        from sentinelav.platform.remediation_broker import run
        return run(args.remediation_broker)
    # Runtime jobs execute samples inside an offline guest machine only; their result is printed as
    # JSON.
    if args.runtime_job:
        if any((args.evaluate_corpus,args.evaluation_output,args.self_test,args.startup,args.scheduled_scan,args.engine_host,
                args.inspection_worker,args.windows_service,args.data_dir,args.static_pilot_key,args.static_corpus_key,
                args.static_holdout_key,args.zeus_validation_key)):
            parser.error('--runtime-job cannot be combined with other modes')
        from sentinelav.lab.runtime_job import run_job
        from sentinelav.updates.artifacts import bounded_json
        try:
            result=run_job(bounded_json(args.runtime_job,16384))
            if sys.stdout: print(json.dumps(result))
            return 0 if result['status']!='Incomplete' else 2
        except Exception as error:
            if sys.stderr: print(str(error),file=sys.stderr)
            return 2
    # Static lab modes evaluate the detector against a sample corpus, unlocked with a key.
    if args.static_pilot_key or args.static_corpus_key or args.static_holdout_key or args.zeus_validation_key:
        if any((args.evaluate_corpus,args.evaluation_output,args.self_test,args.startup,args.scheduled_scan,args.engine_host,args.inspection_worker,args.windows_service,args.data_dir)):
            parser.error('Static pilot cannot be combined with other modes')
        if sum(bool(v) for v in (args.static_pilot_key,args.static_corpus_key,args.static_holdout_key,args.zeus_validation_key))>1:
            parser.error('Choose one static lab mode')
        try:
            if args.zeus_validation_key:
                from sentinelav.lab.static_corpus import main as pilot_main
                return pilot_main(args.zeus_validation_key,zeus_validation=True,signature_free=args.signature_free)
            elif args.static_holdout_key:
                from sentinelav.lab.static_corpus import main as pilot_main
                return pilot_main(args.static_holdout_key,holdout=True,signature_free=args.signature_free)
            elif args.static_corpus_key:
                from sentinelav.lab.static_corpus import main as pilot_main
            else:
                from sentinelav.lab.static_pilot import main as pilot_main
            if args.static_corpus_key:return pilot_main(args.static_corpus_key,signature_free=args.signature_free)
            return pilot_main(args.static_pilot_key)
        except Exception as error:
            # Inside Windows Sandbox there is no console to read, so leave the error in a file the
            # host can collect.
            if os.environ.get('USERNAME')=='WDAGUtilityAccount':
                Path('C:/SentinelAV-Test/static-pilot-error.txt').write_text(str(error)[:2000],encoding='utf-8')
            return 16
    # Corpus evaluation: scan a list of known files read-only and write a report of what was
    # detected.
    if args.evaluate_corpus:
        if not args.evaluation_output or any((args.self_test,args.startup,args.scheduled_scan,args.engine_host,args.inspection_worker,args.windows_service,args.data_dir)):
            parser.error('--evaluate-corpus requires --evaluation-output and no other execution mode')
        from sentinelav.lab.corpus_evaluation import main as evaluate_main
        return evaluate_main([str(args.evaluate_corpus),'--output',str(args.evaluation_output)]+(['--signature-free'] if args.signature_free else [])+(['--batch-offset',str(args.batch_offset)] if args.batch_offset is not None else []))
    if args.evaluation_output:
        parser.error('--evaluation-output requires --evaluate-corpus')
    # Everything below here is a long-running role: the Windows service, a scan worker, or the
    # background engine.
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
        try:return engine_main(data)
        except Exception as error:
            if sys.stderr:print(str(error),file=sys.stderr)
            return 1
    # Headless scan from the command line: prints JSON and exits 1 if anything was flagged.
    if args.scan:
        if args.self_test or args.scheduled_scan or args.startup:
            parser.error('--scan cannot be combined with other execution modes')
        from sentinelav.platform.cli_scan import run as cli_scan
        try:return cli_scan(args.scan,args.data_dir or Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'SentinelAV')
        except Exception as error:
            if sys.stderr:print(str(error),file=sys.stderr)
            return 2
    if args.self_test and not args.data_dir:
        parser.error('--self-test requires an isolated --data-dir')
    if args.self_test:
        try:
            args.data_dir=prepare_self_test_dir(args.data_dir)
        except (OSError,ValueError) as error:
            parser.error('Self-test requires a new, unused directory: '+str(error))
    if args.self_test or args.scheduled_scan:
        os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    # From here on we are starting the normal desktop application.
    app=QApplication(sys.argv[:1])
    data=args.data_dir or Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'SentinelAV'
    data.mkdir(parents=True,exist_ok=True)
    # Only one copy of SentinelAV may use a data folder at a time; a lock file enforces that.
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
        # Real desktop launches protect by default; self-tests stay isolated from the real profile.
        window=Window(data_dir=data,protect_by_default=not args.self_test)
        # Self-test mode: exercise every major component once against harmless fixtures, then write
        # the results to self-test.json. Packaging uses this to prove a build actually works.
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
            from sentinelav.lab.response_check import check_response_ui
            response_result=check_response_ui(app,window,data)
            from sentinelav.lab.advanced_check import check_advanced
            advanced_result=check_advanced(data)
            from sentinelav.lab.corpus_evaluation import create_demo,evaluate
            corpus_result=evaluate(create_demo(data/'evaluation-fixtures'))
            expected_outcomes={'ordinary.txt':'not_detected','renamed.bin':'detected','utf16.txt':'detected',
                               'nested.zip':'detected','unsupported.7z':'unavailable'}
            if {r['path']:r['outcome'] for r in corpus_result['rows']}!=expected_outcomes:
                raise RuntimeError('Static evaluation fixture outcomes differ from expected coverage')
            (data/'corpus-evaluation.json').write_text(json.dumps(corpus_result,indent=2),encoding='utf-8')
            if window.rules_worker:
                if not window.rules_worker.wait(15000):
                    raise RuntimeError('Packaged YARA rule validation did not finish')
                app.processEvents()
            # Visit every page of the window so that any page that fails to draw is caught.
            for index in range(window.stack.count()):
                window.navigate(index)
                app.processEvents()
            window.grab().save(str(data/'packaged-preview.png'))
            (data/'security-report.html').write_text(render_report(snapshot(window.store),'html'),encoding='utf-8')
            from sentinelav.detection.signature_db import SignatureIndex
            signature_index=SignatureIndex(ROOT/'signatures.json')
            signature_count=len(signature_index)
            signature_index.close()
            advanced_checks=['Normalized-content detection']
            if advanced_result['emulation'].get('api_calls')==1: advanced_checks.append('Emulated Win32 dispatch')
            else: advanced_checks.append('Emulation unavailable: see advanced evidence')
            (data/'self-test.json').write_text(json.dumps(dict(status='PASS',signature_count=signature_count,scan=result,buffer=buffer_result,lab=lab_run,response=response_result,advanced=advanced_result,checks=['Qt UI','YARA','SHA-256','SQLite','DPAPI','Ed25519 verification','Isolated file and byte-only workers','HTML export','Four safe lab profiles','Quarantine/restore Qt controls and workers','Restore no-overwrite','Response audit','Fixture cleanup']+advanced_checks)),encoding='utf-8')
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

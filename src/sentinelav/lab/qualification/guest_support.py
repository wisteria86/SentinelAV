# Purpose: Prepare fixed fixtures, project scan evidence, and launch the guest engine.
# Works with: data.storage, lab.qualification.catalog, lab.qualification.guest_context,
#   lab.qualification.guest_process, lab.static_corpus
# Used by: lab.qualification.corpus_inputs, lab.qualification.guest, lab.qualification.guest_lifecycle,
#   lab.qualification.guest_telemetry

"""Typed guest-only case executor. Never accepts arbitrary commands or binaries."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

BASE=Path('C:/SentinelAV-Test')
from .guest_context import BASE, ps, options


def projection(row,mode,versions):
    """Shrink one evaluation row to the compact measurement record the host keeps (identity, coverage,
    verdicts, model scores, emulation summary).
    """
    scan=row.get('scan',{});model=row.get('candidate_model',{});nn=row.get('candidate_neural',{})
    emu=scan.get('advanced_analysis',{}).get('coverage',{}).get('emulation',{})
    compact={k:emu.get(k) for k in ('status','api_attempts','instructions_observed','termination_reason')}
    compact['diagnostics']=[{k:v.get(k) for k in ('kind','library','api')} for v in emu.get('diagnostics',[])[:3]]
    return dict(sha256=row['sha256'],label=row['label'],mode=mode,phase='inspection',versions_digest=versions,
        format=scan.get('file_format',{}).get('format','Unavailable'),
        available=bool(row.get('postcheck_unchanged') and scan.get('scanned')==1),coverage_complete=row.get('coverage_complete',False),
        confirmed=bool(scan.get('detections')),evidence_linked=bool(scan.get('detections')),
        review=bool(scan.get('advanced_review_total')),learned_review=bool(model.get('review') or nn.get('review')),model_score=model.get('model_score'),neural_score=nn.get('model_score'),
        neural_status=nn.get('status'),neural_bytes_examined=nn.get('bytes_examined'),neural_bytes_total=nn.get('bytes_total'),
        model_id=model.get('model_id'),neural_id=nn.get('model_id'),signature_policy=scan.get('signature_policy',{}),
        emulation=compact,
        errors=[str(e)[:250] for e in scan.get('errors',[])[:2]],qualification=False,independently_selected=False)


def prepare(context,group):
    """Record the signature status of the benign control files, then prepare the fixed sealed corpus
    for a group (without scanning yet). Returns the manifest path.
    """
    from sentinelav.lab.static_corpus import main,BENIGN_NAMES
    controls=[]
    for name in BENIGN_NAMES:
        source=Path(os.environ['WINDIR'])/'System32'/name
        # Paths are a fixed program-owned list, never specimen supplied.
        escaped=str(source).replace("'","''")
        try:
            s=json.loads(ps("$s=Get-AuthenticodeSignature -LiteralPath '"+escaped+"';@{status=[string]$s.Status;signer=[string]$s.SignerCertificate.Subject}|ConvertTo-Json"))
            controls.append(dict(name=name,signature_status=s['status'],signer=s['signer'],sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
        except Exception:controls.append(dict(name=name,signature_status='Unavailable'))
    (BASE/'benign-provenance.json').write_text(json.dumps(controls),encoding='utf-8')
    return main(context['transfer_key'],holdout=group=='holdout',zeus_validation=group=='zeus',signature_free=True,prepare_only=True)


def functional(modules):
    """Run approved bundled unit-test modules inside the guest and report how many ran and failed.
    """
    from .catalog import FUNCTIONAL
    allowed={n for names in FUNCTIONAL.values() for n in names}
    if not modules or set(modules)-allowed:raise ValueError('Unapproved functional test module')
    # These are program-bundled tests, never files from the specimen directory.
    loader=unittest.TestLoader();suite=unittest.TestSuite()
    for name in modules:suite.addTests(loader.loadTestsFromName('tests.unit.'+name))
    stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=1).run(suite)
    return dict(tests_executed=result.testsRun>0,tests=result.testsRun,failures=len(result.failures)+len(result.errors),
        skipped=len(result.skipped),details=stream.getvalue()[-8000:],synthetic=True,qualification_evidence=False)


def selftest(root):
    """Run the packaged app's --self-test inside the guest and report whether it passed."""
    p=subprocess.run([sys.executable,'--self-test','--data-dir',str(root/'selftest')],timeout=180,creationflags=subprocess.CREATE_NO_WINDOW)
    result=json.loads((root/'selftest/self-test.json').read_text())
    return dict(selftest_passed=p.returncode==0 and result.get('status')=='PASS',response_journal_probe=result.get('response',{}),synthetic=True)


def start_engine(root,mode,context,filesystem_only=False):
    """Configure and start the background engine in the guest, watching a fresh folder, and wait until
    it accepts commands.

    Returns (process, data folder, watched folder, Qt app).
    """
    from sentinelav.data.storage import Store
    from sentinelav.monitoring.background import request
    from sentinelav.platform.runtime import launch_command
    from PySide6.QtCore import QCoreApplication
    app=QCoreApplication.instance() or QCoreApplication([])
    data=root/'engine';watch=root/'watched';watch.mkdir();data.mkdir()
    store=Store(data/'sentinelav.db')
    for key,value in dict(watch_folders=[str(watch)],watch_processes=not filesystem_only,
        watch_sysmon=not filesystem_only,watch_behavior=not filesystem_only,watch_network=False,
        watch_app_changes=not filesystem_only,evaluation_attestation=True,inspection_options=options(mode),
        auto_response=dict(enabled=False),artifact_updates=dict(enabled=False)).items():store.set(key,value)
    store.db.close()
    from .guest_process import launch_engine
    process=launch_engine(data,context)
    (root/'engine-launch.json').write_text(json.dumps(process.evaluation_launch))
    try:
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if process.poll() is not None:break
            try:
                request(data,'start');return process,data,watch,app
            except (ConnectionError,RuntimeError):time.sleep(.2)
        diagnostic=data/'engine-startup-error.json'
        detail=json.loads(diagnostic.read_text()) if diagnostic.exists() and diagnostic.stat().st_size<8192 else {}
        raise RuntimeError('Background engine did not start (exit '+str(process.poll())+'): '+str(detail))
    except BaseException:
        if process.poll() is None:process.kill()
        process.wait();raise

# Purpose: Dispatch typed guest cases and export their observations or diagnostics.
# Works with: lab.corpus_evaluation, lab.qualification.contracts, lab.qualification.guest_context,
#   lab.qualification.guest_inventory, lab.qualification.guest_lifecycle
# Used by: entrypoint, lab.qualification.disk_pressure, tests.unit.test_harness_storage

"""Typed guest-only case executor. Never accepts arbitrary commands or binaries."""
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import unittest
import uuid
import zlib
from .contracts import CaseDefinition,Observation,digest,identifier,bounded
from .reporting import redact
from sentinelav.paths import RESOURCE_ROOT

BASE=Path('C:/SentinelAV-Test')


from .guest_context import ps, guard, options
from .guest_support import projection, prepare, functional, selftest, start_engine
from .guest_telemetry import telemetry_case
from .guest_lifecycle import deployment, performance, soak


def execute(context):
    if not guard(context):raise ValueError('Registered offline test guest required before reading specimens')
    case=CaseDefinition(**context['case']);nonce=identifier(context['nonce']);root=BASE/'Qualification'/nonce
    root.mkdir(parents=True,exist_ok=False)
    measurements={};complete=True
    if case.action=='functional':measurements=functional(case.parameters['modules'])
    elif case.action=='selftest':measurements=selftest(root)
    elif case.action=='zoo_static':
        from .zoo_guest import execute as zoo_execute
        measurements=zoo_execute(context,root)
    elif case.action in ('live','telemetry','recovery'):measurements,complete=telemetry_case(root,case,context)
    elif case.action in ('inspect','benign'):
        from sentinelav.lab.corpus_evaluation import evaluate
        manifest=prepare(context,case.parameters.get('group','base'))
        if case.action=='benign':
            data=json.loads(manifest.read_text());data['files']=[e for e in data['files'] if e['label']=='benign'];manifest.write_text(json.dumps(data))
        result=evaluate(manifest,options=options(case.mode))
        measurements=dict(samples=[projection(r,case.mode,context['versions_digest']) for r in result['rows']],
            identity_checks_passed=all(r.get('postcheck_unchanged') for r in result['rows']),
            false_confirmed=sum(bool(r.get('scan',{}).get('detections')) for r in result['rows'] if r['label']=='benign'),
            unavailable=sum(not r.get('coverage_complete') for r in result['rows']),
            omissions=json.loads((manifest.parent.parent/'report.json').read_text()).get('corpus_plan',{}))
        # Inspection omissions don't erase completed statistical model evidence.
        complete=measurements['identity_checks_passed']
        if case.action=='benign':
            measurements['control_observations']=measurements.pop('samples')
    elif case.action=='deployment':measurements=deployment(root)
    elif case.action=='performance':measurements=performance(root,context)
    elif case.action=='soak':measurements,complete=soak(root,case,context)
    elif case.action in ('inventory','recurrence','comparison'):
        from .guest_inventory import execute as inventory_execute
        measurements,complete=inventory_execute(context,root)
    else:raise ValueError('Unsupported typed case action')
    try:
        measurements['environment']=json.loads(ps("$w=Get-CimInstance Win32_OperatingSystem;$d=Get-MpComputerStatus -ErrorAction SilentlyContinue;@{os=$w.Version;build=$w.BuildNumber;identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;defender_running=$d.AMServiceEnabled;defender_realtime=$d.RealTimeProtectionEnabled}|ConvertTo-Json -Compress"))
    except Exception:measurements['environment']=dict(status='Unavailable')
    observation=asdict(Observation(case.id,context['versions_digest'],redact(measurements),[str(root/'journal.json')],complete,
        int(measurements.get('losses',0))))
    (root/'journal.json').write_text(json.dumps(redact(measurements),allow_nan=False),encoding='utf-8')
    raw=json.dumps(observation,separators=(',',':'),allow_nan=False).encode()
    if len(raw)>65536:raise ValueError('Guest summary export exceeds 64 KiB; full journal remains guest-local')
    (root/'export.bin').write_bytes(zlib.compress(raw,9))
    return root


def main(path):
    path=Path(path).absolute()
    from sentinelav.workspace import unlinked
    unlinked(path)
    if not path.is_relative_to(BASE/'Jobs') or path.stat().st_size>1024*1024:raise ValueError('Fixed guest job location required')
    context=json.loads(path.read_text());identifier(context['nonce'])
    if not guard(context):raise ValueError('Offline guest identity not established; no guest outputs created')
    try:execute(context);return 0
    except Exception as e:
        # Diagnostics only; never return job contents/transfer keys.
        result=BASE/'Qualification'/context['nonce'];result.mkdir(parents=True,exist_ok=True)
        error=dict(error=type(e).__name__,reason=redact(str(e)),blocked=isinstance(e,FileNotFoundError))
        diagnostics={}
        for name in ('probe-phase.json','engine-launch.json','engine/engine-startup-error.json','telemetry-failure.json'):
            file=result/name
            if file.is_file() and file.stat().st_size<=16384:
                try:diagnostics[name]=redact(json.loads(file.read_text()))
                except (OSError,ValueError):pass
        error['diagnostics']=diagnostics
        (result/'error.json').write_text(json.dumps(error),encoding='utf-8')
        (result/'export.bin').write_bytes(zlib.compress(json.dumps(error).encode()))
        return 72 if error['blocked'] else 73

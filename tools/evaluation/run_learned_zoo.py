# Purpose: Strict-only static/virtual evaluation of the eight existing pinned specimens.
# Works with: lab.static_corpus, response.response, workspace
# Used by: tools.evaluation.audit_learned_zoo

"""Strict-only static/virtual evaluation of the eight existing pinned specimens.

Raw bytes stay guest-local. Host transport returns only bounded numeric flags,
quantized classifier scores and SHA-256 identity metadata. No native sample launch.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from sentinelav.workspace import Workspace
from sentinelav.response.response import dpapi
from sentinelav.lab.static_corpus import SPECS,HOLDOUT_SPECS,ZEUS_VALIDATION_SPECS,REVISION,BENIGN_NAMES


def invoke(guest,code,timeout=60):
    encoded=base64.b64encode(code.encode('utf-16le')).decode()
    process=subprocess.run(['wsb.exe','exec','--id',guest,'-r','ExistingLogin','-c','powershell.exe -NoProfile -EncodedCommand '+encoded,'--raw'],
        capture_output=True,timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
    if process.returncode or len(process.stdout)>65536:raise RuntimeError('Guest control transport failed')
    result=json.loads(process.stdout)
    if type(result.get('ExitCode')) is not int:raise ValueError('Missing guest status')
    return result['ExitCode']


CONTROL=r'''
$ErrorActionPreference='Stop'
if($env:USERNAME -ne 'WDAGUtilityAccount' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or @(Get-NetAdapter | Where-Object Status -eq 'Up').Count){exit 80}
if((Get-Content 'C:\SentinelAV-Test\preflight.json' -Raw | ConvertFrom-Json).kit_id -ne '__KIT__'){exit 81}
$names=@('cmd.exe','whoami.exe','notepad.exe','kernel32.dll','user32.dll','advapi32.dll','crypt32.dll','ntdll.dll','gdi32.dll','WindowsPowerShell/v1.0/powershell.exe')
$controls=@()
foreach($name in $names){
 $path=Join-Path ($env:WINDIR+'\System32') $name
 try{$before=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();$s=Get-AuthenticodeSignature -LiteralPath $path;$after=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();if($before -ne $after){throw 'Changed control'};$controls+=@{name=$name;sha256=$after;signature_status=[string]$s.Status;signer=[string]$s.SignerCertificate.Subject}}
 catch{$controls+=@{name=$name;signature_status='Unavailable'}}
}
$controls | ConvertTo-Json -Depth 4 | Set-Content 'C:\SentinelAV-Test\benign-provenance.json' -Encoding utf8
$p=Start-Process 'C:\SentinelAV-Test\App\SentinelAV.exe' -ArgumentList @('__MODE__','__KEY__','--signature-free') -WindowStyle Hidden -PassThru
try{if(!$p.WaitForExit(900000)){$p.Kill();exit 83};exit $p.ExitCode}finally{$p.Dispose()}
'''

PREFIX=r'''
$ErrorActionPreference='Stop'
$pointer=Get-Content 'C:\SentinelAV-Test\static-corpus-latest.json' -Raw | ConvertFrom-Json
if($pointer.report -notmatch '^C:\\SentinelAV-Test\\StaticCorpus-[0-9a-f]{32}\\report\.json$'){exit 90}
if((Get-Item -LiteralPath $pointer.report).Length -gt 67108864){exit 91}
$r=Get-Content -LiteralPath $pointer.report -Raw | ConvertFrom-Json
if($r.signature_free -ne $true -or $r.sample_execution -ne $false -or $r.response_actions -ne $false){exit 92}
'''


def metadata(guest,name,kind,offset=0):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('Invalid fixed row name')
    code=PREFIX+"\n$row=@($r.rows | Where-Object path -eq '"+name+"');"+("if($row.Count -eq 0){exit 1073741824};" if kind=='flags' else '')+"if($row.Count -ne 1){exit 93};$row=$row[0]\n"
    if kind=='flags':
        code+=r'''
$v=1
if($row.candidate_model.status -eq 'Complete'){$v=$v -bor 2}
if($row.candidate_neural.status -eq 'Complete'){$v=$v -bor 4}
if($row.candidate_model.review -eq $true){$v=$v -bor 8}
if($row.candidate_neural.review -eq $true){$v=$v -bor 16}
if($row.coverage_complete){$v=$v -bor 32}
if($row.postcheck_unchanged){$v=$v -bor 64}
$p=$row.scan.signature_policy
if($p.signature_free -eq $true -and $p.hashes -eq $false -and $p.yara -eq $false -and $p.test_markers -eq $false -and $p.amsi -eq $false -and $p.reputation -eq $false -and $row.definitions.count -eq 0 -and $row.yara.status -eq 'Disabled'){$v=$v -bor 128}
exit (1073741824+$v)
'''
    elif kind=='scores':
        code+=r'''
$a=0;$b=0
if($null -ne $row.candidate_model.model_score){$a=[int][Math]::Round(10000*[double]$row.candidate_model.model_score)}
if($null -ne $row.candidate_neural.model_score){$b=[int][Math]::Round(10000*[double]$row.candidate_neural.model_score)}
if($a -lt 0 -or $a -gt 10000 -or $b -lt 0 -or $b -gt 10000){exit 94}
exit (1073741824+$a+($b -shl 14))
'''
    else:
        if offset not in range(0,64,4):raise ValueError('Invalid digest metadata offset')
        code+="if($row.sha256 -notmatch '^[0-9a-f]{64}$'){exit 95};exit (1073741824+[Convert]::ToInt32($row.sha256.Substring("+str(offset)+",4),16))"
    value=invoke(guest,code)-1073741824
    if value<0 or value>268435455:raise ValueError('Invalid bounded metadata response')
    return value


def main():
    work=Workspace();lab=work.area('lab')/'windows-sandbox'
    state=json.loads((lab/'latest.json').read_text(encoding='utf-8-sig'));guest=state['guest_id']
    running=json.loads(subprocess.check_output(['wsb.exe','list','--raw']))['WindowsSandboxEnvironments']
    if not state.get('active_guest_verified') or not re.fullmatch('[0-9a-f-]{36}',guest) or len(running)!=1 or running[0]['Id']!=guest:raise ValueError('Owned verified offline guest required')
    output=work.run('evaluations','zoo-learned-strict');all_rows=[]
    for group,mode,specs in [('sealed-static-corpus','--static-corpus-key',SPECS),('sealed-static-holdout','--static-holdout-key',HOLDOUT_SPECS),('sealed-zeus-validation','--zeus-validation-key',ZEUS_VALIDATION_SPECS)]:
        key=base64.b64encode(dpapi((lab.parent/group/'transfer-key.dpapi').read_bytes(),True)).decode()
        command=CONTROL.replace('__KIT__',state['kit_id']).replace('__MODE__',mode).replace('__KEY__',key)
        print('Evaluating fixed group:',group,flush=True)
        if invoke(guest,command,1000)!=0:raise RuntimeError('Guest evaluation failed; keep guest-local diagnostics and reset before retry')
        names=[(s['id']+'.bin','malware',s['family']) for s in specs]
        if group=='sealed-static-corpus':names += [('benign-'+n.replace('/','-')+'.bin','benign','Microsoft guest-image control') for n in BENIGN_NAMES]
        with ThreadPoolExecutor(max_workers=4) as pool:
            for name,label,family in names:
                flags=metadata(guest,name,'flags')
                if flags==0:
                    row=dict(path=name,label=label,family=family,unavailable=True,reason='Not imported or control validation unavailable')
                    all_rows.append(row);(output/'partial.json').write_text(json.dumps(all_rows,indent=2));print(json.dumps(row),flush=True);continue
                scores=metadata(guest,name,'scores')
                parts=list(pool.map(lambda i:metadata(guest,name,'sha',i),range(0,64,4)))
                if any(p>65535 for p in parts):raise ValueError('Invalid digest word')
                row=dict(path=name,label=label,family=family,sha256=''.join(f'{p:04x}' for p in parts),
                    model_complete=bool(flags&2),neural_complete=bool(flags&4),model_flag=bool(flags&8),neural_flag=bool(flags&16),
                    coverage_complete=bool(flags&32),postcheck_unchanged=bool(flags&64),signature_free_attested=bool(flags&128),
                    model_score=(scores&16383)/10000 if flags&2 else None,neural_score=(scores>>14)/10000 if flags&4 else None)
                if not row['postcheck_unchanged']:raise ValueError('Input identity not verified after analysis')
                all_rows.append(row)
                (output/'partial.json').write_text(json.dumps(all_rows,indent=2))
                print(json.dumps(row),flush=True)
    report=dict(schema=1,version='0.15.0',source_revision=REVISION,rows=all_rows,guest_id=guest,kit_id=state['kit_id'],
        signature_free=True,sample_native_execution=False,response_actions=False,host_raw_samples=False,
        score_precision=.0001,entire_zoo_repository=False,
        limitations=['Eight selected historical specimens, including one Linux sample; not a representative or training-unseen benchmark.',
            'Classifier flags are research review predictions, not release-validated automatic detections.',
            'Full analysis coverage may remain partial due to unsupported emulation paths.',
            'Numeric metadata is guest-reported; full reports remain guest-local until disposal.'])
    (output/'report.json').write_text(json.dumps(report,indent=2))
    print('REPORT',output/'report.json',flush=True)


if __name__=='__main__':main()

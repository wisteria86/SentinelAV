# Purpose: Run bounded host control commands and decode bounded evidence exports.
# Works with: sibling modules in lab.qualification
# Used by: lab.qualification.backend_hyperv, lab.qualification.backend_sandbox,
#   lab.qualification.backend_transport, lab.qualification.backends

"""Owned guest lifecycle and bounded metadata transport. No writable host share."""
import base64
import json
import os
import subprocess
import time
import zlib


class Blocked(RuntimeError):pass

def run(command,timeout,cancelled,log=None):
    out=log.open('wb') if log else subprocess.PIPE
    process=subprocess.Popen(list(map(str,command)),stdout=out,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    began=time.monotonic()
    try:
        if log:
            while process.poll() is None:
                if cancelled() or time.monotonic()-began>timeout:
                    process.terminate();raise InterruptedError('Operation cancelled or timed out')
                time.sleep(.2)
            raw=b''
        else:
            while True:
                try:raw,_=process.communicate(timeout=.5);break
                except subprocess.TimeoutExpired:
                    if cancelled() or time.monotonic()-began>timeout:
                        process.terminate();raise InterruptedError('Control operation cancelled or timed out')
        if process.returncode:raise RuntimeError('Control operation failed with exit '+str(process.returncode))
        if len(raw)>1024*1024:raise ValueError('Control output too large')
        return raw.decode('utf-8-sig',errors='replace')
    finally:
        if process.poll() is None:process.kill();process.wait()
        if log:out.close()

def powershell(code,timeout=30,cancelled=lambda:False,log=None):
    # A PowerShell 7 parent can export its modules into Windows PowerShell 5.
    # Prefer the child runtime's built-ins; keep the correction process-local.
    prefix="$ProgressPreference='SilentlyContinue';$env:PSModulePath=(Join-Path $PSHOME 'Modules')+';'+$env:PSModulePath;"
    encoded=base64.b64encode((prefix+code).encode('utf-16le')).decode()
    return run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],timeout,cancelled,log)

def quote(value):return "'"+str(value).replace("'","''")+"'"

def read_export(data,maximum=65536):
    decoder=zlib.decompressobj();raw=decoder.decompress(data,maximum+1)
    if len(raw)>maximum or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('Invalid/oversized guest export')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('Guest metadata object required')
    return value

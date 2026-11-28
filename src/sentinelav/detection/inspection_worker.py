# Purpose: Execute bounded JSON scan requests in the isolated worker process.
# Works with: detection.buffer_scan, detection.engine, detection.inspection_protocol,
#   detection.memory_inspection
# Used by: detection.inspection

"""JSON-only scan worker with Windows job limits and bounded transport.

Fault/resource isolation, not a VM or an AppContainer security sandbox.
"""
import ctypes
import base64
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
import time


from .inspection_protocol import MAX_LINE, MAX_REQUEST


def worker_main():
    """Main loop of the isolated scan worker process.

    It reads one JSON request per line from standard input and writes JSON replies to standard
    output. Supported commands are 'initialize' (load the Scanner), 'scan' (scan paths, streaming
    progress and findings), 'buffer' (scan raw bytes) and 'memory' (scan a process's memory). Every
    request is strictly validated, and any error is sent back as an 'error' reply instead of
    crashing the worker.
    """
    from sentinelav.detection.engine import Scanner
    scanner=None
    input_stream=getattr(sys.stdin,'buffer',None)
    output_stream=getattr(sys.stdout,'buffer',None)
    # When started without a console (for example from the packaged app), get the raw standard
    # input/output handles from Windows directly.
    if (input_stream is None or output_stream is None) and os.name=='nt':
        import msvcrt
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.GetStdHandle.argtypes=[wintypes.DWORD]
        kernel.GetStdHandle.restype=wintypes.HANDLE
        if input_stream is None:
            input_stream=os.fdopen(msvcrt.open_osfhandle(int(kernel.GetStdHandle(wintypes.DWORD(-10))),os.O_RDONLY|os.O_BINARY),'rb')
        if output_stream is None:
            output_stream=os.fdopen(msvcrt.open_osfhandle(int(kernel.GetStdHandle(wintypes.DWORD(-11))),os.O_WRONLY|os.O_BINARY),'wb')
    def send(kind,**fields):
        """Write one JSON reply line, replacing it with an error if it is too large."""
        data=json.dumps(dict(protocol=1,type=kind,**fields)).encode()+b'\n'
        if len(data)>MAX_LINE: data=json.dumps(dict(protocol=1,type='error',error='Inspection result exceeded limit; coverage is incomplete')).encode()+b'\n'
        output_stream.write(data)
        output_stream.flush()
    try:
        while True:
            raw=input_stream.readline(MAX_REQUEST+1)
            if not raw: break
            try:
                if len(raw)>MAX_REQUEST or not raw.endswith(b'\n'): raise ValueError('Invalid request framing')
                request=json.loads(raw)
                if not isinstance(request,dict) or request.get('protocol')!=1: raise ValueError('Invalid inspection protocol')
                command=request.get('command')
                if command!='buffer' and len(raw)>128*1024: raise ValueError('Request exceeds command limit')
                if command=='initialize' and scanner is None:
                    config=request['config']
                    if (not isinstance(config,dict) or set(config)!={'signatures','rules','max_mb','exclusions','trusted_hashes','options'}
                            or type(config['max_mb']) is not int or not 1<=config['max_mb']<=1024
                            or not isinstance(config['exclusions'],list) or len(config['exclusions'])>1024
                            or not isinstance(config['trusted_hashes'],list) or len(config['trusted_hashes'])>10000):
                        raise ValueError('Invalid worker configuration')
                    scanner=Scanner(config['signatures'],config['rules'],config['max_mb'],config['exclusions'],config['trusted_hashes'],config['options'])
                    scanner.early_finding=lambda finding:send('finding',finding=finding)
                    result=dict(signature_count=len(scanner.signatures),signature_metadata=scanner.signatures.metadata,yara=scanner.rule_summary,warnings=scanner.warnings)
                elif command=='scan' and scanner is not None:
                    roots=request.get('roots')
                    if not isinstance(roots,list) or not 1<=len(roots)<=10000 or any(not isinstance(p,str) or len(p)>32768 or not Path(p).is_absolute() for p in roots):
                        raise ValueError('Invalid scan paths')
                    skip=request.get('skip',0)
                    if type(skip) is not int or skip<0:raise ValueError('Invalid resume position')
                    last=[0.]
                    sent=[0]
                    def progress(path,scanned,threats):
                        """Forward new findings straight away, and progress at most ten times a second.
                        """
                        detections=scanner.current_scan_result['detections']
                        for finding in detections[sent[0]:]: send('finding',finding=finding)
                        sent[0]=len(detections)
                        if time.monotonic()-last[0]>.1:
                            send('progress',path=path,scanned=scanned,threats=threats)
                            last[0]=time.monotonic()
                    # Announcing each file lets the parent skip exactly the one that hangs or crashes this worker.
                    scanner.file_started=lambda index,path:send('begin',index=index,path=path)
                    scanner.suspicious_sent=0
                    scanner.suspicious_finding=lambda finding:send('suspicious',finding=finding)
                    result=scanner.scan(roots,lambda:False,progress,skip)
                elif command=='buffer' and scanner is not None:
                    from sentinelav.detection.buffer_scan import inspect_buffer,MAX_BUFFER
                    encoded=request.get('content')
                    if set(request)!={'protocol','command','content'} or not isinstance(encoded,str) or len(encoded)>4*((MAX_BUFFER+2)//3):
                        raise ValueError('Invalid buffer request')
                    result=inspect_buffer(scanner,base64.b64decode(encoded,validate=True))
                elif command=='memory' and scanner is not None:
                    from sentinelav.detection.memory_inspection import inspect_memory
                    result=inspect_memory(request['pid'],request['creation'],scanner.analyze_bytes)
                else: raise ValueError('Unsupported worker request')
                send('result',result=result)
            except Exception as error: send('error',error=str(error)[:2000])
    finally:
        if scanner is not None: scanner.signatures.close()
    return 0

# Purpose: Bounded content decoding and container inspection; never evaluates source code.
# Works with: sibling modules in detection
# Used by: detection.advanced_pipeline, tests.unit.test_integrated_analysis

"""Bounded content decoding and container inspection; never evaluates source code."""
import base64
import binascii
import hashlib
import io
import re
import tarfile
import zlib
from collections import deque

SCRIPT_SUFFIXES={'.ps1','.psm1','.js','.jse','.vbs','.vbe','.hta','.bat','.cmd','.wsf'}


def normalized_variants(data,suffix='',max_total=4*1024*1024):
    if len(data)>2*1024*1024: return [],['Script normalization size limit']
    queue=deque([(bytes(data),'original',0)])
    seen={hashlib.sha256(data).digest()}
    variants=[]
    omissions=[]
    total=0
    while queue and len(variants)<16:
        raw,chain,depth=queue.popleft()
        if depth>=3: continue
        candidates=[]
        if raw.startswith((b'\xff\xfe',b'\xfe\xff')) or raw[:256].count(b'\0')>len(raw[:256])//4:
            try: candidates.append((raw.decode('utf-16' if raw[:2] in (b'\xff\xfe',b'\xfe\xff') else 'utf-16le').encode('utf-8'),'utf16'))
            except UnicodeError: pass
        text=raw.decode('utf-8-sig',errors='replace')
        # Only decode complete, bounded literals. No shell, eval, AST execution,
        # Invoke-Expression, COM or script-engine invocation is used here.
        for match in list(re.finditer(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,65536}={0,2}(?![A-Za-z0-9+/=])',text))[:16]:
            try: candidates.append((base64.b64decode(match.group(),validate=True),'base64-literal'))
            except (ValueError,binascii.Error): pass
        if suffix in SCRIPT_SUFFIXES:
            joined=re.sub(r"(['\"])([^'\"\r\n]{0,4096})\1\s*\+\s*(['\"])([^'\"\r\n]{0,4096})\3",
                          lambda m:'"'+m[2]+m[4]+'"',text)
            if joined!=text: candidates.append((joined.encode('utf-8'),'literal-concatenation'))
            escaped=re.sub(r'\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))',
                lambda m:chr(int(m[1] or m[2],16)),text)
            if escaped!=text: candidates.append((escaped.encode('utf-8',errors='replace'),'escaped-literals'))
        for payload,method in candidates:
            digest=hashlib.sha256(payload).digest()
            if digest in seen: continue
            if len(variants)>=16 or total+len(payload)>max_total:
                omissions.append('Normalization variant/byte budget reached')
                continue
            seen.add(digest); total+=len(payload)
            name=chain+'/'+method
            variants.append((name,payload))
            queue.append((payload,name,depth+1))
    if queue: omissions.append('Normalization depth/variant coverage bounded')
    return variants,list(dict.fromkeys(omissions))


def inspect_containers(data,analyze,cancelled=lambda:False):
    """GZIP, TAR and PDF Flate streams, in memory with cumulative limits."""
    findings=[]
    omissions=[]
    expanded=0
    entries=0
    limit=16*1024*1024

    def inspect(name,payload):
        nonlocal expanded,entries
        entries+=1; expanded+=len(payload)
        if cancelled(): raise ValueError('Container inspection cancelled')
        if entries>64 or len(payload)>4*1024*1024 or expanded>limit:
            raise ValueError('Container entry/expansion limit reached')
        names,matches,errors=analyze(payload)
        omissions.extend(name+': '+e for e in errors)
        if names: findings.append(dict(member_chain=[name],member_sha256=hashlib.sha256(payload).hexdigest(),reasons=names,yara_matches=matches))

    try:
        if data.startswith(b'\x1f\x8b'):
            decoder=zlib.decompressobj(16+zlib.MAX_WBITS)
            payload=decoder.decompress(data,4*1024*1024+1)
            if not decoder.eof or decoder.unused_data: omissions.append('GZIP expansion truncated or additional members not inspected')
            inspect('gzip-content',payload)
        elif len(data)>262 and data[257:262]==b'ustar':
            with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
                for index,member in enumerate(archive):
                    if index>=64: raise ValueError('TAR entry limit reached')
                    if not member.isfile():
                        if not member.isdir(): omissions.append('TAR special/link member omitted')
                        continue
                    if member.size>4*1024*1024 or expanded+member.size>limit: raise ValueError('TAR expansion limit')
                    with archive.extractfile(member) as stream: payload=stream.read(member.size+1)
                    inspect('tar-member-'+str(index),payload)
        elif data.startswith(b'%PDF-'):
            omissions.append('PDF partial inspection: no full PDF object/javascript interpreter')
            if len(data)>8*1024*1024: raise ValueError('PDF stream inspection size cap')
            for index,match in enumerate(re.finditer(rb'<<([^<>]{0,8192})>>\s*stream\r?\n',data,re.S)):
                if index>=64: raise ValueError('PDF stream count limit')
                if b'/FlateDecode' not in match[1]: continue
                stop=data.find(b'endstream',match.end(),min(len(data),match.end()+4*1024*1024))
                if stop<0: omissions.append('Unbounded PDF stream omitted'); continue
                decoder=zlib.decompressobj()
                payload=decoder.decompress(data[match.end():stop].rstrip(b'\r\n'),4*1024*1024+1)
                if not decoder.eof: omissions.append('PDF Flate stream incomplete')
                inspect('pdf-flate-'+str(index),payload)
    except (ValueError,OSError,tarfile.TarError,zlib.error) as error:
        omissions.append(str(error))
    return findings,omissions,dict(entries=entries,expanded=expanded)

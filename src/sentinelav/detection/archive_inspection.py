# Purpose: Recursively inspect archives in memory. Never writes member paths or runs contents.
# Works with: detection.archive_formats, detection.file_types
# Used by: detection.engine, detection.scan_flow, tests.unit.test_defense_layers, tests.unit.test_archive_inspection

"""Recursively inspect archives in memory. Never writes member paths or runs contents.

Limits are cumulative across the whole outer file. Reaching one is reported as an
omission, and an extreme expansion ratio is recorded as decompression-bomb evidence.
"""
import hashlib
from pathlib import PurePosixPath
import time

from sentinelav.detection.archive_formats import EXECUTABLE_SUFFIXES,READERS
from sentinelav.detection.file_types import classify

MAX_DEPTH=4
MAX_ENTRIES=4096
MAX_MEMBER=64*1024*1024
MAX_EXPANDED=512*1024*1024
MAX_RATIO=200
SECONDS=60
CONTAINER_KINDS={'zip','tar','gzip','bzip2','xz','7z','rar'}


def container_kind(data,name=''):
    head=bytes(data[:4])
    if not head:return None
    kind=classify(data,PurePosixPath(name).suffix.lower() if name else '')['kind']
    if kind in CONTAINER_KINDS:return kind
    # Self-extractors and appended archives keep a ZIP end record after other content.
    if head[:2]!=b'MZ' and bytes(data).find(b'PK\x05\x06',max(0,len(data)-65558))>=0 and kind not in ('apk','jar','ooxml'):return 'zip'
    return None


def _unsafe(name):
    clean=str(name).replace('\\','/')
    parts=PurePosixPath(clean)
    return parts.is_absolute() or '..' in parts.parts or ':' in clean or '\x00' in clean or len(clean)>1024


def inspect_archive(data,analyze,cancelled=lambda:False,max_depth=MAX_DEPTH,max_entries=MAX_ENTRIES,max_member=MAX_MEMBER,
                    max_expanded=MAX_EXPANDED,max_ratio=MAX_RATIO,seconds=SECONDS):
    """analyze(payload,name) returns (names,matches,errors) or (names,matches,errors,assessment)."""
    findings=[];omissions=[]
    state=dict(entries=0,expanded=0,bomb=False,encrypted_executables=[],opened_encrypted=0,containers=0)
    deadline=time.monotonic()+seconds

    class Stop(Exception):pass

    def member(item,chain,depth):
        if cancelled() or time.monotonic()>deadline:
            omissions.append('Archive inspection cancelled or time limit reached');raise Stop
        state['entries']+=1
        if state['entries']>max_entries:
            omissions.append('Archive entry limit reached');raise Stop
        name=str(item.name).replace('\\','/')
        nested=chain+[name]
        label='!/'.join(nested)
        if item.unsafe:
            omissions.append('Unsafe archive member name/type omitted');return
        if _unsafe(name):
            # A hostile path is only a label here because nothing is written to disk, so still inspect the bytes.
            omissions.append('Unsafe archive member name noted; contents inspected in memory: '+label[:200])
            nested=chain+['unsafe-name'+PurePosixPath(name.replace('\x00','')).suffix[:8]];label='!/'.join(nested)
        declared=item.size
        if declared>=0 and (declared>max_member or state['expanded']+declared>max_expanded):
            omissions.append('Archive expansion/ratio limit: '+label);return
        if declared>=0 and item.compressed and declared>max_ratio*max(1,item.compressed):
            state['bomb']=True
            omissions.append('Archive expansion/ratio limit: '+label);return
        budget=min(max_member,max_expanded-state['expanded'])
        # Decoders raise many error types on corrupt data. A damaged member must never hide the members after it.
        try:payload=item.read(budget)
        except Exception as error:
            if item.encrypted:
                omissions.append('Encrypted archive member could not be opened: '+label)
                if name.casefold().endswith(EXECUTABLE_SUFFIXES):state['encrypted_executables'].append(label)
            else:omissions.append('Archive member unreadable: '+label+': '+str(error)[:120])
            return
        if item.encrypted:state['opened_encrypted']+=1
        state['expanded']+=len(payload)
        if len(payload)>budget or (declared>=0 and len(payload)!=declared):
            if declared<0 and item.compressed and len(payload)>max_ratio*max(1,item.compressed):state['bomb']=True
            omissions.append('Archive member exceeded declared/bounded size: '+label);return
        if declared<0 and item.compressed and len(payload)>max_ratio*max(1,item.compressed):
            state['bomb']=True;omissions.append('Archive expansion/ratio limit: '+label);return
        reply=analyze(payload,name)
        names,matches,errors=reply[:3]
        assessment=reply[3] if len(reply)>3 else None
        omissions.extend(label+': '+str(error) for error in errors)
        if names or (assessment and assessment['verdict']!='Clean'):
            findings.append(dict(member_chain=nested,member_sha256=hashlib.sha256(payload).hexdigest(),reasons=list(names),yara_matches=matches,assessment=assessment))
        visit(payload,nested,depth+1)

    def visit(content,chain,depth):
        kind=container_kind(content,chain[-1] if chain else '')
        if not kind:return
        if depth>=max_depth:
            omissions.append(('Nested archive depth limit reached: ' if kind!='zip' else 'Nested ZIP depth limit reached: ')+'!/'.join(chain));return
        state['containers']+=1
        try:
            for item in READERS[kind](bytes(content)):member(item,chain,depth)
        except Stop:raise
        except Exception as error:
            prefix='ZIP parser failed: ' if kind=='zip' else kind.upper()+' inspection incomplete: '
            omissions.append(prefix+str(error)[:300])

    try:visit(data,[],0)
    except Stop:pass
    return findings,list(dict.fromkeys(omissions)),state


def inspect_zip(data,analyze,cancelled=lambda:False,max_depth=2,max_entries=128,
                max_member=8*1024*1024,max_expanded=32*1024*1024,max_ratio=100,seconds=5):
    """Narrow ZIP-only form kept for callers that supply their own stricter limits."""
    if not bytes(data[:4]).startswith(b'PK') and bytes(data).find(b'PK\x05\x06',max(0,len(data)-65558))<0:
        return [],[],dict(entries=0,expanded=0)
    findings,omissions,state=inspect_archive(data,lambda payload,name:analyze(payload)[:3],cancelled,max_depth,max_entries,max_member,max_expanded,max_ratio,seconds)
    for finding in findings:finding.pop('assessment',None)
    return findings,omissions,state

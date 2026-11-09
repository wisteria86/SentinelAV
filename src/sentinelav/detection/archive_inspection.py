# Purpose: Inspect ZIP members in memory. Never extract paths or execute contents.
# Works with: sibling modules in detection
# Used by: detection.engine, detection.scan_flow, tests.unit.test_defense_layers

"""Inspect ZIP members in memory. Never extract paths or execute contents."""
import io
from pathlib import PurePosixPath
import stat
import time
from zipfile import ZipFile,BadZipFile


def inspect_zip(data,analyze,cancelled=lambda:False,max_depth=2,max_entries=128,
                max_member=8*1024*1024,max_expanded=32*1024*1024,max_ratio=100,seconds=5):
    findings=[]
    omissions=[]
    state=dict(entries=0,expanded=0)
    deadline=time.monotonic()+seconds
    def visit(content,chain,depth):
        if not content.startswith((b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08')) and content.find(b'PK\x05\x06',max(0,len(content)-65558))<0:
            return
        if depth>=max_depth:
            omissions.append('Nested ZIP depth limit reached: '+'!/'.join(chain))
            return
        try:
            with ZipFile(io.BytesIO(content)) as zipped:
                for member in zipped.infolist():
                    if cancelled() or time.monotonic()>deadline:
                        omissions.append('Archive inspection cancelled or time limit reached')
                        return
                    state['entries']+=1
                    if state['entries']>max_entries:
                        omissions.append('Archive entry limit reached')
                        return
                    if member.is_dir(): continue
                    name=member.filename.replace('\\','/')
                    parts=PurePosixPath(name)
                    mode=(member.external_attr>>16)&0xffff
                    if (parts.is_absolute() or '..' in parts.parts or ':' in name or '\x00' in name
                            or len(name)>1024 or stat.S_ISLNK(mode)):
                        omissions.append('Unsafe archive member name/type omitted')
                        continue
                    nested=chain+[name]
                    if member.flag_bits&1:
                        omissions.append('Encrypted ZIP member omitted: '+'!/'.join(nested))
                        continue
                    if (member.file_size>max_member or member.file_size>max_ratio*max(1,member.compress_size)
                            or state['expanded']+member.file_size>max_expanded):
                        omissions.append('Archive expansion/ratio limit: '+'!/'.join(nested))
                        continue
                    with zipped.open(member) as stream:
                        payload=stream.read(min(max_member,max_expanded-state['expanded'])+1)
                    state['expanded']+=len(payload)
                    if len(payload)!=member.file_size or len(payload)>max_member or state['expanded']>max_expanded:
                        omissions.append('Archive member exceeded declared/bounded size')
                        continue
                    names,evidence,errors=analyze(payload)
                    for error in errors: omissions.append('!/'.join(nested)+': '+error)
                    if names:
                        import hashlib
                        findings.append(dict(member_chain=nested,member_sha256=hashlib.sha256(payload).hexdigest(),
                                             reasons=names,yara_matches=evidence))
                    visit(payload,nested,depth+1)
        except (BadZipFile,RuntimeError,NotImplementedError,OSError,ValueError) as error:
            omissions.append('ZIP parser failed: '+str(error)[:300])
    visit(data,[],0)
    return findings,omissions,state

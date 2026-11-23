# Purpose: Explicit managed work storage; never silently falls back to the system disk.
# Works with: sibling modules in sentinelav
# Used by: data.change_journal, lab.qualification.backend_hyperv, lab.qualification.backend_sandbox,
#   lab.qualification.corpus_inputs

"""Explicit managed work storage; never silently falls back to the system disk."""
import json
import os
from pathlib import Path
import shutil
import stat
import uuid
import time

GIB=1024**3
AREAS={'datasets','models','builds','lab','evaluations','cache','licenses','snapshots'}


def unlinked(path):
    path=Path(path).absolute()
    for part in (path,*path.parents):
        if part.is_symlink() or part.is_junction(): raise ValueError('Linked work path refused: '+str(part))
    return path


class Workspace:
    def __init__(self,root=None,quota=80*GIB,reserve=20*GIB):
        self.root=unlinked(root or os.environ.get('SENTINELAV_WORK_ROOT','F:/SentinelAV-Work'))
        self.quota,self.reserve=quota,reserve

    def usage(self):
        total=0
        if not self.root.exists(): return total
        pending=[self.root]
        while pending:
            # Validate each directory on entry. scandir supplies Windows file
            # metadata without repeating ancestor stat calls for every file.
            folder=unlinked(pending.pop())
            with os.scandir(folder) as entries:
                for entry in entries:
                    state=entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(state.st_mode) or getattr(state,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400):
                        raise ValueError('Linked work path refused: '+entry.path)
                    if stat.S_ISDIR(state.st_mode): pending.append(Path(entry.path))
                    else: total+=state.st_size
        return total

    def check(self,additional=0):
        if not self.root.anchor or not Path(self.root.anchor).exists():
            raise OSError('Work drive unavailable: '+str(self.root)+'. Configure a work drive; C: fallback is disabled.')
        probe=self.root
        while not probe.exists(): probe=probe.parent
        if additional<0 or self.usage()+additional>self.quota: raise OSError('SentinelAV work quota exceeded')
        if shutil.disk_usage(probe).free-additional<self.reserve: raise OSError('SentinelAV work drive free-space reserve reached')

    def area(self,name,additional=0):
        if name not in AREAS: raise ValueError('Unknown managed work area')
        self.check(additional)
        path=unlinked(self.root/name); path.mkdir(parents=True,exist_ok=True)
        return path

    def run(self,area,prefix):
        if not prefix.replace('-','').replace('_','').isalnum() or len(prefix)>64: raise ValueError('Invalid run prefix')
        path=self.area(area)/(prefix+'-'+uuid.uuid4().hex)
        path.mkdir(); return path

    def immutable_report(self,report,prefix='report'):
        raw=json.dumps(report,indent=2,allow_nan=False).encode()
        target=self.run('evaluations',prefix)/'report.json'
        self.check(len(raw))
        with target.open('xb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        return target

    def prune_cache(self,days=30,maximum=1024**3):
        """Bounded opt-in retention for regenerable cache namespaces only."""
        if type(days) is not int or not 7<=days<=365 or type(maximum) is not int or not 0<maximum<=4*GIB:
            raise ValueError('Invalid cache retention bounds')
        cutoff=time.time()-days*86400;removed=0;count=0;skipped=0
        for namespace in ('pip','PyInstaller','temporary'):
            base=unlinked(self.root/'cache'/namespace)
            if not base.exists():continue
            for folder,dirs,files in os.walk(base,followlinks=False):
                for name in list(dirs):
                    try:unlinked(Path(folder)/name)
                    except ValueError:dirs.remove(name);skipped+=1
                for name in files:
                    if count>=1000:return dict(files=count,bytes=removed,skipped=skipped,bounded=True)
                    try:
                        path=unlinked(Path(folder)/name);state=path.stat()
                        if state.st_nlink!=1 or state.st_mtime>=cutoff or removed+state.st_size>maximum:continue
                        path.unlink();removed+=state.st_size;count+=1
                    except (OSError,ValueError):skipped+=1
        return dict(files=count,bytes=removed,skipped=skipped,bounded=False)

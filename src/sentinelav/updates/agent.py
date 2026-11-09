# Purpose: Opt-in, signed analysis-data refresh. Only GETs configured artifact URLs.
# Works with: updates.artifacts
# Used by: monitoring.monitor_loop

"""Opt-in, signed analysis-data refresh. Only GETs configured artifact URLs."""
from pathlib import Path
import queue
import threading
import uuid
from sentinelav.updates.artifacts import activate,download,bounded_json


class ArtifactUpdater:
    def __init__(self,config,store,trust):
        if not isinstance(config,dict) or config.get('enabled') is not True: raise ValueError('Update agent is not enabled')
        urls=config.get('urls',{})
        if not isinstance(urls,dict) or not urls or set(urls)-{'model','reputation','policy'}: raise ValueError('Invalid update channels')
        self.interval=config.get('interval_seconds',3600)
        if type(self.interval) is not int or not 900<=self.interval<=7*86400: raise ValueError('Update interval out of range')
        self.urls=dict(urls); self.store=Path(store); self.trust=Path(trust)
        self.stop=threading.Event(); self.events=queue.Queue(maxsize=32)
        self.thread=threading.Thread(target=self.run,name='signed-analysis-updates',daemon=True)
        self.thread.start()

    def report(self,kind,**fields):
        try: self.events.put_nowait(dict(kind=kind,**fields))
        except queue.Full: pass

    def run(self):
        while not self.stop.is_set():
            for kind,url in self.urls.items():
                if self.stop.is_set(): break
                pending=None
                try:
                    for path in (self.store,*self.store.parents):
                        if path.is_symlink() or path.is_junction(): raise ValueError('Linked update store')
                    self.store.mkdir(parents=True,exist_ok=True)
                    pending=self.store/('download-'+uuid.uuid4().hex+'.json')
                    download(url,pending)
                    if self.stop.is_set(): break
                    envelope=bounded_json(pending)
                    active_index=bounded_json(self.store/'active.json',65536) if (self.store/'active.json').exists() else {}
                    # Same-revision responses are verified too; never call an
                    # unauthenticated payload "up to date" solely by its number.
                    from sentinelav.updates.artifacts import verify
                    verify(envelope,bounded_json(self.trust,65536),kind)
                    revision=envelope['manifest']['revision']
                    if revision==active_index.get(kind,{}).get('revision'):
                        from sentinelav.updates.artifacts import active
                        _,current_manifest=active(self.store,self.trust,kind)
                        if current_manifest['payload_sha256']!=envelope['manifest']['payload_sha256']:
                            raise ValueError('Publisher reused a revision with different content')
                        self.report('current',channel=kind,revision=revision)
                    else:
                        record=activate(pending,self.store,self.trust,kind)
                        self.report('updated',channel=kind,revision=record['revision'])
                except Exception as error: self.report('failed',channel=kind,error=str(error)[:300])
                finally:
                    if pending is not None:
                        try: pending.unlink(missing_ok=True)
                        except OSError: pass
            if self.stop.wait(self.interval): break

    def poll(self):
        values=[]
        for _ in range(32):
            try: values.append(self.events.get_nowait())
            except queue.Empty: break
        return values

    def close(self):
        self.stop.set()
        self.thread.join(timeout=35)
        if self.thread.is_alive(): raise RuntimeError('Update request has not finished; shutdown is incomplete')

"""Repeatable harmless throughput and idle monitoring measurements."""
from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
import json
import tempfile
import threading
import time
from pathlib import Path
import psutil
from sentinelav.detection.engine import Scanner
from sentinelav.monitoring.monitoring import Monitor

ROOT=RESOURCE_ROOT
with tempfile.TemporaryDirectory() as temp:
    root=Path(temp)
    for i in range(500):
        (root/f'clean-{i}.txt').write_bytes(b'ordinary sample text\n'*200)
    process=psutil.Process()
    start=time.perf_counter()
    result=Scanner(ROOT/'signatures.json',ROOT/'rules').scan([root],lambda:False,lambda *a:None)
    elapsed=time.perf_counter()-start
    assert result['scanned']==500 and not result['detections']
    monitor=Monitor(dict(folders=[str(root)],processes=False,sysmon=False,max_mb=100,
                         exclusions=[],signatures=ROOT/'signatures.json',rules=ROOT/'rules'),lambda _:None,lambda _:None)
    before=process.cpu_times()
    thread=threading.Thread(target=monitor.run)
    thread.start()
    time.sleep(2)
    monitor.stop.set()
    thread.join(10)
    after=process.cpu_times()
    assert not thread.is_alive()
    data=dict(files=500,scan_seconds=round(elapsed,3),files_per_second=round(500/elapsed),
              rss_mb=round(process.memory_info().rss/1024/1024,1),
              idle_monitor_cpu_seconds=round(after.user+after.system-before.user-before.system,4),
              idle_window_seconds=2,note='Warm local small-file fixture; not a production performance guarantee.')
    output=PROJECT_ROOT/'artifacts/release'/'benchmark.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(data,indent=2))
    print(json.dumps(data))

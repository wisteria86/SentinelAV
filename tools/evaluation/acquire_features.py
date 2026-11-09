# Purpose: Acquire pinned public FEATURE archives only, never specimen binaries.
# Works with: workspace
# Used by: tools.evaluation.prepare_features

"""Acquire pinned public FEATURE archives only, never specimen binaries."""
import argparse
import hashlib
import json
import os
import urllib.request
import uuid
from pathlib import Path
from sentinelav.workspace import Workspace

REVISION='3d23efef7c0f0b702c5024400cfff4c3744a3832'
FILES={
 'Dot_Net_train.zip':(937108923,'b9f6e90ab75293a7ceb9339700586dd033a03d19766282755ee31dfa0836e625'),
 'Dot_Net_test.zip':(220481493,'b74c4181dbd77565fce16ba47c8ab0f7c7044ae6d880d859ec2c27365dea6299'),
 'Win32_train.zip':(12321281336,'6cf9dea847960115f65d405d38b6b09d38c87225c8288dafedf00fed2512b1d4'),
 'Win32_test.zip':(2593425203,'c05f6562dee3ace4195087be918eb00181e33bc31464c671fb5ba00c9dd5dfdb'),
 'Win64_train.zip':(5853142901,'7b050100ce7bd87149bbfca442de3e02d4bf97d51251566caec2581eebe799fd'),
 'Win64_test.zip':(1176459716,'52a5a05c1bfa5bb021bb8b44c2e0afcf8983dfa1c6c0a9d76db393e5c682ce10'),
}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format',choices=('Dot_Net','Win32','Win64','all'),default='Dot_Net')
    args=parser.parse_args();work=Workspace();folder=work.area('datasets')/'ember2024';folder.mkdir(exist_ok=True)
    records=[]
    for name,(size,sha) in FILES.items():
        if args.format!='all' and not name.startswith(args.format+'_'):continue
        target=folder/name
        if not target.exists():
            work.check(size)
            pending=folder/(name+'.'+uuid.uuid4().hex+'.part')
            url='https://huggingface.co/datasets/joyce8/EMBER2024/resolve/'+REVISION+'/'+name
            received=0;last=0
            with urllib.request.urlopen(url,timeout=30) as response,pending.open('xb') as stream:
                if not response.geturl().startswith('https://'):raise ValueError('Feature download left HTTPS')
                while block:=response.read(4*1024*1024):
                    received+=len(block)
                    if received>size:raise ValueError('Feature download exceeded pinned size')
                    stream.write(block)
                    if received-last>=64*1024*1024:
                        work.check();print(json.dumps(dict(file=name,received=received,expected=size)),flush=True);last=received
                stream.flush();os.fsync(stream.fileno())
            if received!=size:raise ValueError('Incomplete feature download')
            digest=hashlib.sha256()
            with pending.open('rb') as stream:
                while raw:=stream.read(4*1024*1024):digest.update(raw)
            if digest.hexdigest()!=sha:raise ValueError('Downloaded feature digest mismatch')
            if target.exists():raise ValueError('Feature destination appeared concurrently; retain verified candidate for review')
            os.replace(pending,target)
        if target.stat().st_size!=size:raise ValueError('Feature archive size mismatch')
        digest=hashlib.sha256()
        with target.open('rb') as stream:
            while raw:=stream.read(4*1024*1024):digest.update(raw)
        if digest.hexdigest()!=sha:raise ValueError('Feature archive digest mismatch')
        records.append(dict(file=name,sha256=sha,bytes=size))
    report=dict(repo='joyce8/EMBER2024',revision=REVISION,license='Apache-2.0',
        files=records,contains='Published static feature JSON, not malware binaries',raw_specimens=False)
    path=work.immutable_report(report,'feature-acquisition');print(path)


if __name__=='__main__':main()

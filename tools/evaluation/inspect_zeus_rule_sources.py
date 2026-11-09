# Purpose: Bounded plain-text extraction of public defensive rule snapshots only.
# Works with: sibling modules in tools.evaluation
# Used by: the Python module loader or CLI entry point

"""Bounded plain-text extraction of public defensive rule snapshots only."""
from pathlib import Path
from zipfile import ZipFile

root=Path('artifacts/evaluations/zeus-review')
for family in ('win.gameover_p2p','win.zeus'):
    with ZipFile(root/(family+'.zip')) as archive:
        files=archive.infolist()
        if len(files)>8 or sum(i.file_size for i in files)>256*1024: raise ValueError('Unexpected source archive bounds')
        for item in files:
            if item.is_dir(): continue
            if '/' in item.filename or '\\' in item.filename or not item.filename.endswith('.yar'): raise ValueError('Unexpected source member')
            raw=archive.read(item)
            text=raw.decode('utf-8')
            (root/item.filename).write_bytes(raw)
            print('SOURCE:',item.filename)
            print(text)

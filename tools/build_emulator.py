# Purpose: Build the pinned Windows x64 Unicorn variant; no mitigation settings change.
# Works with: workspace
# Used by: the Python module loader or CLI entry point

"""Build the pinned Windows x64 Unicorn variant; no mitigation settings change."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
REVISION = '8028ec436f2d9376525352dd38ed9ed6b9f6be10'


def run(*args, cwd=ROOT):
    subprocess.run(args, cwd=cwd, check=True)


def main():
    if os.name != 'nt':
        raise SystemExit('This build requires Windows x64 and MSVC Build Tools.')
    from sentinelav.workspace import Workspace
    workspace=Workspace()
    source = workspace.area('cache')/'unicorn-src'
    patch = ROOT/'native/emulator/unicorn-2.1.4-windows-unwind.patch'
    build = workspace.area('builds')/'native/unicorn-cfg'
    output = workspace.area('builds')/'native/unicorn-runtime'
    if not source.exists():
        run('git', 'clone', '--depth', '1', '--branch', '2.1.4',
            'https://github.com/unicorn-engine/unicorn.git', str(source))
    revision = subprocess.check_output(['git','rev-parse','HEAD'], cwd=source, text=True).strip()
    if revision != REVISION:
        raise SystemExit('Unexpected Unicorn revision; use a separate pinned checkout.')
    changed = subprocess.check_output(['git','diff','HEAD','--no-ext-diff'], cwd=source)
    untracked = subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=source)
    if untracked.strip():
        raise SystemExit('Unicorn checkout contains untracked files; refusing an ambiguous build.')
    if not changed:
        run('git','apply','--check',str(patch),cwd=source)
        run('git','apply',str(patch),cwd=source)
    elif changed != patch.read_bytes():
        raise SystemExit('Unicorn checkout has unrelated changes; refusing to overwrite them.')
    run('cmake','-S',str(source),'-B',str(build),'-G','Visual Studio 17 2022','-A','x64',
        '-DUNICORN_ARCH=x86','-DUNICORN_BUILD_TESTS=OFF','-DUNICORN_INSTALL=OFF',
        '-DUNICORN_LEGACY_STATIC_ARCHIVE=OFF','-DCMAKE_C_FLAGS=/guard:cf /guard:ehcont',
        '-DCMAKE_SHARED_LINKER_FLAGS=/guard:cf /guard:longjmp /guard:ehcont /CETCOMPAT /DYNAMICBASE /NXCOMPAT')
    run('cmake','--build',str(build),'--config','Release','--target','unicorn','--parallel','4')
    output.mkdir(parents=True,exist_ok=True)
    dll = build/'Release/unicorn.dll'
    (output/'unicorn.dll').write_bytes(dll.read_bytes())
    manifest = dict(schema=1, backend='unicorn-windows-unwind-v1', version='2.1.4',
        upstream_revision=REVISION, patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),
        dll_sha256=hashlib.sha256(dll.read_bytes()).hexdigest())
    (output/'emulator-build.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    # Ship corresponding modified source and upstream notices with the native DLL.
    files = subprocess.check_output(['git','ls-files','-z'],cwd=source).decode().split('\0')
    with zipfile.ZipFile(output/'unicorn-corresponding-source.zip','w',zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            if name and (source/name).is_file():
                archive.write(source/name,'unicorn-2.1.4/'+name)
        archive.write(patch,'sentinelav-windows-unwind.patch')
    for name in ('COPYING','COPYING.LGPL2','COPYING_GLIB'):
        (output/name).write_bytes((source/name).read_bytes())
    print('Built native candidate:',output)
    print('Run frozen integration checks before distributing it.')


if __name__ == '__main__':
    main()

# Purpose: Build or package SentinelAV and its declared dependencies.
# Works with: app.py, src/sentinelav, and the matching build or lab scripts
# Used by: the CLI, desktop launcher, or packaging workflow

# PyInstaller onedir bundle. Mutable user data stays outside the installation.
from pathlib import Path
import os
import json
import re
import importlib.util
import sys
from PyInstaller.utils.hooks import collect_dynamic_libs,collect_submodules,collect_data_files,copy_metadata
os.environ['PATH']=os.pathsep.join(p for p in os.environ.get('PATH','').split(os.pathsep) if 'codex-runtimes' not in p.lower())
root=Path(SPECPATH).parent
resources=root/"resources"
signature_datas=[]
analysis_binaries=collect_dynamic_libs('unicorn') if importlib.util.find_spec('unicorn') else []
analysis_imports=collect_submodules('unicorn') if importlib.util.find_spec('unicorn') else []
analysis_datas=[]
if importlib.util.find_spec('mscerts'):
    analysis_datas+=collect_data_files('mscerts')
model_index=resources/'analysis-data/active.json'
if model_index.exists():
    import sys
    sys.path.insert(0,str(root/'src'))
    from sentinelav.updates.artifacts import active
    active(resources/'analysis-data',resources/'trusted-update-keys.json','model')
    index=json.loads(model_index.read_text())
    analysis_datas += [(str(model_index),'analysis-data'),(str(model_index.parent/index['model']['file']),'analysis-data')]
    # The confirmation model must ship with the primary model, or every primary conviction would stand unchecked.
    if 'confirm_model' in index:
        active(resources/'analysis-data',resources/'trusted-update-keys.json','confirm_model')
        analysis_datas.append((str(model_index.parent/index['confirm_model']['file']),'analysis-data'))
for name in ('malconv2-state.npz','malconv2.json'):
    if (resources/'analysis-data'/name).exists():analysis_datas.append((str(resources/'analysis-data'/name),'analysis-data'))
for dependency in ('speakeasy','thrember','lightgbm','py7zr','rarfile','pyzipper','oletools','olefile'):
    if importlib.util.find_spec(dependency):
        analysis_imports+=collect_submodules(dependency)
        analysis_datas+=collect_data_files(dependency,include_py_files=dependency in ('speakeasy','thrember'))
        analysis_binaries+=collect_dynamic_libs(dependency)
        analysis_datas+=copy_metadata('speakeasy-emulator' if dependency=='speakeasy' else dependency)
native_runtime=Path(os.environ.get('SENTINELAV_WORK_ROOT','F:/SentinelAV-Work'))/'builds/native/unicorn-runtime'
native_datas=[]
if (native_runtime/'emulator-build.json').exists():
    import hashlib
    manifest=json.loads((native_runtime/'emulator-build.json').read_text(encoding='utf-8'))
    native_dll=native_runtime/'unicorn.dll'
    if manifest.get('dll_sha256')!=hashlib.sha256(native_dll.read_bytes()).hexdigest():
        raise ValueError('Native emulator build receipt does not match DLL')
    analysis_binaries=[item for item in analysis_binaries if Path(item[0]).name.lower()!='unicorn.dll']
    analysis_binaries.append((str(native_dll),'unicorn/lib'))
    native_datas=[(str(native_runtime/'emulator-build.json'),'.')]+[
        (str(native_runtime/name),'licenses/unicorn') for name in
        ('COPYING','COPYING.LGPL2','COPYING_GLIB','unicorn-corresponding-source.zip')]
sys.path.insert(0,str(root/'src'))
from sentinelav.detection.definition_paths import binaries as clamav_binaries,signature_data_dir
feed_manifest=signature_data_dir(resources)/'active.json'
if feed_manifest.exists():
    if feed_manifest.stat().st_size>16384:
        raise ValueError('Signature manifest exceeds size limit')
    feed=json.loads(feed_manifest.read_text(encoding='utf-8'))
    database=feed.get('database','')
    if not isinstance(database,str) or not re.fullmatch(r'hashes-[0-9a-f]{32}\.sqlite',database):
        raise ValueError('Invalid signature database filename')
    signature_datas=[(str(feed_manifest),'signature-data'),(str(feed_manifest.parent/database),'signature-data')]
a=Analysis([str(root/'app.py')],pathex=[str(root/"src"),str(root)],
    binaries=analysis_binaries,datas=[(str(resources/'rules'),'rules'),(str(resources/'licenses'),'licenses/analysis'),(str(resources/'behavior'),'behavior'),(str(resources/'deception'),'deception'),(str(resources/'assets'),'assets'),
                      (str(resources/'trusted-update-keys.json'),'.'),
                      (str(resources/'runtime-protocol.json'),'.'),
                      (str(root/'docs/DEFINITION-UPDATES.md'),'.'),
                      (str(root/'docs/APP-CHANGES-AND-INDEPENDENT-PROTECTION.md'),'.'),
                      (str(root/'docs/PROTECTED-REMEDIATION.md'),'.'),
                      (str(root/'docs/SIGNATURE-FREE-EVALUATION.md'),'.'),
                      (str(root/'docs/LEARNED-DETECTION.md'),'.'),
                      (str(root/'docs/YARA-REVIEW.md'),'.'),
                      (str(resources/'scripts/process_events.ps1'),'scripts'),
                      (str(root/'scripts/Install-ProtectionService.ps1'),'.'),
                      (str(root/'scripts/Export-AppControlAudit.ps1'),'.'),
                      (str(root/'scripts/Deploy-GuestAppControl.ps1'),'.'),
                      (str(root/'scripts/Manage-AppControl.ps1'),'.'),
                      (str(root/'scripts/Install-KernelCollector.ps1'),'.'),
                      (str(root/'docs/DEFENSE-IMPLEMENTATION.md'),'.'),
                      (str(root/'docs/AMSI-PROVIDER.md'),'.'),
                      (str(root/'docs/GUEST-AMSI-VALIDATION.md'),'.'),
                      (str(resources/'signatures.json'),'.'),(str(root/'README.md'),'.'),
                      (str(root/'docs/HARDENING.md'),'.'),(str(root/'docs/BACKGROUND-ENGINE.md'),'.')]+signature_datas+native_datas+analysis_datas,
    hiddenimports=['tzdata','watchdog.observers.winapi','watchdog.observers.read_directory_changes']+analysis_imports+collect_submodules('tests.unit'),
    hookspath=[],runtime_hooks=[],
    excludes=['torch','torchvision','torchaudio','PySide6.QtWebEngineCore','PySide6.QtWebEngineWidgets','PySide6.QtPdf','PySide6.QtQuick','PySide6.QtQml'],
    noarchive=False)
# Qt 6.12 uses Windows' native, unversioned ICU exports. A build-host Poppler
# ICU with versioned exports must never shadow the operating-system library.
a.binaries=[entry for entry in a.binaries if Path(entry[0]).name.lower() not in ('icuuc.dll','icudt78.dll','icuin.dll')]
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,[],exclude_binaries=True,name='SentinelAV',debug=False,
        bootloader_ignore_signals=False,strip=False,upx=False,console=os.getenv('SENTINEL_CONSOLE')=='1',
        icon=str(resources/'assets/sentinelav.ico'))
coll=COLLECT(exe,a.binaries,a.datas,strip=False,upx=False,name='SentinelAV')
# ClamAV is a separate GPL program run as its own process. Its runtime (no debug symbols) ships beside the app;
# signatures are downloaded by freshclam after installation.
clamav=clamav_binaries()
if clamav:
    import shutil
    target=Path(DISTPATH)/'SentinelAV'/'clamav'
    shutil.rmtree(target,ignore_errors=True)
    shutil.copytree(clamav['home'],target,ignore=shutil.ignore_patterns('*.pdb','*.lib','UserManual','conf_examples'))
# capa (Mandiant, Apache-2.0) is a standalone program that SentinelAV runs on undecided Windows programs.
from sentinelav.detection.capa_engine import locate as capa_locate
capa=capa_locate()
if capa:
    import shutil
    target=Path(DISTPATH)/'SentinelAV'/'capa'
    shutil.rmtree(target,ignore_errors=True);target.mkdir(parents=True)
    shutil.copy2(capa,target/'capa.exe')
# 7-Zip (Igor Pavlov, LGPL-2.1 with the unRAR restriction) opens RAR archives for inspection.
from sentinelav.detection.archive_formats import seven_zip_tool
seven=seven_zip_tool()
if seven:
    import shutil
    target=Path(DISTPATH)/'SentinelAV'/'7zip'
    shutil.rmtree(target,ignore_errors=True);target.mkdir(parents=True)
    for name in ('7z.exe','7z.dll'):shutil.copy2(Path(seven).with_name(name),target/name)

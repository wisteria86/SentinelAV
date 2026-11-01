# PyInstaller onedir bundle. Mutable user data stays outside the installation.
from pathlib import Path
import os
import json
import re
os.environ['PATH']=os.pathsep.join(p for p in os.environ.get('PATH','').split(os.pathsep) if 'codex-runtimes' not in p.lower())
root=Path(SPECPATH).parent
resources=root/"resources"
signature_datas=[]
feed_manifest=resources/'signature-data'/'active.json'
if feed_manifest.exists():
    if feed_manifest.stat().st_size>16384:
        raise ValueError('Signature manifest exceeds size limit')
    feed=json.loads(feed_manifest.read_text(encoding='utf-8'))
    database=feed.get('database','')
    if not isinstance(database,str) or not re.fullmatch(r'hashes-[0-9a-f]{32}\.sqlite',database):
        raise ValueError('Invalid signature database filename')
    signature_datas=[(str(feed_manifest),'signature-data'),(str(feed_manifest.parent/database),'signature-data')]
a=Analysis([str(root/'app.py')],pathex=[str(root/"src"),str(root)],
    binaries=[],datas=[(str(resources/'rules'),'rules'),(str(resources/'assets'),'assets'),
                      (str(resources/'trusted-update-keys.json'),'.'),
                      (str(root/'docs/DEFINITION-UPDATES.md'),'.'),
                      (str(root/'docs/YARA-REVIEW.md'),'.'),
                      (str(resources/'scripts/process_events.ps1'),'scripts'),
                      (str(root/'scripts/Install-ProtectionService.ps1'),'.'),
                      (str(root/'docs/DEFENSE-IMPLEMENTATION.md'),'.'),
                      (str(root/'docs/AMSI-PROVIDER.md'),'.'),
                      (str(resources/'signatures.json'),'.'),(str(root/'README.md'),'.'),
                      (str(root/'docs/HARDENING.md'),'.'),(str(root/'docs/BACKGROUND-ENGINE.md'),'.'),(str(root/'docs/PHASE-7-MALWARE-LAB-PLAN.md'),'.')]+signature_datas,
    hiddenimports=['tzdata','watchdog.observers.winapi','watchdog.observers.read_directory_changes'],
    hookspath=[],runtime_hooks=[],
    excludes=['PySide6.QtWebEngineCore','PySide6.QtWebEngineWidgets','PySide6.QtPdf','PySide6.QtQuick','PySide6.QtQml'],
    noarchive=False)
# Qt 6.12 uses Windows' native, unversioned ICU exports. A build-host Poppler
# ICU with versioned exports must never shadow the operating-system library.
a.binaries=[entry for entry in a.binaries if Path(entry[0]).name.lower() not in ('icuuc.dll','icudt78.dll','icuin.dll')]
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,[],exclude_binaries=True,name='SentinelAV',debug=False,
        bootloader_ignore_signals=False,strip=False,upx=False,console=os.getenv('SENTINEL_CONSOLE')=='1',
        icon=str(resources/'assets/sentinelav.ico'))
coll=COLLECT(exe,a.binaries,a.datas,strip=False,upx=False,name='SentinelAV')

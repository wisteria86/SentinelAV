# Purpose: Choose Quick and Full scan locations from the running Windows profile.
# Works with: monitoring.windows_inventory
# Used by: ui.scan_actions, platform.runtime, entrypoint

"""Choose Quick and Full scan locations from the running Windows profile."""
import ctypes
import os
from pathlib import Path
import re
import string

import psutil

DRIVE_FIXED=3
# The worker's request limit is 128 KiB, so keep the extra program list well inside it.
QUICK_LIMIT=300
EXECUTABLE_REFERENCE=re.compile(r'(?:"([a-zA-Z]:\\[^"]+\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|js))"|([a-zA-Z]:\\[^\s"]+\.(?:exe|dll|scr|com|bat|cmd|ps1|vbs|js)))',re.I)


def fixed_drives():
    """All local fixed drives; network, optical and removable media stay opt-in through Custom Scan."""
    if os.name!='nt':return [Path('/')]
    kernel=ctypes.WinDLL('kernel32')
    kernel.GetDriveTypeW.argtypes=[ctypes.c_wchar_p]
    return [Path(f'{letter}:\\') for letter in string.ascii_uppercase if os.path.exists(f'{letter}:\\') and kernel.GetDriveTypeW(f'{letter}:\\')==DRIVE_FIXED]


def quick_folders():
    """Return the folders a Quick Scan checks: Downloads, Desktop, temporary folders, Startup folders
    and the Public profile (only those that exist).
    """
    home=Path.home();env=os.environ.get
    candidates=[home/'Downloads',home/'Desktop',home/'OneDrive/Desktop',Path(env('TEMP',str(home/'AppData/Local/Temp'))),
        Path(env('APPDATA',str(home/'AppData/Roaming')))/'Microsoft/Windows/Start Menu/Programs/Startup',
        Path(env('PROGRAMDATA','C:/ProgramData'))/'Microsoft/Windows/Start Menu/Programs/Startup',
        Path(env('LOCALAPPDATA',str(home/'AppData/Local')))/'Temp',Path(env('PUBLIC','C:/Users/Public'))]
    seen={};result=[]
    for path in candidates:
        try:key=os.path.normcase(str(path.resolve()))
        except OSError:continue
        if key not in seen and path.is_dir():seen[key]=True;result.append(path)
    return result


def default_watch_folders():
    """Where downloads and droppers land; a person can edit this list on the protection page."""
    home=Path.home();env=os.environ.get
    candidates=[home/'Downloads',home/'Desktop',home/'Documents',Path(env('TEMP',str(home/'AppData/Local/Temp'))),
        Path(env('APPDATA',str(home/'AppData/Roaming')))/'Microsoft/Windows/Start Menu/Programs/Startup']
    return [str(path) for path in candidates if path.is_dir()]


def running_images():
    """Return the file paths of every program that is currently running."""
    images=set()
    for process in psutil.process_iter(['exe']):
        try:
            if process.info.get('exe'):images.add(process.info['exe'])
        except (psutil.Error,OSError):continue
    return images


def _command_targets(text):
    """Yield every program path found inside a command line."""
    for match in EXECUTABLE_REFERENCE.finditer(str(text or '')):
        yield match[1] or match[2]


def persistence_images():
    """Programs named by autorun registry values; unreadable hives simply contribute nothing."""
    if os.name!='nt':return set()
    import winreg
    keys=[(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\Run'),(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        (winreg.HKEY_LOCAL_MACHINE,r'Software\Microsoft\Windows\CurrentVersion\Run'),(winreg.HKEY_LOCAL_MACHINE,r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        (winreg.HKEY_LOCAL_MACHINE,r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')]
    found=set()
    for hive,name in keys:
        try:
            with winreg.OpenKey(hive,name) as key:
                for index in range(winreg.QueryInfoKey(key)[1]):
                    found.update(_command_targets(os.path.expandvars(str(winreg.EnumValue(key,index)[1]))))
        except OSError:continue
    return found


def quick_targets():
    """Folders where malware usually lands, plus whatever is running or set to start."""
    folders=quick_folders()
    keys=[os.path.normcase(str(folder)) for folder in folders]
    files=[]
    for image in sorted(running_images()|persistence_images()):
        lowered=os.path.normcase(image)
        if any(lowered.startswith(key+os.sep) for key in keys):continue
        if os.path.isfile(image):files.append(Path(image))
        if len(files)>=QUICK_LIMIT:break
    return folders+files


def full_targets():
    """A Full Scan covers every local fixed drive."""
    return fixed_drives()


def targets(kind):
    """kind is 'Quick' or 'Full'; Custom scans pass their own roots."""
    if kind=='Quick':return quick_targets()
    if kind=='Full':return full_targets()
    raise ValueError('Unknown scan kind')

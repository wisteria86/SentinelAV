# Purpose: Route bytes to per-format static indicator modules. Nothing here executes content.
# Works with: detection.threat_score, detection.indicators.pe, strings, scripts, documents, unix, mobile, dos
# Used by: detection.file_analysis

"""Route bytes to per-format static indicator modules. Nothing here executes content."""
from sentinelav.detection.indicators import documents,dos,mobile,pe,scripts,strings,unix

SCRIPT_KINDS={'powershell','vbscript','javascript','batch','shell','python','perl','php','ruby','lua','html'}
STRING_SCAN_KINDS={'pe','dos_mz','elf','macho','dex','apk','jar','class','com','lnk','data'}


def collect(data,file_type,metadata=None,analysis=None,malformed='',omissions=None):
    """Return indicators for one object; a parser failure becomes evidence or an omission, never a pass."""
    kind=file_type['kind']
    omissions=[] if omissions is None else omissions
    found=[]
    runners=[]
    if kind=='pe':runners.append(lambda:pe.indicators(data,metadata,analysis,malformed))
    elif kind in ('dos_mz','com'):runners.append(lambda:dos.indicators(data,kind))
    elif kind=='elf':runners.append(lambda:unix.elf_indicators(data))
    elif kind=='macho':runners.append(lambda:unix.macho_indicators(data))
    elif kind in ('apk','dex'):runners.append(lambda:mobile.android_indicators(data,kind))
    elif kind in ('jar','class'):runners.append(lambda:mobile.java_indicators(data,kind))
    elif kind in ('ole','ooxml'):runners.append(lambda:documents.office_indicators(data,omissions))
    elif kind=='pdf':runners.append(lambda:documents.pdf_indicators(data))
    elif kind=='rtf':runners.append(lambda:documents.rtf_indicators(data))
    elif kind=='lnk':runners.append(lambda:strings.shortcut_indicators(data))
    if kind in SCRIPT_KINDS:runners.append(lambda:scripts.indicators(data,kind,omissions))
    if kind in STRING_SCAN_KINDS:runners.append(lambda:strings.indicators(data,kind))
    for run in runners:
        try:found.extend(run())
        except Exception as error:omissions.append(f'{kind} indicator analysis incomplete: {type(error).__name__}: {str(error)[:160]}')
    return found

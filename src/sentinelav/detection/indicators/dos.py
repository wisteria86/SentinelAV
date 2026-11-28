# Purpose: Static traits of DOS executables, a format with little structure to analyze.
# Works with: detection.threat_score
# Used by: detection.indicators

"""Static traits of DOS executables, a format with little structure to analyze.

These programs are obsolete, so ordinary software rarely appears in this format,
but detection here is inherently weak. Evaluations report that limit openly.
"""
import re
from sentinelav.detection.threat_score import indicator

DOS_CALL=b'\xcd\x21'
DISK_WRITE=(b'\xcd\x26',b'\xcd\x13')
FILE_MASK=re.compile(rb'\*\.(?:com|exe)\x00',re.I)
HOST_NAMES=re.compile(rb'command\.com|comspec=',re.I)


def indicators(data,kind):
    """Look for the classic routines of old DOS file-infecting viruses: searching for programs, writing
    to the disk directly, jumping to the end of the file, and staying resident in memory.
    """
    view=bytes(data[:2*1024*1024]);found=[]
    if FILE_MASK.search(view) and DOS_CALL in view:
        found.append(indicator('searches_for_programs','replication',40,'Searches for .COM or .EXE files using DOS calls, the core of a file-infecting virus.',category='Virus',evidence=FILE_MASK.search(view).group().rstrip(b'\0').decode('ascii','replace')))
    if HOST_NAMES.search(view) and DOS_CALL in view:
        found.append(indicator('references_command_interpreter','structure',12,'A DOS program references the command interpreter directly.',category='Virus'))
    if any(call in view for call in DISK_WRITE):
        found.append(indicator('direct_disk_interrupts','destruction',18,'Calls BIOS or DOS disk interrupts directly instead of using the file system.',category='Virus'))
    # Appending viruses patch the host's first bytes to jump to the end of the file.
    if kind=='com' and len(view)>=256 and view[0]==0xE9:
        target=int.from_bytes(view[1:3],'little')+3
        if target>=len(view)*.6 and target<len(view):
            found.append(indicator('entry_jumps_to_file_end','structure',24,'Execution jumps immediately to the end of the file, as appending viruses arrange.',category='Virus'))
    if re.search(rb'\xb4\x4e|\xb4\x4f',view) and re.search(rb'\xb4\x40',view) and re.search(rb'\xb8\x00\x42|\xb8\x02\x42',view):
        found.append(indicator('find_seek_write_sequence','replication',30,'Uses the DOS find-file, seek and write functions together, the infection routine of a file virus.',category='Virus'))
    if re.search(rb'\xcd\x27|\xb8\x00\x31|\xb4\x31',view) and re.search(rb'\xb8\x21\x25|\xb4\x25|\x25\x21',view):
        found.append(indicator('resident_interrupt_hook','structure',22,'Stays resident in memory and replaces an interrupt handler.',category='Virus'))
    return found

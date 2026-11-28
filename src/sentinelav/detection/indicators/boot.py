# Purpose: Static traits of boot-sector and master-boot-record code in disk and floppy images.
# Works with: detection.threat_score, detection.file_types
# Used by: detection.indicators

"""Static traits of boot-sector code in disk and floppy images.

Ordinary boot loaders read the disk and jump to an operating system. Boot
viruses must also stay resident: they shrink the BIOS conventional-memory count
at 0040:0013, copy themselves to the top of memory, and take over the disk
interrupt (INT 13h) so they can infect other disks. Nothing is executed.
"""
import re
from sentinelav.detection.threat_score import indicator

SECTOR = 512
# DEC WORD [0413h] / SUB WORD [0413h],n / MOV AX,[0413h] ... MOV [0413h],AX
MEMORY_SHRINK = re.compile(rb'\xff\x0e\x13\x04|\x83\x2e\x13\x04.|\x81\x2e\x13\x04..', re.S)
MEMORY_READ = re.compile(rb'\xa1\x13\x04|\x8b[\x06\x1e\x0e\x16\x36\x3e]\x13\x04')
MEMORY_WRITE = re.compile(rb'\xa3\x13\x04|\x89[\x06\x1e\x0e\x16\x36\x3e]\x13\x04')
# Writes to the INT 13h vector at 0000:004C (offset) or 0000:004E (segment).
VECTOR_WRITE = re.compile(rb'\xa3[\x4c\x4e]\x00|\x89[\x06\x1e\x0e\x16\x36\x3e][\x4c\x4e]\x00|\xc7\x06[\x4c\x4e]\x00|\x8c[\x06\x0e\x1e][\x4c\x4e]\x00', re.S)
VECTOR_READ = re.compile(rb'\xa1\x4c\x00|\x8b[\x06\x1e\x0e\x16\x36\x3e][\x4c\x4e]\x00|\xc4[\x06\x1e\x36\x3e]\x4c\x00')
INT13 = b'\xcd\x13'
# MOV AH,03 or MOV AX,03xx shortly before INT 13h: write sectors.
DISK_WRITE = re.compile(rb'(?:\xb4\x03|\xb8.\x03)[^\xcd]{0,12}\xcd\x13', re.S)
COPY = re.compile(rb'\xf3[\xa4\xa5]')
# Converting kilobytes to a paragraph segment: SHL AX,6 or MOV CL,6 / SHL AX,CL.
KB_TO_SEGMENT = re.compile(rb'\xc1\xe0\x06|\xb1\x06\xd3\xe0')


def is_boot_sector(data):
    """Tell whether the data starts with a boot sector (512 bytes ending in the 55 AA signature)."""
    return len(data) >= SECTOR and bytes(data[510:512]) == b'\x55\xaa'


def _sectors(data):
    """Sector 0, plus the boot sector of the active MBR partition when it is inside the image."""
    yield 0, bytes(data[:SECTOR])
    for slot in range(4):
        entry = bytes(data[446 + slot * 16:462 + slot * 16])
        if len(entry) == 16 and entry[0] == 0x80:
            start = int.from_bytes(entry[8:12], 'little') * SECTOR
            if 0 < start <= len(data) - SECTOR and bytes(data[start + 510:start + 512]) == b'\x55\xaa':
                yield start, bytes(data[start:start + SECTOR])


def indicators(data, kind='boot'):
    """Look for the tell-tale tricks of a boot virus in the boot sectors of a disk image.

    Each trick (reserving memory, hooking the disk interrupt, copying itself high, writing sectors)
    adds one indicator. Several of them together are what separates a boot virus from an ordinary
    boot loader.
    """
    found = []
    seen = set()
    for offset, sector in _sectors(data):
        where = 'master boot record' if offset == 0 else f'partition boot sector at byte {offset}'
        add = lambda code, group, weight, text: seen.add(code) or found.append(indicator(code, group, weight,
            f'{text} ({where}).', category='BootVirus')) if code not in seen else None
        shrinks = MEMORY_SHRINK.search(sector) or (MEMORY_READ.search(sector) and MEMORY_WRITE.search(sector))
        if shrinks:
            add('boot_reserves_memory', 'boot_residency', 45, 'Boot code lowers the BIOS memory size to hide itself at the top of memory')
        if VECTOR_WRITE.search(sector) and (VECTOR_READ.search(sector) or INT13 in sector):
            add('boot_hooks_disk_interrupt', 'boot_hook', 40, 'Boot code replaces the disk interrupt (INT 13h) handler, so it can intercept and infect disks')
        if COPY.search(sector) and KB_TO_SEGMENT.search(sector) and shrinks:
            add('boot_relocates_high', 'boot_residency', 15, 'Boot code copies itself into the memory it reserved')
        if DISK_WRITE.search(sector) and (shrinks or VECTOR_WRITE.search(sector)):
            add('boot_writes_sectors', 'replication', 20, 'Resident boot code writes disk sectors, as boot viruses do when infecting')
    return found

# Purpose: Delay-load import evidence using the same bounded RVA decoder as emulation.
# Works with: detection.pe_image
# Used by: detection.file_formats

"""Delay-load import evidence using the same bounded RVA decoder as emulation."""
import struct
from sentinelav.detection.pe_image import PEImage


def inspect_delay_imports(data,metadata):
    offset=struct.unpack_from('<I',data,0x3c)[0]+24
    size=struct.unpack_from('<H',data,offset-4)[0]
    magic=struct.unpack_from('<H',data,offset)[0]
    directory=112 if magic==0x20b else 96
    if magic not in (0x10b,0x20b) or size<directory: raise ValueError('Missing delay-import directory header')
    count=struct.unpack_from('<I',data,offset+directory-4)[0]
    if count<=13: return dict(status='Complete',libraries=[],functions=0)
    if size<directory+14*8: raise ValueError('Truncated delay import directory')
    if struct.unpack_from('<II',data,offset+directory+13*8)==(0,0):
        return dict(status='Complete',libraries=[],functions=0)
    items=PEImage(data,metadata).imports(delay=True)
    libraries={}
    for item in items:
        symbols=libraries.setdefault(item['library'],[])
        symbols.append(dict(name=item['name']) if item['name'] else dict(ordinal=item['ordinal']))
    return dict(status='Complete',libraries=[dict(name=k,symbols=v) for k,v in libraries.items()],functions=len(items))

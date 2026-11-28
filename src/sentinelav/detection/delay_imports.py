# Purpose: Delay-load import evidence using the same bounded RVA decoder as emulation.
# Works with: detection.pe_image
# Used by: detection.file_formats

"""Delay-load import evidence using the same bounded RVA decoder as emulation."""

import struct
from sentinelav.detection.pe_image import PEImage


def inspect_delay_imports(data, metadata):
    """List the DLL functions a Windows program loads lazily ('delay-load imports').

    These imports are only resolved the first time they are used, which malware sometimes relies on
    to keep suspicious functions out of the normal import table. Returns the libraries and function
    names found.
    """
    offset = struct.unpack_from('<I', data, 0x3C)[0] + 24
    size = struct.unpack_from('<H', data, offset - 4)[0]
    magic = struct.unpack_from('<H', data, offset)[0]
    directory = 112 if magic == 0x20B else 96
    if magic not in (0x10B, 0x20B) or size < directory:
        raise ValueError('Missing delay-import directory header')
    # The delay-import entry is number 13 in the data-directory table; skip the work if the table is
    # too short or the entry is empty.
    count = struct.unpack_from('<I', data, offset + directory - 4)[0]
    if count <= 13:
        return dict(status='Complete', libraries=[], functions=0)
    if size < directory + 14 * 8:
        raise ValueError('Truncated delay import directory')
    if struct.unpack_from('<II', data, offset + directory + 13 * 8) == (0, 0):
        return dict(status='Complete', libraries=[], functions=0)
    items = PEImage(data, metadata).imports(delay=True)
    libraries = {}
    for item in items:
        symbols = libraries.setdefault(item['library'], [])
        symbols.append(dict(name=item['name']) if item['name'] else dict(ordinal=item['ordinal']))
    return dict(
        status='Complete',
        libraries=[dict(name=k, symbols=v) for k, v in libraries.items()],
        functions=len(items),
    )

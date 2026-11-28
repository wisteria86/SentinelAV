# Purpose: Bounded PE export/resource/CLR descriptions without loading executable code.
# Works with: detection.pe_image
# Used by: detection.file_formats

"""Bounded PE export/resource/CLR descriptions without loading executable code."""

import struct
from sentinelav.detection.pe_image import PEImage


def describe(data, metadata):
    """Describe the extra parts of a Windows program: exported functions, resources, relocations, .NET
    (CLR) metadata, an attached signature and TLS callbacks.

    Each part is read with strict size limits. A damaged part is noted in 'omissions' and marks the
    result Incomplete, but never stops the others from being read.
    """
    if metadata.get('format') != 'PE':
        return dict(status='Not applicable')
    result = dict(status='Complete', omissions=[])
    try:
        image = PEImage(data, metadata)
    except ValueError as error:
        return dict(status='Incomplete', omissions=[str(error)])

    def string(rva, cap=512):
        """Read a zero-terminated ASCII string at a virtual address inside the image (at most `cap`
        characters).
        """
        value = bytearray()
        for index in range(cap):
            character = data[image.locate(rva + index, 1)]
            if not character:
                return value.decode('ascii', errors='strict')
            value.append(character)
        raise ValueError('Unterminated directory string')

    for kind, index in [
        ('exports', 0),
        ('resources', 2),
        ('relocations', 5),
        ('clr', 14),
        ('certificate', 4),
    ]:
        try:
            rva, size = image.directory(index)
            if not rva or not size:
                result[kind] = dict(present=False)
                continue
            if kind == 'certificate':
                if rva + size > len(data):
                    raise ValueError('Certificate file range')
                result[kind] = dict(
                    present=True, bytes=size, trust='Presence only; not signer validation'
                )
                continue
            offset = image.locate(
                rva, min(size, 24 if kind == 'clr' else 40 if kind == 'exports' else 16)
            )
            if kind == 'exports':
                if size < 40:
                    raise ValueError('Truncated export directory')
                library, base, functions, names, functions_rva, names_rva, ordinals_rva = (
                    struct.unpack_from('<IIIIIII', data, offset + 12)
                )
                entries = []
                result[kind] = dict(present=True, declared=functions, named=names, entries=entries)
                for number in range(min(names, 4096)):
                    name_rva = struct.unpack_from(
                        '<I', data, image.locate(names_rva + number * 4, 4)
                    )[0]
                    ordinal = struct.unpack_from(
                        '<H', data, image.locate(ordinals_rva + number * 2, 2)
                    )[0]
                    if ordinal >= functions:
                        raise ValueError('Export ordinal range')
                    address = struct.unpack_from(
                        '<I', data, image.locate(functions_rva + ordinal * 4, 4)
                    )[0]
                    entries.append(dict(name=string(name_rva), ordinal=base + ordinal, rva=address))
                if names > 4096:
                    raise ValueError('Export budget; partial entries retained')
            elif kind == 'clr':
                if size < 24:
                    raise ValueError('Truncated CLR header')
                length, major, minor, meta_rva, meta_size, flags, entry = struct.unpack_from(
                    '<IHHIIII', data, offset
                )
                if length < 24 or length > size:
                    raise ValueError('CLR header bounds')
                meta = image.locate(meta_rva, 16)
                if meta_size < 16 or data[meta : meta + 4] != b'BSJB':
                    raise ValueError('CLR metadata signature')
                version = struct.unpack_from('<I', data, meta + 12)[0]
                if version > 4096 or 16 + version + 4 > meta_size:
                    raise ValueError('CLR version range')
                position = 16 + ((version + 3) & ~3)
                count = struct.unpack_from('<H', data, image.locate(meta_rva + position + 2, 2))[0]
                if count > 64:
                    raise ValueError('CLR stream count budget')
                position += 4
                streams = []
                for _ in range(count):
                    if position + 8 > meta_size:
                        raise ValueError('CLR stream header bounds')
                    start, length = struct.unpack_from(
                        '<II', data, image.locate(meta_rva + position, 8)
                    )
                    name = string(meta_rva + position + 8, 32)
                    if position + 8 + len(name) + 1 > meta_size:
                        raise ValueError('CLR stream name bounds')
                    if start + length > meta_size:
                        raise ValueError('CLR stream bounds')
                    streams.append(dict(name=name, bytes=length))
                    position += 8 + ((len(name) + 4) & ~3)
                result[kind] = dict(
                    present=True,
                    runtime=[major, minor],
                    flags=flags,
                    entrypoint_token=entry,
                    streams=streams,
                    execution='Not executed',
                )
            elif kind == 'relocations':
                used = 0
                blocks = 0
                entries = 0
                while used < size:
                    page, length = struct.unpack_from('<II', data, image.locate(rva + used, 8))
                    if length < 8 or length % 2 or used + length > size:
                        raise ValueError('Relocation block range')
                    image.locate(rva + used, length)
                    entries += (length - 8) // 2
                    blocks += 1
                    used += length
                    if entries > 65536 or blocks > 4096:
                        raise ValueError('Relocation budget')
                result[kind] = dict(present=True, blocks=blocks, entries=entries)
            else:
                if size < 16:
                    raise ValueError('Truncated resource root')
                named, numbered = struct.unpack_from('<HH', data, offset + 12)
                if named + numbered > 256:
                    raise ValueError('Resource root budget')
                image.locate(rva + 16, (named + numbered) * 8)
                result[kind] = dict(present=True, named=named, numbered=numbered, bytes=size)
        except (ValueError, struct.error, UnicodeError) as error:
            result['status'] = 'Incomplete'
            result['omissions'].append(kind + ': ' + str(error))
    try:
        result['tls_callbacks'] = image.tls_callbacks()
    except (ValueError, struct.error) as error:
        result['status'] = 'Incomplete'
        result['omissions'].append('TLS: ' + str(error))
    return result

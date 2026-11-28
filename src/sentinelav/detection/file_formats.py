# Purpose: Small bounded PE-header inspector. No unpacking or executable loading.
# Works with: detection.delay_imports, detection.image_details, detection.pe_imports
# Used by: detection.engine, detection.scan_flow, tests.unit.test_integrated_analysis,
#   tests.unit.test_pe_imports

"""Small bounded PE-header inspector. No unpacking or executable loading."""

import struct
import math
from collections import Counter


def byte_statistics(data):
    """Exact Shannon entropy and concentration; no sample/family patterns."""
    size = len(data)
    counts = Counter(data)
    return dict(
        bytes=size,
        entropy_bits=(
            round(-sum((count / size) * math.log2(count / size) for count in counts.values()), 6)
            if size
            else 0.0
        ),
        unique_bytes=len(counts),
        zero_fraction=round(counts.get(0, 0) / size, 6) if size else 0.0,
    )


def pe_metadata(data):
    """Read the basic structure of a Windows program (PE file) without running or unpacking it.

    Returns the CPU type, the list of sections (name, size, location, permissions and byte
    statistics), the entry point, any overlapping sections, and how many extra bytes trail after the
    last section. Non-PE content gives {'format': 'Other'}; a broken header raises ValueError.
    """
    if not data.startswith(b'MZ'):
        return dict(format='Other')
    if len(data) < 64:
        raise ValueError('Truncated DOS/PE header')
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    if offset > 1024 * 1024 or offset + 24 > len(data) or data[offset : offset + 4] != b'PE\0\0':
        raise ValueError('Invalid or unsupported PE-header offset/signature')
    machine, sections = struct.unpack_from('<HH', data, offset + 4)
    optional_size = struct.unpack_from('<H', data, offset + 20)[0]
    table = offset + 24 + optional_size
    if not 1 <= sections <= 96 or optional_size > 4096 or table + sections * 40 > len(data):
        raise ValueError('PE section-table bounds exceeded')
    result = []
    for index in range(sections):
        start = table + index * 40
        name = data[start : start + 8].split(b'\0')[0].decode('ascii', errors='replace')
        raw_size, raw_offset = struct.unpack_from('<II', data, start + 16)
        if raw_size and raw_offset + raw_size > len(data):
            raise ValueError('PE section exceeds inspected file bounds')
        virtual_size, virtual_address = struct.unpack_from('<II', data, start + 8)
        flags = struct.unpack_from('<I', data, start + 36)[0]
        result.append(
            dict(
                name=name,
                raw_bytes=raw_size,
                raw_offset=raw_offset,
                virtual_bytes=virtual_size,
                virtual_address=virtual_address,
                executable=bool(flags & 0x20000000),
                writable=bool(flags & 0x80000000),
                statistics=byte_statistics(memoryview(data)[raw_offset : raw_offset + raw_size]),
            )
        )
    entrypoint = None
    if optional_size >= 20:
        magic = struct.unpack_from('<H', data, offset + 24)[0]
        if magic in (0x10B, 0x20B):
            entrypoint = struct.unpack_from('<I', data, offset + 40)[0]
    # Which section(s) contain the entry point? Normal programs start inside their code section.
    entry_sections = [
        i
        for i, s in enumerate(result)
        if entrypoint is not None
        and s['virtual_address']
        <= entrypoint
        < s['virtual_address'] + max(s['virtual_bytes'], s['raw_bytes'])
    ]
    overlaps = []
    # Sections whose file data overlap each other are a sign of a deliberately malformed file.
    ranges = sorted(
        (s['raw_offset'], s['raw_offset'] + s['raw_bytes'], i)
        for i, s in enumerate(result)
        if s['raw_bytes']
    )
    for index, (begin, end, section) in enumerate(ranges):
        for other_begin, other_end, other in ranges[index + 1 :]:
            if other_begin >= end:
                break
            overlaps.append([section, other])
    return dict(
        format='PE',
        machine=hex(machine),
        sections=result,
        unpacked=False,
        entrypoint_rva=entrypoint,
        entrypoint_sections=entry_sections,
        raw_overlaps=overlaps,
        trailing_bytes=max(
            0, len(data) - max([table + sections * 40] + [end for _, end, _ in ranges])
        ),
    )


def static_analysis(data, metadata=None):
    """Explain structural anomalies without pretending to estimate malware probability.

    Entropy is descriptive: compression and encryption are common in benign files.
    No thresholds trained on evaluation samples and no automatic response eligibility.
    """
    metadata = pe_metadata(data) if metadata is None else metadata
    signals = []
    if metadata['format'] == 'PE':
        for index, section in enumerate(metadata['sections']):
            if section['executable'] and section['writable']:
                signals.append(
                    dict(
                        code='writable_executable_section',
                        section=index,
                        explanation='Section permits both writing and execution.',
                    )
                )
        if metadata['entrypoint_rva'] and not metadata['entrypoint_sections']:
            signals.append(
                dict(
                    code='entrypoint_outside_sections',
                    explanation='Nonzero entry point is outside all declared section ranges.',
                )
            )
        if metadata['raw_overlaps']:
            signals.append(
                dict(
                    code='overlapping_raw_sections',
                    pairs=metadata['raw_overlaps'],
                    explanation='Declared section data ranges overlap.',
                )
            )
    statistics = byte_statistics(data)
    sections = metadata.get('sections', [])
    features = dict(
        entropy_bits=statistics['entropy_bits'],
        zero_fraction=statistics['zero_fraction'],
        log2_bytes=math.log2(1 + len(data)),
        section_count=len(sections),
        max_section_entropy=max((s['statistics']['entropy_bits'] for s in sections), default=0),
        writable_executable_fraction=sum(s['writable'] and s['executable'] for s in sections)
        / max(1, len(sections)),
        entrypoint_outside_sections=int(
            bool(metadata.get('entrypoint_rva')) and not metadata.get('entrypoint_sections')
        ),
        overlapping_section_pairs=len(metadata.get('raw_overlaps', [])),
        trailing_fraction=metadata.get('trailing_bytes', 0) / max(1, len(data)),
    )
    imports = dict(status='Not applicable', libraries=[])
    delayed = dict(status='Not applicable', libraries=[])
    capabilities = []
    if metadata['format'] == 'PE':
        from sentinelav.detection.pe_imports import inspect_imports, capability_evidence

        try:
            imports = inspect_imports(data, metadata)
            capabilities = capability_evidence(imports)
        except ValueError as error:
            imports = dict(status='Incomplete', reason=str(error), libraries=[])
        from sentinelav.detection.delay_imports import inspect_delay_imports

        try:
            delayed = inspect_delay_imports(data, metadata)
        except ValueError as error:
            delayed = dict(status='Incomplete', reason=str(error), libraries=[])
        capabilities = capability_evidence(
            dict(libraries=imports.get('libraries', []) + delayed.get('libraries', []))
        )
        if {c['capability'] for c in capabilities} >= {'cross_process_memory', 'remote_thread'}:
            signals.append(
                dict(
                    code='cross_process_execution_capability',
                    explanation='Imports combine remote memory access/writes and remote thread creation; legitimate tools can also do this.',
                )
            )
    from sentinelav.detection.image_details import describe

    return dict(
        schema=1,
        method='structural-analysis-v1',
        statistics=statistics,
        features=features,
        image_details=describe(data, metadata),
        imports=imports,
        delay_imports=delayed,
        capabilities=capabilities,
        signals=signals,
        signal_count=len(signals),
        assessment='Review' if signals else 'No structural signals',
        calibrated=False,
        malware_probability=None,
        automatic_response_eligible=False,
    )

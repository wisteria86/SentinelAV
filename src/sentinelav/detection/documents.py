# Purpose: Optional in-memory VBA source extraction. Macro source is never executed.
# Works with: sibling modules in detection
# Used by: detection.advanced_pipeline

"""Optional in-memory VBA source extraction. Macro source is never executed."""
import io
import time
import zipfile


def macro_sources(data):
    """Extract the VBA macro source code from an Office document, entirely in memory.

    Works for both old binary Office files (OLE) and modern .docx/.xlsm style ZIP files. Size, count
    and time limits protect against hostile documents. Macros are only read as text, never run.

    Returns (sources, omissions): a list of (name, source bytes) pairs and a list of anything we
    could not inspect.
    """
    omissions=[]
    ole=data.startswith(bytes.fromhex('d0cf11e0a1b11ae1'))
    office_zip=False
    if data.startswith(b'PK'):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries=archive.infolist()
                # Jars, APKs and plain ZIPs are not Office files; their own readers apply their own limits.
                if not any(e.filename.casefold().endswith('vbaproject.bin') for e in entries[:65536]):return [],[]
                if len(entries)>1024 or sum(e.file_size for e in entries)>128*1024*1024 or any(e.file_size>32*1024*1024 or (e.file_size>1024*1024 and e.file_size>200*max(1,e.compress_size)) or e.flag_bits&1 for e in entries):
                    return [],['Office container exceeds macro-extraction limits']
                office_zip=any(e.filename.casefold().endswith('vbaproject.bin') for e in entries)
        except (zipfile.BadZipFile,OSError): return [],['Malformed Office ZIP']
    if not ole and not office_zip: return [],[]
    if len(data)>32*1024*1024: return [],['Office macro extraction size limit']
    try: from oletools.olevba import VBA_Parser
    except ImportError: return [],['Optional oletools dependency unavailable; VBA source not inspected']
    sources=[]; expanded=0; deadline=time.monotonic()+3
    parser=None
    try:
        parser=VBA_Parser('in-memory-document',data=bytes(data))
        for index,item in enumerate(parser.extract_macros()):
            if index>=32 or time.monotonic()>deadline: omissions.append('Macro count/time limit'); break
            source=item[3]
            payload=source.encode('utf-8',errors='replace') if isinstance(source,str) else bytes(source)
            expanded+=len(payload)
            if len(payload)>1024*1024 or expanded>4*1024*1024: omissions.append('Macro source byte limit'); break
            sources.append(('vba-source-'+str(index),payload))
        omissions.append('VBA source inspection does not inspect compiled p-code or execute macros')
    except Exception as error: omissions.append('Macro extraction incomplete: '+str(error)[:200])
    finally:
        if parser is not None: parser.close()
    return sources,omissions

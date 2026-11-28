# Purpose: Safe packaged analyzer integration check; no fixture is executed by Windows.
# Works with: detection.inspection, paths, platform.emulation_support
# Used by: entrypoint, tests.unit.test_learned_detectors, tests.unit.test_speakeasy_backend

"""Safe packaged analyzer integration check; no fixture is executed by Windows."""
import base64
import struct
import importlib.util
from sentinelav.paths import RESOURCE_ROOT
from sentinelav.detection.inspection import IsolatedScanner


def exit_fixture():
    """Build a tiny, harmless Windows program by hand whose only instruction is to call ExitProcess(0).

    It is never run by Windows; it only gives the emulator something real to step through during the
    self-test.
    """
    data=bytearray(1536); data[:2]=b'MZ'
    struct.pack_into('<I',data,0x3c,64); data[64:68]=b'PE\0\0'
    struct.pack_into('<HH',data,68,0x14c,1); struct.pack_into('<H',data,84,224)
    struct.pack_into('<H',data,88,0x10b); struct.pack_into('<I',data,104,0x1200)
    struct.pack_into('<I',data,116,0x400000); struct.pack_into('<II',data,144,0x2000,512)
    struct.pack_into('<II',data,120,0x1000,512)
    struct.pack_into('<H',data,156,3)
    struct.pack_into('<I',data,180,16); struct.pack_into('<II',data,192,0x1000,40)
    data[312:320]=b'.text\0\0\0'; struct.pack_into('<IIII',data,320,1024,0x1000,1024,512)
    struct.pack_into('<I',data,348,0x60000020)
    struct.pack_into('<IIIII',data,512,0x1100,0,0,0x1060,0x1100)
    data[608:621]=b'kernel32.dll\0'; struct.pack_into('<I',data,768,0x1180)
    data[898:910]=b'ExitProcess\0'
    data[1024:1032]=b'\x6a\x00\xff\x15'+struct.pack('<I',0x401100)
    return bytes(data)


def check_advanced(directory):
    """Self-test the advanced analysis in the packaged build.

    First a Base64-encoded test marker must be found by content decoding; then, if the emulator is
    available, the hand-built program must be emulated and its single ExitProcess call observed.
    Returns PASS or PARTIAL with details.
    """
    marker=b'SENTINELAV_DEMO_THREAT_7C23A'
    encoded=directory/'encoded-fixture.ps1'; encoded.write_bytes(base64.b64encode(marker))
    scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',options={'advanced':True,'documents':False})
    result=scanner.scan([encoded],lambda:False,lambda *args:None)
    if not any(d.get('detection_scope')=='derived content' for d in result['detections']):
        raise RuntimeError('Packaged normalized-content detection failed')
    if importlib.util.find_spec('unicorn') is None:
        return dict(status='PARTIAL',normalized_detection=True,emulation=dict(status='Dependency not included'),windows_fixture_execution=False)
    import unicorn
    from sentinelav.platform.emulation_support import compatibility
    support=compatibility(unicorn.__version__)
    if not support['available']:
        return dict(status='PARTIAL',normalized_detection=True,emulation=dict(status='Unavailable',reason=support['reason']),windows_fixture_execution=False)
    executable=directory/'emulated-fixture.bin'; executable.write_bytes(exit_fixture())
    scanner=IsolatedScanner(RESOURCE_ROOT/'signatures.json',RESOURCE_ROOT/'rules',options={'emulation':True,'documents':False})
    emulated=scanner.scan([executable],lambda:False,lambda *args:None)
    coverage=emulated.get('advanced_analysis',{}).get('coverage',{}).get('emulation',{})
    if coverage.get('api_calls')!=1 or not any(e.get('kind')=='exit' or (e.get('kind')=='modeled_api' and e.get('api')=='ExitProcess') for e in coverage.get('api_events',[])):
        raise RuntimeError('Packaged Win32 emulator unavailable or failed: '+str(emulated.get('errors',[])))
    return dict(status='PASS',normalized_detection=True,emulation=coverage,windows_fixture_execution=False)

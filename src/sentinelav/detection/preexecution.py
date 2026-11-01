"""Manual pre-execution verdict; does not intercept system-wide launches."""
from pathlib import Path
import os


def verdict(path,report,approved_hashes=()):
    path=Path(path).resolve()
    identity=report.get('file_identity')
    if report.get('detections'): return dict(decision='Block',reason='Detection present',system_wide_enforcement=False)
    if report.get('status')!='Complete' or not identity or report.get('skipped') or report.get('errors'):
        return dict(decision='Indeterminate',reason='Inspection incomplete; no launch approval',system_wide_enforcement=False)
    current=path.stat()
    observed=tuple(str(value) for value in (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns))
    if observed!=tuple(identity['stat']):
        return dict(decision='Indeterminate',reason='File changed since inspection',system_wide_enforcement=False)
    if identity['sha256'] not in approved_hashes:
        return dict(decision='Not approved',reason='No detection is not proof of safety; exact hash is not in the launch allowlist',system_wide_enforcement=False)
    return dict(decision='Approved hash at inspection time',reason='Caller must enforce the decision and prevent subsequent file changes; this tool does not launch files',system_wide_enforcement=False)

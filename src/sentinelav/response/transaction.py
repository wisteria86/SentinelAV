# Purpose: Process-lifetime remediation lock. A crashed owner releases the OS lock.
# Works with: workspace
# Used by: data.change_journal, platform.remediation_broker, tests.unit.test_remediation_transactions

"""Process-lifetime remediation lock. A crashed owner releases the OS lock."""
from contextlib import contextmanager
import os
from pathlib import Path
from sentinelav.workspace import unlinked


class RemediationBusy(RuntimeError):
    pass


@contextmanager
def exclusive_file(path,create=None,verify=None):
    path=unlinked(Path(path))
    if not path.exists():
        try:
            if create:
                with create(path) as stream:stream.write(b'\0');stream.flush();os.fsync(stream.fileno())
            else:
                with path.open('xb') as stream:stream.write(b'\0')
        except FileExistsError:pass
    if verify:verify(path)
    with path.open('r+b',buffering=0) as stream:
        if os.fstat(stream.fileno()).st_nlink!=1:raise ValueError('Linked execution lock refused')
        acquired=False
        try:
            try:
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
                acquired=True
            except OSError as error:raise RemediationBusy('Another cleanup or recovery operation is active; wait for its receipt') from error
            yield
        finally:
            if acquired:
                stream.seek(0)
                if os.name=='nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
                else:
                    import fcntl
                    fcntl.flock(stream,fcntl.LOCK_UN)

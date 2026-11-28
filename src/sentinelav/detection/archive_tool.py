# Purpose: Read archive members through 7-Zip when the in-process readers cannot (cabinets, Deflate64 or Implode ZIPs, unusual 7z filters).
# Works with: detection.archive_formats
# Used by: detection.archive_formats

"""Read archive members through 7-Zip when the in-process readers cannot.

Cabinets, ZIP methods the standard library lacks (Deflate64, Implode, Reduce) and
7z archives with filters py7zr does not implement are listed and decompressed by
7z.exe from a short-lived temp copy. Members are only read into memory, never run.
"""

import os
import subprocess
import tempfile
from pathlib import Path

CAB_LIMIT = 256 * 1024 * 1024
TOOL_LIMIT = 256 * 1024 * 1024
SHARING_PASSWORDS = ('infected', 'malware', 'virus')


def seven_zip_tool():
    """7z.exe from SENTINELAV_7ZIP, a `7zip` folder beside the application, then the work drive's tool area."""
    from sentinelav.paths import PROJECT_ROOT

    for path in (
        os.environ.get('SENTINELAV_7ZIP'),
        PROJECT_ROOT / '7zip' / '7z.exe',
        Path(os.environ.get('SENTINELAV_WORK_ROOT', 'F:/SentinelAV-Work'))
        / 'tools'
        / '7zip'
        / '7z.exe',
    ):
        if path and Path(path).is_file():
            return str(path)
    return None


def _listing(tool, path, password):
    """Ask 7-Zip to list an archive's files, returning (name, size, encrypted) tuples, or None if the
    password was wrong.
    """
    run = subprocess.run(
        [tool, 'l', '-slt', '-ba', '-p' + password, str(path)],
        capture_output=True,
        timeout=60,
        creationflags=0x08000000,
    )
    if run.returncode != 0:
        return None
    entries = []
    for block in run.stdout.decode('utf-8', 'replace').replace(chr(13), '').split(chr(10) * 2):
        fields = dict(line.split(' = ', 1) for line in block.splitlines() if ' = ' in line)
        if (
            fields.get('Path')
            and fields.get('Folder') != '+'
            and 'D' not in fields.get('Attributes', '').split('_')[0]
        ):
            entries.append(
                (fields['Path'], int(fields.get('Size') or 0), fields.get('Encrypted') == '+')
            )
    return entries


def tool_members(data, suffix, limit=TOOL_LIMIT, passwords=('', *SHARING_PASSWORDS)):
    """List and read an archive's members through the external 7-Zip program.

    The archive is written to a short-lived temporary copy, listed, and all members are extracted in
    one pass to memory, cut apart using their declared sizes. Each password (none, then the sharing
    passwords) is tried in turn. Raises RuntimeError if 7-Zip is missing or cannot read it.
    """
    from sentinelav.detection.archive_formats import Member

    tool = seven_zip_tool()
    if not tool:
        raise RuntimeError(f'{suffix} members were not inspected: 7-Zip is not available')
    # 7-Zip needs a seekable file; the copy lives only for this call, in the temp folder.
    with tempfile.TemporaryDirectory(prefix='sav-7z-') as folder:
        path = Path(folder) / ('package' + suffix)
        path.write_bytes(data)
        for password in passwords:
            entries = _listing(tool, path, password)
            if entries is None:
                continue
            total = sum(size for _, size, _ in entries)
            # Read at most the declared total plus one byte, so an archive that lies about its sizes cannot expand without bound.
            if total > limit:
                raise RuntimeError('Archive expansion limit: declares ' + str(total) + ' bytes')
            # One pass writes every member to stdout in listing order; the declared sizes cut it apart.
            process = subprocess.Popen(
                [tool, 'e', '-so', '-p' + password, str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000,
            )
            try:
                output = process.stdout.read(total + 1)
            finally:
                process.kill()
                process.wait(10)
            if len(output) != total:
                continue  # Wrong password for encrypted members, or sizes that do not match
            result = []
            offset = 0
            for name, size, encrypted in entries:
                result.append(
                    Member(
                        name,
                        size,
                        lambda limit, start=offset, size=size: output[
                            start : start + min(size, limit + 1)
                        ],
                        encrypted=encrypted,
                    )
                )
                offset += size
            return result
    raise RuntimeError(f'{suffix} archive could not be read by 7-Zip')


def cab_members(data):
    """List and read the members of a Windows cabinet (.cab) file through 7-Zip."""
    return tool_members(data, '.cab', CAB_LIMIT, ('',))

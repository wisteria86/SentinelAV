# Purpose: ENOSPC trial on a positively identified, newly attached 64 MiB guest VHDX.
# Works with: data.storage, lab.qualification.guest, paths, response.response
# Used by: lab.qualification.guest_telemetry

"""ENOSPC trial on a positively identified, newly attached 64 MiB guest VHDX."""
import hashlib
import json
from pathlib import Path
import uuid


def test(root,context):
    """Check that quarantine fails safely when the disk is full.

    Inside the Hyper-V guest, the newly attached 64 MiB test disk is positively identified,
    formatted and filled up. Then a harmless marker file is quarantined: the action must fail and
    the original must be left untouched.
    """
    from .guest import guard,ps
    if not guard(context) or context['backend']!='hyperv':raise ValueError('Dedicated guest required for volume trial')
    identifier=str(uuid.UUID(context['owned_disk_identifier'])).replace('-','').lower()
    script=r'''$ErrorActionPreference='Stop'
Update-HostStorageCache
$id='__ID__'
$disks=@(Get-Disk|Where-Object {($_.SerialNumber -replace '[^a-zA-Z0-9]','').ToLowerInvariant() -eq $id -or ($_.UniqueId -replace '[^a-zA-Z0-9]','').ToLowerInvariant() -eq $id})
if($disks.Count -ne 1){throw 'Owned test disk identity could not be established; no disk formatted'}
$d=$disks[0]
if($d.IsBoot -or $d.IsSystem -or $d.Number -eq 0 -or $d.Size -ne 67108864 -or $d.PartitionStyle -ne 'RAW'){throw 'Owned test disk shape mismatch; no disk formatted'}
Initialize-Disk -Number $d.Number -PartitionStyle GPT -PassThru|Out-Null
$p=New-Partition -DiskNumber $d.Number -UseMaximumSize -AssignDriveLetter
$p|Format-Volume -FileSystem NTFS -NewFileSystemLabel 'SentinelAV-Lab' -Confirm:$false|Out-Null
@{drive=[string]$p.DriveLetter;disk=$d.Number}|ConvertTo-Json -Compress
'''.replace('__ID__',identifier)
    facts=json.loads(ps(script,60));letter=facts['drive']
    if not isinstance(letter,str) or len(letter)!=1 or not letter.isalpha():raise ValueError('Invalid owned volume')
    from sentinelav.data.storage import Store
    from sentinelav.response.response import ResponseService
    from sentinelav.paths import RESOURCE_ROOT
    volume=Path(letter+':/');data=volume/'SentinelAV-State';data.mkdir();store=Store(data/'history.db')
    source=root/'disk-full-harmless.txt';marker=b'SENTINELAV_DEMO_THREAT_7C23A';source.write_bytes(marker)
    service=ResponseService(store,RESOURCE_ROOT);fill=volume/'SentinelAV-owned-fill.bin';full=False;error=''
    try:
        try:
            with fill.open('xb') as f:
                for _ in range(65):f.write(bytes(1024*1024));f.flush()
        except OSError:full=True
        if not full:raise RuntimeError('Disk-full condition not established within fixed 65 MiB write cap')
        try:service.quarantine_file(dict(path=str(source),sha256=hashlib.sha256(marker).hexdigest(),reasons=['Harmless disk-full response probe']))
        except Exception as e:error=type(e).__name__+': '+str(e)[:200]
        preserved=source.exists() and source.read_bytes()==marker
        return dict(disk_full_verified=bool(error) and preserved,original_preserved=preserved,expected_failure=error,
            owned_volume=letter,protected_controls_changed=int(not preserved),bytes_cap=65*1024**2)
    finally:
        store.db.close();fill.unlink(missing_ok=True)

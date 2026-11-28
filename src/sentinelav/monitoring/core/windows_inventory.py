# Purpose: Read current supported Windows persistence and file state.
# Works with: data.contracts, workspace
# Used by: monitoring.app_changes, monitoring.core.change_monitor

"""Read-only persistence inventory, honest attribution, and encrypted reconciliation."""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
from sentinelav.data.contracts import fingerprint
from sentinelav.workspace import unlinked

MAX_FILE = 1024 * 1024
RUN_KEYS = (
    r'Software\Microsoft\Windows\CurrentVersion\Run',
    r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
)


def resource(kind, **fields):
    """Describe one watched item (a registry value, file, task or service) with a stable id derived
    from its fields.
    """
    return dict(kind=kind, id=fingerprint(dict(kind=kind, **fields)), **fields)


def powershell(script, data=None):
    """Fixed program plus JSON stdin. No interpolated shell input or expression eval."""
    encoded = base64.b64encode(script.encode('utf-16le')).decode()
    env = os.environ.copy()
    env['PSModulePath'] = os.path.join(
        env.get('SystemRoot', 'C:/Windows'), 'System32/WindowsPowerShell/v1.0/Modules'
    )
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
        input=json.dumps(data) if data is not None else '',
        capture_output=True,
        text=True,
        encoding='utf-8-sig',
        errors='replace',
        timeout=25,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        env=env,
    )
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError('Inventory transport budget exceeded')
    if result.returncode:
        raise OSError(result.stderr.strip()[:1000] or 'Windows inventory operation failed')
    return json.loads(result.stdout or 'null')


def file_state(path):
    """Take a snapshot of a small file (up to 1 MiB): its hash, size and content, refusing hard links
    and files that change while being read.
    """
    path = unlinked(path)
    try:
        with path.open('rb') as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(MAX_FILE + 1)
            after = os.fstat(stream.fileno())
        current = path.stat()
    except FileNotFoundError:
        return dict(exists=False)
    if len(raw) > MAX_FILE:
        raise ValueError('Tracked file exceeds 1 MiB snapshot limit')
    if before.st_nlink != 1:
        raise ValueError('Hard-linked tracker resource refused')
    signature = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns)
    if signature(before) != signature(after) or signature(after) != signature(current):
        raise ValueError('Tracked file changed during snapshot')
    return dict(
        exists=True,
        sha256=hashlib.sha256(raw).hexdigest(),
        bytes=len(raw),
        content=base64.b64encode(raw).decode(),
        file_id=[after.st_dev, after.st_ino],
        modified_ns=after.st_mtime_ns,
    )


TASKS_SCRIPT = r'''
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8
$service=New-Object -ComObject 'Schedule.Service';$service.Connect()
$rows=[Collections.Generic.List[object]]::new();$bytes=0
function Visit($folder){
 foreach($task in $folder.GetTasks(1)){
  if($task.Path.StartsWith('\Microsoft\Windows\',[StringComparison]::OrdinalIgnoreCase)){continue}
  if($rows.Count -ge 256){throw 'Task inventory count budget'}
  $xml=[string]$task.Xml;$script:bytes+=$xml.Length
  if($xml.Length -gt 131072 -or $script:bytes -gt 1000000){throw 'Task XML budget'}
  $rows.Add(@{path=[string]$task.Path;xml=$xml;sddl=[string]$task.GetSecurityDescriptor(7)})
 }
 foreach($child in $folder.GetFolders(0)){Visit $child}
}
Visit ($service.GetFolder('\'));@($rows.ToArray()) | ConvertTo-Json -Depth 5 -Compress
'''

SERVICES_SCRIPT = r'''
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8
@(Get-CimInstance Win32_Service | Select-Object -First 512 | ForEach-Object {
 @{name=[string]$_.Name;display_name=[string]$_.DisplayName;image=[string]$_.PathName;
 start=[string]$_.StartMode;account=[string]$_.StartName;service_type=[string]$_.ServiceType}
}) | ConvertTo-Json -Depth 4 -Compress
'''


class WindowsInventory:
    """Lists the places Windows uses to start programs automatically.

    That means the Run and RunOnce registry keys (32 and 64-bit views), scheduled tasks outside
    Microsoft's own folder, services, the Startup folders, and any configuration files the user
    chose to track. Everything is read-only.
    """

    def __init__(self, settings=(), service_scope=False):
        """Remember which extra setting files to track (up to 64). service_scope=True skips per-user
        locations when running as the system service.
        """
        if (
            not isinstance(settings, (list, tuple))
            or len(settings) > 64
            or any(not isinstance(p, str) or not Path(p).is_absolute() for p in settings)
        ):
            raise ValueError('Track up to 64 explicit absolute configuration files')
        self.settings = list(settings)
        self.service_scope = service_scope

    def collect(self):
        """Read every autostart location and return {'rows', 'errors', 'complete'}.

        rows is a list of (resource, state) pairs. complete lists the kinds that were read in full;
        only those can be trusted to show that an entry was removed.
        """
        rows = []
        errors = []
        complete = set()
        if os.name != 'nt':
            return dict(rows=[], errors=['Windows change tracking requires Windows'], complete=[])
        import winreg

        registry_ok = True
        for hive, hkey in [('HKCU', winreg.HKEY_CURRENT_USER), ('HKLM', winreg.HKEY_LOCAL_MACHINE)]:
            if self.service_scope and hive == 'HKCU':
                continue
            for view, access in [(32, winreg.KEY_WOW64_32KEY), (64, winreg.KEY_WOW64_64KEY)]:
                for key in RUN_KEYS:
                    try:
                        with winreg.OpenKey(hkey, key, 0, winreg.KEY_READ | access) as handle:
                            count = winreg.QueryInfoKey(handle)[1]
                            if count > 256:
                                raise ValueError('Run entry count budget')
                            for index in range(count):
                                name, value, kind = winreg.EnumValue(handle, index)
                                if not isinstance(value, str) or len(value) > 32768:
                                    raise ValueError('Unsupported Run value type/size')
                                rows.append(
                                    (
                                        resource(
                                            'registry', hive=hive, key=key, name=name, view=view
                                        ),
                                        dict(exists=True, value=value, type=kind),
                                    )
                                )
                    except FileNotFoundError:
                        pass
                    except OSError as error:
                        registry_ok = False
                        errors.append(f'{hive} {key}: {error}')
                    except ValueError as error:
                        registry_ok = False
                        errors.append(str(error))
        if registry_ok:
            complete.add('registry')
        for kind, script in [('task', TASKS_SCRIPT), ('service', SERVICES_SCRIPT)]:
            try:
                items = powershell(script) or []
                if isinstance(items, dict):
                    items = [items]
                if len(items) >= (256 if kind == 'task' else 512):
                    raise ValueError(
                        'Inventory count boundary reached; deletion reconciliation suppressed'
                    )
                for item in items:
                    identity = item['path'] if kind == 'task' else item['name']
                    rows.append((resource(kind, name=identity), dict(exists=True, **item)))
                complete.add(kind)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                errors.append(kind + ': ' + str(error))
        roots = [
            Path(os.environ.get('APPDATA', '')) / 'Microsoft/Windows/Start Menu/Programs/Startup',
            Path(os.environ.get('ProgramData', 'C:/ProgramData'))
            / 'Microsoft/Windows/Start Menu/Programs/Startup',
        ]
        if self.service_scope:
            roots = roots[1:]
        files_ok = True
        for root in roots:
            try:
                unlinked(root)
                if not root.exists():
                    continue
                files = list(root.iterdir())
                if len(files) > 256:
                    raise ValueError('Startup entry count limit')
                for path in files:
                    if path.is_file():
                        rows.append(
                            (resource('startup_file', path=str(path.absolute())), file_state(path))
                        )
            except (OSError, ValueError) as error:
                files_ok = False
                errors.append('Startup: ' + str(error))
        if files_ok:
            complete.add('startup_file')
        settings_ok = True
        for path in self.settings:
            try:
                path = unlinked(path)
                if path.suffix.lower() not in (
                    '.ini',
                    '.json',
                    '.xml',
                    '.cfg',
                    '.conf',
                    '.yaml',
                    '.yml',
                ):
                    raise ValueError(
                        'Select an application configuration file, not a browser profile or credential store'
                    )
                if any(
                    part.casefold()
                    in ('credentials', 'vault', 'cookies', 'login data', 'logins.json')
                    for part in path.parts
                ):
                    raise ValueError('Credential stores are not tracked')
                rows.append((resource('setting_file', path=str(path)), file_state(path)))
            except (OSError, ValueError) as error:
                settings_ok = False
                errors.append('Setting: ' + str(error))
        if settings_ok:
            complete.add('setting_file')
        return dict(rows=rows, errors=errors, complete=sorted(complete))

    def read(self, target):
        """Read the current state of one resource directly."""
        kind = target['kind']
        if kind in ('startup_file', 'setting_file'):
            return file_state(target['path'])
        if kind == 'registry':
            import winreg

            if (
                target['key'] not in RUN_KEYS
                or target['hive'] not in ('HKCU', 'HKLM')
                or target['view'] not in (32, 64)
            ):
                raise ValueError('Registry resource outside supported scope')
            hive = (
                winreg.HKEY_CURRENT_USER if target['hive'] == 'HKCU' else winreg.HKEY_LOCAL_MACHINE
            )
            try:
                with winreg.OpenKey(
                    hive,
                    target['key'],
                    0,
                    winreg.KEY_READ
                    | (winreg.KEY_WOW64_32KEY if target['view'] == 32 else winreg.KEY_WOW64_64KEY),
                ) as handle:
                    value, typ = winreg.QueryValueEx(handle, target['name'])
                    return dict(exists=True, value=value, type=typ)
            except FileNotFoundError:
                return dict(exists=False)
        inventory = self.collect()
        if kind not in inventory['complete']:
            raise OSError(
                'Cannot establish fresh ' + kind + ' state: ' + '; '.join(inventory['errors'])
            )
        return next(
            (state for item, state in inventory['rows'] if item == target), dict(exists=False)
        )

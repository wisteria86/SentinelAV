# Purpose: Apply narrowly scoped Windows resource changes and verify remnants.
# Works with: data.contracts, monitoring.app_changes, response.remediation_resources, response.response
# Used by: response.remediation

"""Stored, expiring, evidence-linked cleanup and conflict-checked manual recovery."""

import base64
import ctypes
import hashlib
import os
from pathlib import Path
import xml.etree.ElementTree as ET
from sentinelav.data.contracts import fingerprint
from sentinelav.monitoring.app_changes import WindowsInventory, powershell, RUN_KEYS
from sentinelav.response.response import checked_path, locked_file, delete_locked
from .remediation_resources import MUTATE_SCRIPT, referenced_paths, task_disabled


class WindowsRemediationBackend:
    """Reads and changes the Windows resources that remediation works on: processes, files, Run keys,
    tasks, services and setting files.
    """

    def __init__(self, inventory=None):
        """Use the given inventory (or a default WindowsInventory) to read autostart locations."""
        self.inventory = inventory or WindowsInventory()

    def read(self, target):
        """Return the current state of a resource: a process's identity, a file's hash, or an autostart
        entry's value.
        """
        if target['kind'] == 'process':
            import psutil

            try:
                proc = psutil.Process(target['pid'])
                return dict(
                    exists=True,
                    pid=proc.pid,
                    creation=proc.create_time(),
                    path=str(Path(proc.exe()).resolve()),
                    owner=proc.username(),
                )
            except psutil.NoSuchProcess:
                return dict(exists=False)
        if target['kind'] == 'file':
            path = checked_path(target['path'])
            try:
                with path.open('rb') as stream:
                    initial = os.fstat(stream.fileno())
                    digest = hashlib.sha256()
                    total = 0
                    while raw := stream.read(1024 * 1024):
                        total += len(raw)
                        if total > 100 * 1024 * 1024:
                            raise ValueError('Response file budget')
                        digest.update(raw)
                    after = os.fstat(stream.fileno())
                if (initial.st_ino, initial.st_size, initial.st_mtime_ns) != (
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ):
                    raise ValueError('Response file changed')
                return dict(
                    exists=True,
                    sha256=digest.hexdigest(),
                    file_id=[after.st_dev, after.st_ino],
                    bytes=total,
                )
            except FileNotFoundError:
                return dict(exists=False)
        return self.inventory.read(target)

    def verify_incident(self, plan):
        """After a cleanup, check whether any active autostart still points at one of the incident's
        files, and list gaps in the inventory.
        """
        inventory = self.inventory.collect()
        remnants = []
        gaps = list(inventory['errors'])
        known = {
            os.path.normcase(os.path.abspath(d['path']))
            for item in plan['actions']
            for d in item['evidence']
        }
        for target, state in inventory['rows']:
            if target['kind'] == 'service' and state.get('start') == 'Disabled':
                continue
            if target['kind'] == 'task':
                try:
                    if task_disabled(state):
                        continue
                except (ValueError, ET.ParseError):
                    gaps.append('A task definition could not be reconciled')
                    continue
            try:
                paths = referenced_paths(dict(resource=target, after=state))
                if any(os.path.normcase(os.path.abspath(path)) in known for path in paths):
                    remnants.append(
                        dict(
                            resource=target,
                            reason='Active persistence still references an incident file',
                        )
                    )
            except (ValueError, ET.ParseError):
                gaps.append('An inventory reference could not be reconciled')
        required = {'registry', 'startup_file', 'task', 'service', 'setting_file'}
        missing = required - set(inventory['complete'])
        if missing:
            gaps.append('Incomplete inventories: ' + ', '.join(sorted(missing)))
        return dict(
            complete=not gaps and not remnants,
            remnants=remnants,
            omissions=gaps,
            scope='Current supported persistence references to incident files; no reboot or global absence guarantee',
        )

    def apply(self, target, action, state, expected=None):
        """Change one resource: disable or restore a Run-key value, task or service, or restore a
        setting/startup file.

        Every change first confirms the resource still looks exactly as expected, so a change made
        in the meantime is never overwritten.
        """
        if expected is not None and fingerprint(self.read(target)) != fingerprint(expected):
            raise ValueError('Resource changed before mutation')
        if target['kind'] == 'registry':
            import winreg

            if (
                target['key'] not in RUN_KEYS
                or target['hive'] not in ('HKCU', 'HKLM')
                or target['view'] not in (32, 64)
            ):
                raise ValueError('Registry scope refused')
            hive = (
                winreg.HKEY_CURRENT_USER if target['hive'] == 'HKCU' else winreg.HKEY_LOCAL_MACHINE
            )
            access = (
                winreg.KEY_SET_VALUE
                | winreg.KEY_QUERY_VALUE
                | (winreg.KEY_WOW64_32KEY if target['view'] == 32 else winreg.KEY_WOW64_64KEY)
            )
            with winreg.OpenKey(hive, target['key'], 0, access) as handle:
                try:
                    value, typ = winreg.QueryValueEx(handle, target['name'])
                    observed = dict(exists=True, value=value, type=typ)
                except FileNotFoundError:
                    observed = dict(exists=False)
                if expected is not None and fingerprint(observed) != fingerprint(expected):
                    raise ValueError('Registry value changed immediately before mutation')
                if action == 'disable' or not state.get('exists'):
                    try:
                        winreg.DeleteValue(handle, target['name'])
                    except FileNotFoundError:
                        pass
                else:
                    if state.get('type') not in (
                        winreg.REG_SZ,
                        winreg.REG_EXPAND_SZ,
                    ) or not isinstance(state.get('value'), str):
                        raise ValueError('Unsupported registry restoration')
                    winreg.SetValueEx(handle, target['name'], 0, state['type'], state['value'])
            return
        if target['kind'] in ('task', 'service'):
            if action == 'restore' and not state.get('exists'):
                raise ValueError('Deleting a task/service is not a restoration operation')
            powershell(
                MUTATE_SCRIPT, dict(resource=target, action=action, state=state, expected=expected)
            )
            return
        if target['kind'] in ('setting_file', 'startup_file') and action == 'restore':
            path = checked_path(target['path'])
            if not state.get('exists'):
                if expected is None:
                    raise ValueError('Missing recovery precondition')
                with locked_file(path) as stream:
                    if os.fstat(stream.fileno()).st_nlink != 1 or hashlib.sha256(
                        stream.read(1024 * 1024 + 1)
                    ).hexdigest() != expected.get('sha256'):
                        raise ValueError('Recovery target changed or has hard links')
                    delete_locked(stream)
                return
            raw = base64.b64decode(state['content'], validate=True)
            if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != state['sha256']:
                raise ValueError('Recovery content integrity failed')
            if expected is not None and not expected.get('exists'):
                with locked_file(path, create=True) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.seek(0)
                    if hashlib.sha256(stream.read()).hexdigest() != state['sha256']:
                        raise ValueError('Recovery write verification failed')
                return
            # Existing configuration is held exclusively; preserve its identity.
            import msvcrt

            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ]
            kernel.CreateFileW.restype = ctypes.c_void_p
            handle = kernel.CreateFileW(str(path), 0xC0000000, 0, None, 3, 0x00200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            with os.fdopen(fd, 'r+b') as stream:
                if os.fstat(stream.fileno()).st_nlink != 1:
                    raise ValueError('Hard-linked configuration refused')
                current = stream.read(1024 * 1024 + 1)
                if expected is None or hashlib.sha256(current).hexdigest() != expected.get(
                    'sha256'
                ):
                    raise ValueError('Configuration changed before exclusive write')
                stream.seek(0)
                stream.write(raw)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
            return
        raise ValueError(
            'This resource/action requires file quarantine or a supported recorded baseline'
        )

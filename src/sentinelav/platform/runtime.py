# Purpose: Paths and opt-in Windows integrations for source and packaged execution.
# Works with: data.storage, detection.inspection, paths
# Used by: data.reporting, entrypoint, lab.qualification.guest_process, lab.qualification.guest_support

"""Paths and opt-in Windows integrations for source and packaged execution."""

from sentinelav.paths import RESOURCE_ROOT, PROJECT_ROOT
from pathlib import Path
import subprocess
import sys
import getpass
import csv
import io
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

VERSION = '0.17.0'
ZONE = ZoneInfo('Asia/Karachi')
TASK_NAME = 'SentinelAV Daily Scan'


def launch_command(*args):
    """Return the command line that starts SentinelAV with the given arguments (the .exe when packaged,
    otherwise pythonw plus app.py).
    """
    if getattr(sys, 'frozen', False):
        return [sys.executable, *args]
    python = Path(sys.executable).with_name('pythonw.exe')
    return [
        str(python if python.exists() else Path(sys.executable)),
        str(PROJECT_ROOT / 'app.py'),
        *args,
    ]


def next_daily(hour, minute, now=None):
    """Return the next date-time (in the app's time zone) at hour:minute, today if still ahead,
    otherwise tomorrow.
    """
    now = now or datetime.now(ZONE)
    now = now.astimezone(ZONE)
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return candidate if candidate > now else candidate + timedelta(days=1)


def due(schedule, now=None):
    """Tell whether an enabled schedule's next run time has arrived."""
    return bool(
        schedule.get('enabled')
        and schedule.get('next_run')
        and datetime.fromisoformat(schedule['next_run']) <= (now or datetime.now(ZONE))
    )


def set_startup(enabled):
    """Add or remove SentinelAV from the current user's Windows startup (Run key).

    An entry written by a different SentinelAV copy is left untouched, and FileExistsError is raised
    instead.
    """
    import winreg

    with winreg.CreateKey(
        winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'
    ) as key:
        expected = subprocess.list2cmdline(launch_command('--startup'))
        try:
            existing = winreg.QueryValueEx(key, 'SentinelAV')[0]
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not isinstance(existing, str) or existing.casefold() != expected.casefold()
        ):
            raise FileExistsError(
                'Another SentinelAV copy owns Windows startup; its registration was preserved'
            )
        if enabled:
            winreg.SetValueEx(key, 'SentinelAV', 0, winreg.REG_SZ, expected)
        else:
            try:
                winreg.DeleteValue(key, 'SentinelAV')
            except FileNotFoundError:
                pass


def startup_enabled():
    """Tell whether this copy of SentinelAV is registered to start with Windows."""
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'
        ) as key:
            value = winreg.QueryValueEx(key, 'SentinelAV')[0]
            return (
                isinstance(value, str)
                and value.casefold()
                == subprocess.list2cmdline(launch_command('--startup')).casefold()
            )
    except OSError:
        return False


def task_xml(schedule, data_dir):
    """Build the Windows Task Scheduler XML for the daily scheduled scan (runs as the user, without
    elevation).
    """
    namespace = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
    ET.register_namespace('', namespace)

    def tag(parent, name, text=None, **attrs):
        """Add a child element (with optional text and attributes) in the task XML namespace."""
        el = ET.SubElement(parent, '{' + namespace + '}' + name, attrs)
        if text is not None:
            el.text = str(text)
        return el

    root = ET.Element('{' + namespace + '}Task', version='1.2')
    info = tag(root, 'RegistrationInfo')
    tag(
        info,
        'Description',
        'SentinelAV opt-in daily scan; runs only while this Windows user is logged in.',
    )
    triggers = tag(root, 'Triggers')
    trigger = tag(triggers, 'CalendarTrigger')
    tag(trigger, 'StartBoundary', schedule['next_run'])
    tag(trigger, 'Enabled', 'true')
    daily = tag(trigger, 'ScheduleByDay')
    tag(daily, 'DaysInterval', '1')
    principals = tag(root, 'Principals')
    principal = tag(principals, 'Principal', id='User')
    tag(principal, 'UserId', getpass.getuser())
    tag(principal, 'LogonType', 'InteractiveToken')
    tag(principal, 'RunLevel', 'LeastPrivilege')
    settings = tag(root, 'Settings')
    tag(settings, 'MultipleInstancesPolicy', 'IgnoreNew')
    tag(settings, 'DisallowStartIfOnBatteries', 'false')
    tag(settings, 'StopIfGoingOnBatteries', 'false')
    tag(settings, 'StartWhenAvailable', 'true')
    tag(settings, 'ExecutionTimeLimit', 'PT4H')
    tag(settings, 'Enabled', 'true')
    actions = tag(root, 'Actions', Context='User')
    action = tag(actions, 'Exec')
    command = launch_command('--scheduled-scan', '--data-dir', str(data_dir))
    tag(action, 'Command', command[0])
    tag(action, 'Arguments', subprocess.list2cmdline(command[1:]))
    tag(action, 'WorkingDirectory', str(Path(command[0]).parent))
    return ET.tostring(root, encoding='unicode', xml_declaration=False)


def _text(output):
    """Decode schtasks output, which may be UTF-16, UTF-8 or the local code page."""
    if isinstance(output, str):
        return output
    if output.startswith((b'\xff\xfe', b'\xfe\xff')):
        return output.decode('utf-16')
    if b'\0' in output[:100]:
        return output.decode('utf-16-le')
    try:
        return output.decode('utf-8-sig')
    except UnicodeDecodeError:
        return output.decode('mbcs')


def existing_task():
    """Return the XML of our scheduled task if it exists, or None. Raises PermissionError if it exists
    but cannot be read.
    """
    query = subprocess.run(
        ['schtasks.exe', '/Query', '/TN', TASK_NAME, '/XML'],
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
        timeout=15,
    )
    if query.returncode == 0:
        return ET.fromstring(_text(query.stdout))
    # Use machine-readable names rather than localized error-message matching.
    listing = subprocess.run(
        ['schtasks.exe', '/Query', '/FO', 'CSV', '/NH'],
        capture_output=True,
        check=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
        timeout=15,
    )
    names = [
        row[0].lstrip('\\').casefold()
        for row in csv.reader(io.StringIO(_text(listing.stdout)))
        if row
    ]
    if TASK_NAME.lstrip('\\').casefold() in names:
        raise PermissionError(
            'An existing SentinelAV task could not be inspected; no changes were made'
        )
    return None


def owns_task(task, data_dir):
    """Tell whether a scheduled task was created by this copy of SentinelAV for this data folder."""
    ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    actions = task.findall('t:Actions/*', ns)
    if len(actions) != 1 or actions[0].tag != '{' + ns['t'] + '}Exec':
        return False
    command = actions[0].findtext('t:Command', default='', namespaces=ns)
    arguments = actions[0].findtext('t:Arguments', default='', namespaces=ns)
    expected = launch_command('--scheduled-scan', '--data-dir', str(Path(data_dir).resolve()))
    return (
        os.path.normcase(os.path.abspath(command)) == os.path.normcase(os.path.abspath(expected[0]))
        and arguments.strip().casefold() == subprocess.list2cmdline(expected[1:]).casefold()
    )


def register_schedule(schedule, data_dir):
    """Create, update or delete the Windows scheduled task to match the saved schedule. A task owned by
    another copy is left alone.
    """
    data_dir = Path(data_dir).resolve()
    task = existing_task()
    if task is not None and not owns_task(task, data_dir):
        raise FileExistsError(
            'Another SentinelAV copy or data directory owns the Windows task; it was preserved'
        )
    if not schedule.get('enabled'):
        if task is not None:
            subprocess.run(
                ['schtasks.exe', '/Delete', '/TN', TASK_NAME, '/F'],
                capture_output=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=15,
            )
        return
    xml_path = Path(data_dir) / 'schedule.xml'
    xml_path.write_text(task_xml(schedule, data_dir), encoding='utf-16')
    subprocess.run(
        ['schtasks.exe', '/Create', '/TN', TASK_NAME, '/XML', str(xml_path), '/F'],
        capture_output=True,
        check=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
        timeout=15,
    )


def run_scheduled(data_dir):
    """Run the scheduled scan if it is due (`--scheduled-scan`): scan, save the result, set the next
    run time and log an event.
    """
    from sentinelav.data.storage import Store
    from sentinelav.detection.inspection import IsolatedScanner as Scanner
    import os

    root = RESOURCE_ROOT
    store = Store(Path(data_dir) / 'sentinelav.db')
    try:
        schedule = store.get('schedule', {})
        if not due(schedule):
            return dict(status='Not due')
        from sentinelav.detection.scan_targets import targets

        roots = (
            [Path(schedule['folder'])]
            if schedule['kind'] == 'Folder'
            else targets('Full' if schedule['kind'] == 'Full' else 'Quick')
        )
        result = Scanner(
            root / 'signatures.json',
            root / 'rules',
            store.get('max_mb', 100),
            store.get('exclusions', []) + [str(store.path.parent)],
            store.get('trusted_hashes', []),
            store.get('inspection_options', {}),
        ).scan(roots, lambda: False, lambda *args: None)
        result['kind'] = 'Scheduled ' + schedule['kind']
        store.save_scan(result)
        schedule['next_run'] = next_daily(schedule['hour'], schedule['minute']).isoformat()
        store.set('schedule', schedule)
        level = (
            'Alert'
            if result['detections']
            else 'Warning' if result['status'] != 'Complete' or result.get('warnings') else 'Info'
        )
        store.save_event(
            dict(
                time=datetime.now(ZONE).strftime('%Y-%m-%d %H:%M:%S'),
                kind='Scheduled scan completed',
                details=f"{result['scanned']} files; {len(result['detections'])} detections; {len(result.get('suspicious',[]))} suspicious; {result['status']}",
                source='Scheduler',
                level=level,
            )
        )
        return result
    except Exception as error:
        store.save_event(
            dict(
                time=datetime.now(ZONE).strftime('%Y-%m-%d %H:%M:%S'),
                kind='Scheduled scan failed',
                details=str(error),
                source='Scheduler',
                level='Warning',
            )
        )
        raise
    finally:
        store.db.close()

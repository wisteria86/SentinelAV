# Purpose: Decoy saved sessions and wallet pointers in the user's registry, for apps this PC does not have.
# Works with: monitoring.deception.common
# Used by: monitoring.deception.breadcrumbs, monitoring.deception

"""Decoy saved sessions and wallet pointers in the user's registry, for apps this PC does not have.

Stealers read PuTTY, WinSCP and Bitcoin Core keys to find servers and wallets.
Windows records registry reads only when auditing is configured, so these
decoys work mainly as breadcrumbs: they point at decoy servers and decoy wallet
files, and the use of those is what raises the alert. A change to or deletion of
a decoy key is reported directly.
"""

import os

if os.name == 'nt':
    import winreg
else:  # Lets the module import on other systems; deployment is Windows-only.
    winreg = None

APP_ROOT = 'Software'
TEST_ROOT = r'Software\SentinelAV-Test-Decoys'


def default_base():
    # Tests and evaluations set a decoy home; their registry decoys then stay under a throwaway key, never real app keys.
    """Return the registry key decoys go under: a throwaway test key when a test decoy home is set,
    otherwise the normal Software key.
    """
    return TEST_ROOT if os.environ.get('SENTINELAV_DECOY_HOME') else APP_ROOT


def _write(root, path, values):
    """Create a registry key and write the given values (numbers as DWORD, everything else as text)."""
    with winreg.CreateKeyEx(root, path, 0, winreg.KEY_WRITE) as key:
        for name, value in values.items():
            winreg.SetValueEx(
                key, name, 0, winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ, value
            )


def _read(root, path):
    """Return all values of a registry key as a dict, or None if the key does not exist."""
    try:
        with winreg.OpenKey(root, path) as key:
            values = {}
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    return values
                values[name] = value
                index += 1
    except FileNotFoundError:
        return None


def _exists(root, path):
    """Tell whether a registry key exists."""
    try:
        winreg.OpenKey(root, path).Close()
        return True
    except FileNotFoundError:
        return False


def deploy(specs, root=None, base=None):
    """specs: (label, app key, entry key below it, values). An entry is written only when the app key is absent."""
    if winreg is None:
        return []
    root = root if root is not None else winreg.HKEY_CURRENT_USER
    base = base or default_base()
    record = []
    for label, app_key, entry_key, values in specs:
        app_path = base + '\\' + app_key
        if _exists(root, app_path):
            continue  # The real app keeps data here; never add fake entries next to it.
        path = app_path + ('\\' + entry_key if entry_key else '')
        _write(root, path, values)
        record.append(dict(label=label, app_path=app_path, path=path, values=values, base=base))
    return record


def changed(record, root=None):
    """Decoy keys that were deleted or altered since deployment, as (entry, state)."""
    if winreg is None:
        return []
    root = root if root is not None else winreg.HKEY_CURRENT_USER
    found = []
    for entry in record:
        current = _read(root, entry['path'])
        if current is None:
            found.append((entry, 'deleted'))
        elif any(current.get(name) != value for name, value in entry['values'].items()):
            found.append((entry, 'modified'))
    return found


def _delete_tree(root, path):
    """Delete a registry key together with all its subkeys."""
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(root, path + '\\' + child)
        winreg.DeleteKey(root, path)
    except FileNotFoundError:
        pass


def _empty(root, path):
    """Tell whether a registry key exists and has no subkeys and no values."""
    try:
        with winreg.OpenKey(root, path) as key:
            subkeys, values, _ = winreg.QueryInfoKey(key)
            return not subkeys and not values
    except FileNotFoundError:
        return False


def remove(record, root=None, base=None):
    """Delete each decoy entry, then any parent keys left empty. A real app installed later keeps its own entries."""
    if winreg is None:
        return
    root = root if root is not None else winreg.HKEY_CURRENT_USER
    for entry in record:
        if entry['path'] == entry['app_path']:
            # Values sit on the app's own key: remove only the decoy values, and the key only if nothing else is there.
            try:
                with winreg.OpenKey(root, entry['path'], 0, winreg.KEY_ALL_ACCESS) as key:
                    for name in entry['values']:
                        try:
                            winreg.DeleteValue(key, name)
                        except FileNotFoundError:
                            pass
            except FileNotFoundError:
                continue
            parent = entry['path']
        else:
            _delete_tree(root, entry['path'])
            parent = entry['path'].rsplit('\\', 1)[0]
        limit = base or entry.get('base') or APP_ROOT
        while parent.startswith(limit + '\\') and _empty(root, parent):
            winreg.DeleteKey(root, parent)
            parent = parent.rsplit('\\', 1)[0]

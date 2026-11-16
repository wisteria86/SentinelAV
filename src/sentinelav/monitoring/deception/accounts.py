# Purpose: Opt-in decoy Windows account and network share, and a watcher for logon attempts that use any decoy name.
# Works with: monitoring.deception.common
# Used by: monitoring.deception

"""Opt-in decoy Windows account and network share, and a watcher for logon attempts that use any decoy name.

The account is created disabled, with a long random password nobody knows, so it
can never be used to sign in; an attempt to use it, or the fake credentials held
in memory, shows up in the Windows Security log. The share exposes only a folder
of decoy files, read-only. Both need administrator rights, and both are removed
only if they still carry SentinelAV's marker.
"""
import secrets

from sentinelav.monitoring.deception.common import event

REMARK = 'SentinelAV decoy - do not use'
ACCOUNT = 'backup_admin'
SHARE = 'Backups'
LOGON_EVENTS = (4625, 4648, 4771, 4776)  # failed logon, explicit credentials, Kerberos pre-auth failure, NTLM validation


def create_account(name=ACCOUNT):
    import win32net
    import win32netcon
    flags = win32netcon.UF_ACCOUNTDISABLE | win32netcon.UF_SCRIPT | win32netcon.UF_DONT_EXPIRE_PASSWD
    win32net.NetUserAdd(None, 1, dict(name=name, password=secrets.token_urlsafe(32) + 'Aa1!', priv=win32netcon.USER_PRIV_USER,
        flags=flags, comment=REMARK, home_dir=None, script_path=None))
    return name


def remove_account(name=ACCOUNT):
    import win32net
    try:
        if win32net.NetUserGetInfo(None, name, 1).get('comment') == REMARK:
            win32net.NetUserDel(None, name)
            return True
    except Exception:
        pass
    return False


def create_share(folder, name=SHARE):
    import win32net
    import win32netcon
    win32net.NetShareAdd(None, 2, dict(netname=name, type=win32netcon.STYPE_DISKTREE, remark=REMARK, permissions=win32netcon.ACCESS_READ,
        max_uses=-1, current_uses=0, path=str(folder), passwd=None))
    return name


def remove_share(name=SHARE):
    import win32net
    try:
        if win32net.NetShareGetInfo(None, name, 2).get('remark') == REMARK:
            win32net.NetShareDel(None, name)
            return True
    except Exception:
        pass
    return False


class LogonWatcher:
    """Reads new Security-log logon events that name a decoy account. Reading that log needs administrator rights."""

    def __init__(self, emit, names, query=None):
        self.emit, self.names, self.query = emit, {name.casefold() for name in names}, query or self._query
        self.last, self.available = None, True

    def _query(self, after):
        import win32evtlog
        ids = ' or '.join(f'EventID={number}' for number in LOGON_EVENTS)
        xpath = f'*[System[({ids})' + (f' and EventRecordID>{after}' if after is not None else '') + ']]'
        flags = win32evtlog.EvtQueryChannelPath | (win32evtlog.EvtQueryForwardDirection if after is not None else win32evtlog.EvtQueryReverseDirection)
        handle = win32evtlog.EvtQuery('Security', flags, xpath)
        rows = []
        for item in win32evtlog.EvtNext(handle, 64 if after is not None else 1):
            rows.append(win32evtlog.EvtRender(item, win32evtlog.EvtRenderEventXml))
        return rows

    def poll(self):
        if not self.available:
            return []
        import re
        try:
            rows = self.query(self.last)
        except Exception as error:
            self.available = False
            self.emit(event('Decoy logon watch unavailable', f'The Security log could not be read ({str(error)[:120]}). '
                'Run SentinelAV as administrator to watch for use of the decoy accounts.', level='Warning'))
            return []
        first_read, found = self.last is None, []
        for xml in rows:
            record = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml)
            if record:
                self.last = max(self.last or 0, int(record.group(1)))
        if first_read:
            self.last = self.last or 0  # The first read only finds where the log ends; older events are history.
            return []
        for xml in rows:
            names = {value.casefold() for value in re.findall(r"<Data Name='Target(?:User)?Name'>([^<]*)</Data>", xml)}
            hit = names & self.names
            if hit:
                number = re.search(r'<EventID>(\d+)</EventID>', xml).group(1)
                source = re.search(r"<Data Name='(?:IpAddress|Workstation|WorkstationName)'>([^<]*)</Data>", xml)
                found.append(event('Decoy account used', f'A logon attempt (event {number}) used the decoy account {sorted(hit)[0]}'
                    f" from {source.group(1) if source else 'an unknown source'}. Nothing legitimate knows this account, so its "
                    'details were stolen or guessed.', event_id=int(number)))
                self.emit(found[-1])
        return found

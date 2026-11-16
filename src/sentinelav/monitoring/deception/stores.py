# Purpose: Decoy browser, wallet, chat and FTP data stores, placed only for apps this PC does not have.
# Works with: monitoring.deception.common, monitoring.honeypots
# Used by: monitoring.deception

"""Decoy browser, wallet, chat and FTP data stores, placed only for apps this PC does not have.

Info-stealers read these well-known paths without checking whether the app is
really installed, so a read of one is strong evidence of credential theft.
A store is placed only when its app folder does not exist, and it is removed as
soon as the app's program appears, so a later install never sees fake data.
"""
import json
import os
import secrets
import sqlite3
import tempfile
from pathlib import Path

from sentinelav.monitoring.deception.common import DECOY_HOST, MARKER, profile_dirs, remove_decoys, write_decoy


def _token():
    return secrets.token_hex(8)


def _login_data():
    """A real SQLite file with a Chromium-like logins table and fake rows, so stealers parse it as they would the real one."""
    folder = tempfile.mkdtemp(prefix='sav-decoy-')
    path = Path(folder) / 'db'
    try:
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE logins (origin_url TEXT, action_url TEXT, username_value TEXT, password_value BLOB, date_created INTEGER)')
            db.execute('CREATE TABLE sentinelav_decoy (note TEXT)')
            db.execute('INSERT INTO sentinelav_decoy VALUES (?)', (MARKER,))
            for site in ('https://mail.example.invalid/', f'http://{DECOY_HOST}/admin', 'https://bank.example.invalid/login'):
                db.execute('INSERT INTO logins VALUES (?,?,?,?,?)', (site, site, f'decoy.{_token()}@example.invalid', b'v10' + secrets.token_bytes(32), 13300000000000000))
        db.close()
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)
        os.rmdir(folder)


def _text(body):
    return (MARKER + '\n' + body).encode('utf-8')


def _firefox_logins():
    entry = dict(id=1, hostname='https://mail.example.invalid', encryptedUsername='MD' + secrets.token_urlsafe(40),
        encryptedPassword='MD' + secrets.token_urlsafe(40), encType=1, sentinelav=MARKER)
    return json.dumps(dict(nextId=2, logins=[entry], version=3)).encode('utf-8')


def _filezilla():
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<!-- {MARKER} -->\n<FileZilla3><RecentServers><Server><Host>{DECOY_HOST}</Host>'
        f'<Port>21</Port><User>backup</User><Pass encoding="base64">{secrets.token_urlsafe(12)}</Pass></Server></RecentServers></FileZilla3>\n').encode('utf-8')


def _wallet():
    return _text(json.dumps(dict(wallet_type='standard', seed_version=52, keystore=dict(type='bip32', xprv='decoy' + secrets.token_hex(40)))))


# (name, base, app folder, files [(path inside the app folder, kind, builder)], program paths that mean the app is installed)
STORES = (
    ('Google Chrome', 'local', 'Google/Chrome/User Data', [('Profile 9/Login Data', 'browser_store', _login_data)],
     ['%ProgramFiles%/Google/Chrome/Application/chrome.exe', '%ProgramFiles(x86)%/Google/Chrome/Application/chrome.exe', '%LOCALAPPDATA%/Google/Chrome/Application/chrome.exe']),
    ('Brave', 'local', 'BraveSoftware/Brave-Browser/User Data', [('Profile 9/Login Data', 'browser_store', _login_data)],
     ['%ProgramFiles%/BraveSoftware/Brave-Browser/Application/brave.exe', '%LOCALAPPDATA%/BraveSoftware/Brave-Browser/Application/brave.exe']),
    ('Opera', 'roaming', 'Opera Software/Opera Stable', [('Login Data', 'browser_store', _login_data)],
     ['%LOCALAPPDATA%/Programs/Opera/opera.exe']),
    ('Vivaldi', 'local', 'Vivaldi/User Data', [('Profile 9/Login Data', 'browser_store', _login_data)],
     ['%LOCALAPPDATA%/Vivaldi/Application/vivaldi.exe']),
    ('Firefox', 'roaming', 'Mozilla/Firefox', [('Profiles/decoy9.default-release/logins.json', 'browser_store', _firefox_logins)],
     ['%ProgramFiles%/Mozilla Firefox/firefox.exe', '%ProgramFiles(x86)%/Mozilla Firefox/firefox.exe']),
    ('FileZilla', 'roaming', 'FileZilla', [('recentservers.xml', 'ftp_store', _filezilla), ('sitemanager.xml', 'ftp_store', _filezilla)],
     ['%ProgramFiles%/FileZilla FTP Client/filezilla.exe']),
    ('Electrum', 'roaming', 'Electrum', [('wallets/default_wallet', 'crypto_wallet_store', _wallet)], ['%ProgramFiles(x86)%/Electrum/electrum.exe']),
    ('Exodus', 'roaming', 'Exodus', [('exodus.wallet/seed.seco', 'crypto_wallet_store', lambda: _text(secrets.token_hex(64)))],
     ['%LOCALAPPDATA%/exodus/Exodus.exe']),
    ('Bitcoin Core', 'roaming', 'Bitcoin', [('wallets/decoy/wallet.dat', 'crypto_wallet_store', lambda: _text(secrets.token_hex(96)))],
     ['%ProgramFiles%/Bitcoin/bitcoin-qt.exe']),
    ('Telegram', 'roaming', 'Telegram Desktop', [('tdata/key_datas', 'chat_session_store', lambda: b'TDF$' + secrets.token_bytes(60) + MARKER.encode())],
     ['%APPDATA%/Telegram Desktop/Telegram.exe']),
    ('Discord', 'roaming', 'discord', [('Local Storage/leveldb/000003.log', 'chat_session_store',
        lambda: _text('_https://discord.com\x00\x01tokens\x00"decoy.' + secrets.token_urlsafe(40) + '"'))],
     ['%LOCALAPPDATA%/Discord/Update.exe']),
)


def installed(markers):
    return any(Path(os.path.expandvars(marker)).exists() for marker in markers if '%' not in os.path.expandvars(marker))


def deploy(stores=STORES):
    """Place every store whose app folder is absent. Returns (entries, record) for the watcher and later cleanup."""
    _, local, roaming = profile_dirs()
    bases = dict(local=local, roaming=roaming)
    entries, record = [], []
    for name, base, folder, files, markers in stores:
        root = bases[base] / folder
        if root.exists() or installed(markers):
            continue  # The app is or was here: never mix fake data into a real profile.
        created = []
        placed = [entry for entry in (write_decoy(root / relative, builder(), kind, created) for relative, kind, builder in files) if entry]
        entries += placed
        record.append(dict(name=name, root=str(root), markers=markers, created=created, entries=placed))
    return entries, record


def retire_installed(record):
    """Remove stores whose app has since been installed. Returns (still placed, names retired)."""
    kept, retired = [], []
    for store in record:
        if installed(store['markers']):
            remove_decoys(store['entries'], store['created'])
            retired.append(store['name'])
        else:
            kept.append(store)
    return kept, retired


def remove(record):
    left = []
    for store in record:
        left += remove_decoys(store['entries'], store['created'])
    return left

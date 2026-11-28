# Purpose: Verify the decoders and rules added for script, Java, RTF, payload and compiled-Python gaps, on inert fixtures.
# Works with: detection.script_decoders, detection.indicators

"""Verify the decoders and rules added for script, Java, RTF, payload and compiled-Python gaps, on inert fixtures."""

import io
import unittest
import zipfile

from sentinelav.detection.file_types import classify
from sentinelav.detection.indicators import collect, documents, mobile, payloads, scripts
from sentinelav.detection.script_decoders import batch_expand, powershell_normalize
from sentinelav.detection.threat_score import score


def codes(items):
    return {item['code'] for item in items}


class DecoderTests(unittest.TestCase):
    def test_batch_variables_and_substrings_are_expanded(self):
        text = '@echo off\nset "a=pow"\nset b=ershell\nset c=^-w hid^den\n%a%%b% %c% -c x%junk%\necho %comspec:~-7,3%\n'
        expanded = batch_expand(text)
        self.assertIn('powershell -w hidden -c x', expanded)
        self.assertIn('echo cmd', expanded)

    def test_delayed_expansion(self):
        self.assertIn(
            'echo b', batch_expand('setlocal enabledelayedexpansion\nset z=abc&echo !z:~1,1!\n')
        )

    def test_powershell_literal_forms_are_undone(self):
        text = "&(\"{1}{0}\"-f'EX','I') ([char]104+[char]105+[char]0x21); I`nv`oke-Ex`pression 'abXc'.replace('X','')"
        self.assertEqual(powershell_normalize(text), '&"IEX" ("hi!"); Invoke-Expression "abc"')


class ScriptRuleTests(unittest.TestCase):
    def test_obfuscated_batch_launcher_is_seen_after_expansion(self):
        text = b'@echo off\nset "p1=pow"\nset "p2=ershell"\n%p1%%p2% -w hidden -c "Add-MpPreference -ExclusionPath C:\\"\n'
        self.assertIn('defender_exclusion', codes(scripts.indicators(text, 'batch')))

    def test_batch_that_decodes_its_own_text(self):
        text = b'@echo off\ncopy C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /y "%~0.exe"\n"%~nx0.exe" -c "$t=[IO.File]::ReadAllText(\'%~f0\');[Convert]::FromBase64String($t)"\n'
        self.assertTrue(
            {'batch_hidden_payload', 'renamed_system_binary'}
            <= codes(scripts.indicators(text, 'batch'))
        )

    def test_heavy_substring_obfuscation(self):
        text = ('@echo off\n' + '%ALLUSERSPROFILE:~4,1%' * 30 + '\n').encode()
        self.assertIn('batch_heavy_obfuscation', codes(scripts.indicators(text, 'batch')))

    def test_python_exec_of_decoded_code(self):
        self.assertIn(
            'python_exec_decoded',
            codes(
                scripts.indicators(
                    b"import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n", 'python'
                )
            ),
        )

    def test_ordinary_scripts_stay_clean(self):
        for text, kind in (
            (b'@echo off\nset PATH=%PATH%;C:\\tools\ncall build.cmd\n', 'batch'),
            (b'import base64\nprint(base64.b64decode("aGk="))\n', 'python'),
            (b'Get-ChildItem | Where-Object Length -gt 1kb\n', 'powershell'),
        ):
            self.assertEqual(score(scripts.indicators(text, kind))['verdict'], 'Clean', kind)


def jar(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def class_file(*names):
    pool = b''.join(b'\x01' + len(n).to_bytes(2, 'big') + n.encode() for n in names)
    return b'\xca\xfe\xba\xbe\x00\x00\x00\x34' + (len(names) + 1).to_bytes(2, 'big') + pool


class JavaTests(unittest.TestCase):
    def test_encrypted_class_entries(self):
        data = jar(
            {f'a/{i}.class': b'\x13\x37' * 50 for i in range(5)}
            | {'a/Main.class': class_file('a/Main')}
        )
        self.assertIn('encrypted_class_files', codes(mobile.java_indicators(data, 'jar')))

    def test_session_token_access_in_a_mod_but_not_in_the_game(self):
        mod = jar(
            {'x/M.class': class_file('net/minecraft/client/User', 'java/net/HttpURLConnection')}
        )
        game = jar(
            {
                'x/M.class': class_file('net/minecraft/client/User', 'java/net/HttpURLConnection'),
                'net/minecraft/client/Minecraft.class': class_file('a'),
            }
        )
        self.assertIn('game_session_token_access', codes(mobile.java_indicators(mod, 'jar')))
        self.assertNotIn('game_session_token_access', codes(mobile.java_indicators(game, 'jar')))


class DocumentAndPayloadTests(unittest.TestCase):
    def test_rtf_object_hidden_by_padding_and_remote_template(self):
        hexed = (bytes.fromhex('d0cf11e0a1b11ae1') + b'\x00' * 20 + b'Equation.3\x00').hex()
        padded = ''.join(
            hexed[i : i + 6] + r'{\*\pad12 ffee}\par ' for i in range(0, len(hexed), 6)
        )
        doc = (
            r'{\rtf1{\object\objemb{\*\objdata '
            + padded
            + r'}}{\*\template https://example.invalid/t.dotm}}'
        ).encode()
        self.assertEqual(
            codes(documents.rtf_indicators(doc)), {'rtf_remote_template', 'rtf_equation_object'}
        )

    def test_encoded_program_and_shellcode(self):
        program = b'MZ' + b'\0' * 62 + b'This program cannot be run in DOS mode' + b'\0' * 64
        self.assertEqual(
            codes(payloads.data_indicators(bytes(b ^ 0x5A for b in program))),
            {'xor_encoded_program'},
        )
        self.assertEqual(codes(payloads.data_indicators(program[::-1])), {'backwards_program'})
        stager = (
            b'\xfc\xe8\x82\x00\x00\x00'
            + b'\x90' * 10
            + b'\x64\x8b\x15\x30\x00\x00\x00'
            + b'\xc1\xcf\x0d'
        )
        self.assertEqual(codes(payloads.data_indicators(stager)), {'raw_shellcode'})
        self.assertEqual(payloads.data_indicators(bytes(range(256)) * 64), [])

    def test_compiled_python_is_recognized_and_read(self):
        data = b'\xcb\r\r\n' + b'\0' * 12 + b'\xe3exec\xdab64decode\xdabase64\xda'
        kind = classify(data, '.pyc')
        self.assertEqual(kind['kind'], 'pyc')
        self.assertIn('python_exec_decoded', codes(collect(data, kind)))


if __name__ == '__main__':
    unittest.main()

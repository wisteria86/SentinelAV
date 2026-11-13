# Purpose: Verify exact class-constant matching for Java rules and Windows Installer stream-name decoding, on inert data.
# Works with: detection.indicators.mobile, detection.archive_formats

"""Verify exact class-constant matching for Java rules and Windows Installer stream-name decoding, on inert data."""
import io
import unittest
import zipfile

from sentinelav.detection.archive_formats import MSI_CHARS, msi_name
from sentinelav.detection.indicators.mobile import constants, java_indicators


def class_file(*names):
    """A minimal class file whose constant pool holds only the given UTF-8 names (inert, never loadable)."""
    pool=b''.join(b'\x01'+len(n).to_bytes(2,'big')+n.encode() for n in names)
    return b'\xca\xfe\xba\xbe\x00\x00\x00\x34'+(len(names)+1).to_bytes(2,'big')+pool+b'\x00'*8


def jar(*classes):
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as archive:
        for index,item in enumerate(classes):archive.writestr(f'pkg/Name{index}.class',item)
    return buffer.getvalue()


def codes(data):
    return {item['code'] for item in java_indicators(data,'jar')}


class JavaRuleTests(unittest.TestCase):
    def test_constants_are_read_exactly(self):
        self.assertEqual(constants(class_file('java/lang/Runtime','exec')),{'java/lang/runtime','exec'})
        self.assertEqual(constants(b'not a class'),set())

    def test_word_inside_another_name_does_not_match(self):
        self.assertNotIn('runtime_exec',codes(jar(class_file('java/lang/Runtime','executorService'))))
        self.assertIn('runtime_exec',codes(jar(class_file('java/lang/Runtime','exec'))))

    def test_encrypted_loader_and_webhook(self):
        found=codes(jar(class_file('defineClass','javax/crypto/Cipher'),class_file('https://example.invalid/api/webhooks/1','Login Data')))
        self.assertTrue({'encrypted_class_loader','chat_webhook_exfiltration'}<=found)

    def test_ordinary_library_constants_stay_quiet(self):
        self.assertEqual(codes(jar(class_file('java/net/URLClassLoader','java/lang/Runtime','availableProcessors'))),set())


class MsiNameTests(unittest.TestCase):
    def test_packed_names_and_tables_decode(self):
        pair=chr(0x3800+MSI_CHARS.index('B')+(MSI_CHARS.index('i')<<6))
        self.assertEqual(msi_name(chr(0x4840)+pair),'!Bi')
        self.assertEqual(msi_name(chr(0x4800+MSI_CHARS.index('x'))),'x')


if __name__=='__main__':
    unittest.main()

# Purpose: Verify boot-sector classification and residency indicators on synthetic, non-functional sectors.
# Works with: detection.helpers.file_types, detection.indicators.boot, detection.helpers.threat_score

"""Verify boot-sector classification and residency indicators on synthetic sectors.

The byte sequences are isolated instruction fragments placed in a zeroed sector;
they do not form a working program.
"""

import unittest

from sentinelav.detection.helpers.file_types import classify
from sentinelav.detection.indicators import boot, collect
from sentinelav.detection.helpers.threat_score import score


def sector(*fragments, at=0x3E):
    image = bytearray(512)
    image[0:3] = b'\xeb\x3c\x90'
    position = at
    for fragment in fragments:
        image[position : position + len(fragment)] = fragment
        position += len(fragment) + 3
    image[510:512] = b'\x55\xaa'
    return bytes(image)


RESIDENT = sector(
    b'\xff\x0e\x13\x04',  # shrink BIOS memory count
    b'\xa1\x4c\x00',  # read INT 13h vector
    b'\xa3\x4c\x00',  # write INT 13h vector
    b'\xb1\x06\xd3\xe0',  # kilobytes to segment
    b'\xf3\xa5',  # copy words
    b'\xb8\x01\x03\xcd\x13',
)  # write a sector
LOADER = sector(b'\xb8\x01\x02\xcd\x13', b'\xea\x00\x7c\x00\x00')


class BootSectorTests(unittest.TestCase):
    def test_floppy_image_is_classified_as_boot_code(self):
        self.assertEqual(classify(RESIDENT + bytes(1474560 - 512), '.img')['kind'], 'boot')
        self.assertEqual(classify(b'text ' * 200, '.txt')['kind'] != 'boot', True)

    def test_resident_disk_hooking_sector_is_malicious(self):
        items = collect(RESIDENT, classify(RESIDENT, '.bin'))
        codes = {item['code'] for item in items}
        self.assertTrue(
            {
                'boot_reserves_memory',
                'boot_hooks_disk_interrupt',
                'boot_relocates_high',
                'boot_writes_sectors',
            }
            <= codes
        )
        self.assertEqual(score(items, 'DOS')['verdict'], 'Malicious')

    def test_plain_loader_raises_nothing(self):
        self.assertEqual(boot.indicators(LOADER), [])

    def test_active_partition_boot_sector_is_checked(self):
        mbr = bytearray(LOADER)
        mbr[446:462] = b'\x80' + bytes(7) + (4).to_bytes(4, 'little') + (100).to_bytes(4, 'little')
        image = bytes(mbr) + bytes(512 * 3) + RESIDENT
        codes = {item['code'] for item in boot.indicators(image)}
        self.assertIn('boot_reserves_memory', codes)


if __name__ == '__main__':
    unittest.main()

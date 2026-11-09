# Purpose: Verify accurate fast quota accounting without following linked entries.
# Works with: workspace.Workspace; build.ps1

import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from sentinelav.workspace import Workspace


class WorkspaceUsageTests(unittest.TestCase):
    def test_nested_files_are_counted_without_per_file_ancestor_walks(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'nested').mkdir()
            (root/'first').write_bytes(b'abc')
            (root/'nested/second').write_bytes(b'12345')
            work=Workspace(root,reserve=0)
            from sentinelav.workspace import unlinked
            with patch('sentinelav.workspace.unlinked',wraps=unlinked) as checked:
                self.assertEqual(work.usage(),8)
            self.assertEqual(checked.call_count,2)

    def test_linked_files_and_directories_refused_before_descent(self):
        with tempfile.TemporaryDirectory() as temp:
            work=Workspace(temp,reserve=0)
            for mode, attributes in ((stat.S_IFLNK,0),(stat.S_IFDIR,0x400),(stat.S_IFREG,0x400)):
                with self.subTest(mode=mode,attributes=attributes):
                    entry=SimpleNamespace(path='linked',stat=lambda **kw:SimpleNamespace(
                        st_mode=mode,st_file_attributes=attributes,st_size=100))
                    listing=MagicMock()
                    listing.__enter__.return_value=iter([entry])
                    with patch('os.scandir',return_value=listing):
                        with self.assertRaisesRegex(ValueError,'Linked work path'):
                            work.usage()

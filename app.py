# Purpose: Launch the stable source entry point used by the desktop shortcut.
# Works with: sentinelav.entrypoint; start.ps1
# Used by: the CLI, desktop launcher, or packaging workflow

"""Stable launcher for the desktop shortcut, background engine and scan workers."""

from pathlib import Path
import sys

if not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))

from sentinelav.entrypoint import main

if __name__ == '__main__':
    sys.exit(main())

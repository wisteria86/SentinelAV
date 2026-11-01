"""Shared paths for source checkouts and PyInstaller bundles."""
from pathlib import Path
import sys

if getattr(sys, 'frozen', False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
    RESOURCE_ROOT = Path(sys._MEIPASS)
else:
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    RESOURCE_ROOT = PROJECT_ROOT / 'resources'

SCREENSHOTS_DIR = PROJECT_ROOT / 'artifacts' / 'screenshots'

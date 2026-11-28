# Purpose: Shared paths for source checkouts and PyInstaller bundles.
# Works with: sibling modules in sentinelav
# Used by: detection.core.advanced_pipeline, detection.inspection, detection.helpers.memory_inspection,
#   detection.helpers.neural_bytes

"""Shared paths for source checkouts and PyInstaller bundles."""

from pathlib import Path
import sys

# When packaged with PyInstaller ('frozen'), files live next to the .exe and bundled resources are
# unpacked to a temporary folder. When running from source, everything is relative to the
# repository.
if getattr(sys, 'frozen', False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
    RESOURCE_ROOT = Path(sys._MEIPASS)
else:
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    RESOURCE_ROOT = PROJECT_ROOT / 'resources'

SCREENSHOTS_DIR = PROJECT_ROOT / 'artifacts' / 'screenshots'

# Purpose: Mark the tests package for Python imports.
# Works with: the sibling modules in tests
# Used by: unittest discovery

from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from sentinelav.paths import SCREENSHOTS_DIR
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

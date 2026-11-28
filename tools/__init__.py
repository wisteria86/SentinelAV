# Purpose: Make repository CLI tools able to import the src/sentinelav package.
# Works with: tools subpackages; src/sentinelav
# Used by: the Python module loader or CLI entry point

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

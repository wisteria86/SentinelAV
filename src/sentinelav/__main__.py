# Purpose: Launch SentinelAV through Python module execution.
# Works with: entrypoint.py; app.py
# Used by: the Python module loader or CLI entry point

from sentinelav.entrypoint import main

raise SystemExit(main())

# Purpose: Freeze this regression runner to verify native emulation with CFG enabled.
# Works with: platform.core.emulation_support, tests.unit.test_integrated_analysis
# Used by: the Python module loader or CLI entry point

"""Freeze this regression runner to verify native emulation with CFG enabled.

Only synthetic bytes are interpreted inside Unicorn. No native fixture launch.
Requires the same DLL and build receipt as the application bundle.
"""

import json
import unittest
from sentinelav.platform.core.emulation_support import (
    control_flow_guard_enabled,
    validated_native_build,
)
from tests.unit.test_integrated_analysis import IntegratedAnalysisTests

if __name__ == '__main__':
    if not control_flow_guard_enabled() or not validated_native_build():
        raise SystemExit('Requires CFG and the verified bundled Windows-unwind build')
    names = [
        name
        for name in unittest.defaultTestLoader.getTestCaseNames(IntegratedAnalysisTests)
        if any(part in name for part in ('abis', 'allocation', 'unknown', 'tls'))
    ]
    if len(names) < 4:
        raise SystemExit('Missing emulator regression cases')
    suite = unittest.TestSuite(IntegratedAnalysisTests(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            dict(
                cfg_enabled=True,
                native_build_verified=True,
                cases=names,
                passed=result.wasSuccessful(),
                windows_fixture_execution=False,
            )
        )
    )
    raise SystemExit(0 if result.wasSuccessful() else 1)

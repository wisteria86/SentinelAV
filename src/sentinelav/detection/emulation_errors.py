# Purpose: Share the unsupported-API exception between virtual machine modules.
# Works with: sibling modules in detection
# Used by: detection.emulated_calls, detection.winapi_emulator

"""In-memory Win32 API model for a bounded Unicorn analysis pass.

No host files, registry, network, processes or DLLs are accessed by guest APIs.
Unsupported semantics stop analysis instead of fabricating successful execution.
"""


class UnsupportedAPI(ValueError):
    """Raised when an emulated program calls a Windows function we do not model, which ends that
    emulation run.
    """

    pass

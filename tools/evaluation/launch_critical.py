# Purpose: Keep double-click bootstrap failures visible even before the UI imports.
# Works with: tools.evaluation.critical_harness
# Used by: the Python module loader or CLI entry point

"""Keep double-click bootstrap failures visible even before the UI imports."""

import sys


def main():
    try:
        from .critical_harness import main as evaluate

        return evaluate()
    except Exception as exc:
        message = 'SentinelAV evaluation could not start: ' + type(exc).__name__ + ': ' + str(exc)
        if '--headless' in sys.argv:
            print(message, file=sys.stderr)
        else:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, 'SentinelAV evaluation', 0x10)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())

# Purpose: Enforce small first-party files and purpose/collaborator headers.
# Works with: sibling modules in tools.maintenance
# Used by: the Python module loader or CLI entry point

"""Check first-party module sizes and collaborator headers without importing code."""

from pathlib import Path
import ast
import os

ROOT = Path(__file__).resolve().parents[2]
EXTENSIONS = {'.py', '.ps1', '.cmd', '.cpp', '.c', '.h', '.cs', '.spec', '.iss'}
EXCLUDED = {'vendor', 'obj', 'bin', '__pycache__'}

# Python modules are measured in statements, so layout (Black's one-statement-per-line style,
# wrapped tables, comments and docstrings) never changes the result. Other files are measured
# in physical lines.
PYTHON_STATEMENT_LIMIT = 300
OTHER_LINE_LIMIT = 250


def code_files():
    """Return every first-party source file, skipping vendored and build folders."""
    paths = list(ROOT.iterdir())
    for folder in ('src', 'tools', 'tests', 'scripts', 'native', 'packaging'):
        for directory, children, files in os.walk(ROOT / folder):
            children[:] = [name for name in children if name not in EXCLUDED]
            paths.extend(Path(directory) / name for name in files)
    return sorted(
        {
            p
            for p in paths
            if p.is_file()
            and not EXCLUDED.intersection(p.relative_to(ROOT).parts)
            and (p.suffix in EXTENSIONS or p.name == 'CMakeLists.txt')
        }
    )


def size_of(text, suffix):
    """Return (size, unit, limit) for one file.

    For Python the size is the number of statements (docstrings excluded), which does not depend
    on how the code is laid out. Other languages are not parsed here, so their physical line
    count is used.
    """
    if suffix != '.py':
        return len(text.splitlines()), 'lines', OTHER_LINE_LIMIT
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return len(text.splitlines()), 'lines', OTHER_LINE_LIMIT
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt):
            continue
        # A docstring is a plain string expression; it documents code rather than being code.
        is_docstring = (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
        count += not is_docstring
    return count, 'statements', PYTHON_STATEMENT_LIMIT


def main():
    """Check every file's size and header, print any problems, and return 1 if there were any."""
    errors = []
    largest = (0, None, '')
    files = code_files()
    for path in files:
        text = path.read_text(encoding='utf-8-sig')
        lines = text.splitlines()
        size, unit, limit = size_of(text, path.suffix)
        if unit == 'statements' and size > largest[0]:
            largest = (size, path.relative_to(ROOT), unit)
        if size > limit:
            errors.append(f'{path.relative_to(ROOT)}: {size} {unit}; limit is {limit}')
        header = '\n'.join(lines[:12])
        for marker in ('Purpose:', 'Works with:'):
            if marker not in header:
                errors.append(f'{path.relative_to(ROOT)}: missing {marker} header')
        if path.suffix == '.py':
            try:
                ast.parse(text, filename=str(path))
            except SyntaxError as error:
                errors.append(str(error))
    for error in errors:
        print(error)
    print(
        f'{len(files)} first-party files checked; '
        f'largest Python module: {largest[0]} {largest[2]} ({largest[1]})'
    )
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())

# Purpose: Enforce small first-party files and purpose/collaborator headers.
# Works with: sibling modules in tools.maintenance
# Used by: the Python module loader or CLI entry point

"""Check first-party module sizes and collaborator headers without importing code."""
from pathlib import Path
import ast
import os

ROOT=Path(__file__).resolve().parents[2]
EXTENSIONS={'.py','.ps1','.cmd','.cpp','.c','.h','.cs','.spec','.iss'}
EXCLUDED={'vendor','obj','bin','__pycache__'}


def code_files():
    paths=list(ROOT.iterdir())
    for folder in ('src','tools','tests','scripts','native','packaging'):
        for directory,children,files in os.walk(ROOT/folder):
            children[:]=[name for name in children if name not in EXCLUDED]
            paths.extend(Path(directory)/name for name in files)
    return sorted({p for p in paths if p.is_file() and not EXCLUDED.intersection(p.relative_to(ROOT).parts)
        and (p.suffix in EXTENSIONS or p.name=='CMakeLists.txt')})


def main():
    errors=[];largest=(0,None);files=code_files()
    for path in files:
        text=path.read_text(encoding='utf-8-sig');lines=text.splitlines()
        if len(lines)>largest[0]:largest=(len(lines),path.relative_to(ROOT))
        if len(lines)>250:errors.append(f'{path.relative_to(ROOT)}: {len(lines)} lines; limit is 250')
        header='\n'.join(lines[:12])
        for marker in ('Purpose:','Works with:'):
            if marker not in header:errors.append(f'{path.relative_to(ROOT)}: missing {marker} header')
        if path.suffix=='.py':
            try:ast.parse(text,filename=str(path))
            except SyntaxError as error:errors.append(str(error))
    for error in errors:print(error)
    print(f'{len(files)} first-party files checked; largest: {largest[0]} lines ({largest[1]})')
    return int(bool(errors))


if __name__=='__main__':raise SystemExit(main())

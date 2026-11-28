# Purpose: Enforce small first-party files (code lines only) and purpose/collaborator headers.
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


def code_line_count(text,suffix):
    """Count the lines that hold real code, so documentation never counts against the size limit.

    For Python files we skip blank lines, comment-only lines and docstrings. Other languages
    are counted as-is, because they are not parsed here.
    """
    lines=text.splitlines()
    if suffix!='.py':return len(lines)
    try:tree=ast.parse(text)
    except SyntaxError:return len(lines)
    skipped=set()
    # A docstring is the first plain string in a module, class or function body.
    for node in ast.walk(tree):
        if isinstance(node,(ast.Module,ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.body:
            first=node.body[0]
            if isinstance(first,ast.Expr) and isinstance(first.value,ast.Constant) and isinstance(first.value.value,str):
                skipped.update(range(first.lineno,first.end_lineno+1))
    return sum(1 for number,line in enumerate(lines,1)
        if number not in skipped and line.strip() and not line.strip().startswith('#'))


def main():
    errors=[];largest=(0,None);files=code_files()
    for path in files:
        text=path.read_text(encoding='utf-8-sig');lines=text.splitlines()
        size=code_line_count(text,path.suffix)
        if size>largest[0]:largest=(size,path.relative_to(ROOT))
        if size>250:errors.append(f'{path.relative_to(ROOT)}: {size} code lines; limit is 250')
        header='\n'.join(lines[:12])
        for marker in ('Purpose:','Works with:'):
            if marker not in header:errors.append(f'{path.relative_to(ROOT)}: missing {marker} header')
        if path.suffix=='.py':
            try:ast.parse(text,filename=str(path))
            except SyntaxError as error:errors.append(str(error))
    for error in errors:print(error)
    print(f'{len(files)} first-party files checked; largest: {largest[0]} code lines ({largest[1]})')
    return int(bool(errors))


if __name__=='__main__':raise SystemExit(main())

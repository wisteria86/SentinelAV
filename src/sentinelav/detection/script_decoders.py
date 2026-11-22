# Purpose: Undo common batch and PowerShell obfuscation by static text rewriting; nothing is run.
# Works with: detection.indicators.scripts
# Used by: detection.indicators.scripts

"""Undo common batch and PowerShell obfuscation by static text rewriting; nothing is run.

Batch obfuscators split commands into many `set` variables and rebuild them with
%name%, %name:~start,length% and caret escapes, often using substrings of
standard environment variables. The batch decoder replays only `set` assignments
and variable expansion over the text, in order, the way cmd.exe would expand it.
No command, loop or call is followed.

PowerShell obfuscators reorder fragments with the -f format operator, spell
words with [char] codes and break keywords with backticks. The PowerShell
normalizer rewrites only those literal forms.
"""
import re

LINE_LIMIT=20000
TEXT_LIMIT=4*1024*1024
# Values that are the same on every Windows installation; obfuscators take single characters from them.
STANDARD_ENV={'comspec':'C:\\Windows\\system32\\cmd.exe','windir':'C:\\Windows','systemroot':'C:\\Windows','systemdrive':'C:',
    'programdata':'C:\\ProgramData','allusersprofile':'C:\\ProgramData','programfiles':'C:\\Program Files',
    'programfiles(x86)':'C:\\Program Files (x86)','commonprogramfiles':'C:\\Program Files\\Common Files','public':'C:\\Users\\Public',
    'os':'Windows_NT','processor_architecture':'AMD64','pathext':'.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL',
    'psmodulepath':'C:\\Program Files\\WindowsPowerShell\\Modules;C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules'}
EXPANSION=re.compile(r'%%|%([^%\r\n:=]{1,64})(?::(~-?\d+(?:,-?\d+)?|[^%=\r\n]{1,64}=[^%\r\n]{0,64}))?%')
DELAYED=re.compile(r'!([^!\r\n:=]{1,64})(?::(~-?\d+(?:,-?\d+)?))?!')
SET=re.compile(r'^\s*@?\s*set\s+(?!/[ap]\b)"?([^=\s"]{1,64})=(.*?)"?\s*$',re.I)


def _substring(value,spec):
    if spec.startswith('~'):
        numbers=[int(n) for n in spec[1:].split(',')]
        start=numbers[0]
        start=max(0,len(value)+start) if start<0 else min(start,len(value))
        if len(numbers)==1:return value[start:]
        length=numbers[1]
        return value[start:len(value)+length] if length<0 else value[start:start+length]
    old,new=spec.split('=',1)
    if old.startswith('*'):
        # %name:*text=new% replaces everything up to and including the first match.
        position=value.casefold().find(old[1:].casefold())
        return new+value[position+len(old)-1:] if old[1:] and position>=0 else value
    return re.sub(re.escape(old),lambda m:new,value,flags=re.I) if old else value


def _expand(text,env,pattern):
    def replace(match):
        if match.group()=='%%':return '%'
        name=match.group(1)
        if name[:1].isdigit() or name.startswith('~'):return match.group()  # %1, %~f0: arguments stay as they are
        value=env.get(name.casefold())
        if value is None:return '' if pattern is EXPANSION else match.group()
        return _substring(value,match.group(2)) if match.group(2) else value
    return pattern.sub(replace,text)


def batch_expand(text):
    """The batch text with set-variable expansion replayed; returns None when nothing changed."""
    text=text[:TEXT_LIMIT]
    env=dict(STANDARD_ENV)
    delayed=bool(re.search(r'enabledelayedexpansion',text,re.I))
    lines=[]
    for line in text.splitlines()[:LINE_LIMIT]:
        line=re.sub(r'\^(.)',r'\1',line)
        expanded=_expand(line,env,EXPANSION)
        out=[]
        for command in re.split(r'&&?|\|\|',expanded):
            if delayed:command=_expand(command,env,DELAYED)
            assignment=SET.match(command)
            if assignment and len(env)<20000:env[assignment.group(1).casefold()]=assignment.group(2)[:8192]
            else:out.append(command)
        lines.append('&'.join(out))
    result='\n'.join(line for line in lines if line.strip())
    return result if result.strip() and result!=text else None


FORMAT=re.compile(r"""\(\s*(["'])((?:\{\d{1,3}(?:,-?\d+)?(?::[^}]*)?\}|[^"'{}])*)\1\s*-f\s*((?:(?:'[^'\r\n]*'|"[^"\r\n]*")\s*,\s*){0,63}(?:'[^'\r\n]*'|"[^"\r\n]*"))\s*\)""",re.I)
CHARS=re.compile(r'(?:\[char\]\s*(?:\(\s*(?:0x[0-9a-f]{1,4}|\d{1,5})\s*\)|(?:0x[0-9a-f]{1,4}|\d{1,5}))\s*\+?\s*){3,}',re.I)
CHAR_ARRAY=re.compile(r'\[char\[\]\]\s*\(\s*((?:(?:0x[0-9a-f]{1,4}|\d{1,5})\s*,\s*){1,}(?:0x[0-9a-f]{1,4}|\d{1,5}))\s*\)\s*-join\s*(?:\'\'|"")',re.I)
REPLACE=re.compile(r"""(['"])([^'"\r\n]{1,4096})\1\s*\)?\s*\.replace\(\s*(['"])([^'"\r\n]{1,64})\3\s*,\s*(['"])([^'"\r\n]{0,64})\5\s*\)""",re.I)


def _number(token):
    token=token.strip()
    value=int(token,16) if token.lower().startswith('0x') else int(token)
    return chr(value) if 0<value<0x110000 else ''


def powershell_normalize(text):
    """PowerShell text with literal format, char-code and backtick obfuscation undone; None when nothing changed."""
    original=text=text[:TEXT_LIMIT]
    # Backticks inside a word, or before a letter that is not an escape such as `n `t `r `a `b `f `v, only break up keywords.
    text=re.sub(r'(?<=[a-z])`(?=[a-z])|`(?=[cdeg-mopqsuw-z])','',text,flags=re.I)
    for _ in range(3):
        before=text
        text=FORMAT.sub(lambda m:'"'+_format(m.group(2),m.group(3))+'"',text)
        text=CHARS.sub(lambda m:'"'+''.join(_number(n) for n in re.findall(r'0x[0-9a-f]{1,4}|\d{1,5}',m.group(),re.I))+'"',text)
        text=CHAR_ARRAY.sub(lambda m:'"'+''.join(_number(n) for n in m.group(1).split(','))+'"',text)
        text=REPLACE.sub(lambda m:'"'+re.sub(re.escape(m.group(4)),lambda _:m.group(6),m.group(2),flags=re.I)+'"',text)
        text=re.sub(r"""(['"])([^'"\r\n]{0,4096})\1\s*\+\s*(['"])([^'"\r\n]{0,4096})\3""",lambda m:'"'+m.group(2)+m.group(4)+'"',text)
        if text==before:break
    return text if text!=original else None


def _format(template,arguments):
    values=[item[1:-1] for item in re.findall(r"""'[^'\r\n]*'|"[^"\r\n]*\"""",arguments)]
    def slot(match):
        index=int(match.group(1))
        return values[index] if index<len(values) else ''
    return re.sub(r'\{(\d{1,3})(?:,-?\d+)?(?::[^}]*)?\}',slot,template)

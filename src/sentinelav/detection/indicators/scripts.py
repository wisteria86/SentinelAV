# Purpose: Behavior indicators for scripts, applied after bounded literal deobfuscation.
# Works with: detection.content_analysis, detection.threat_score
# Used by: detection.indicators, detection.indicators.documents

"""Behavior indicators for scripts, applied after bounded literal deobfuscation. Scripts are never run."""
import re
from sentinelav.detection.threat_score import indicator

SUFFIX={'powershell':'.ps1','vbscript':'.vbs','javascript':'.js','batch':'.bat','html':'.js','shell':'.sh','python':'.py'}
# (kinds or None, code, group, weight, category, explanation, patterns that must ALL match)
RULES=(
    (('powershell','vbscript','javascript','html','batch'),'download_and_execute','download',40,'Downloader','Downloads content and then runs or saves it.',
     (r'downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|urldownloadtofile|bitsadmin\s+/transfer|certutil(?:\.exe)?\s+-urlcache',
      r'invoke-expression|\biex\b|start-process|wscript\.shell|shell\.application|shellexecute|adodb\.stream|savetofile|\bstart\s+"?%|\bcall\s+%')),
    (('shell',),'pipe_download_to_shell','download',20,'Downloader','Pipes downloaded content straight into a shell; installers also do this.',
     (r'(?:curl|wget)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba)?sh\b',)),
    (('python','perl','ruby'),'exec_downloaded_code','download',40,'Downloader','Runs code immediately after fetching it over the network.',
     (r'(?:exec|eval)\s*\(\s*(?:urllib\S{0,30}urlopen|urlopen|requests\.get|lwp::simple::get|net::http\.get)',)),
    (('powershell',),'encoded_or_hidden_powershell','obfuscation',22,'Script','Uses encoded commands, a hidden window or an execution-policy bypass.',
     (r'-(?:e|en|enc|encodedcommand)\s+[a-z0-9+/=]{20,}|-w(?:indowstyle)?\s+hidden|-(?:ep|executionpolicy)\s+bypass|frombase64string',)),
    (('powershell',),'amsi_bypass','evasion',40,'Evasion','Tampers with the Windows script-scanning interface.',(r'amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext',)),
    (('powershell',),'reflective_loading','injection',32,'Injector','Loads a program image or injects code directly from memory.',
     (r'reflection\.assembly\]::load|virtualalloc|createthread|getdelegateforfunctionpointer|writeprocessmemory',)),
    (('powershell',),'credential_dump_tooling','credentials',40,'Stealer','References credential-dumping tooling.',(r'invoke-mimikatz|sekurlsa|dumpcreds|get-gpppassword',)),
    (('powershell','batch','vbscript'),'shadow_copy_tampering','ransomware',40,'Ransomware','Deletes shadow copies or disables system recovery.',
     (r'vssadmin\s+delete|shadowcopy\s+delete|win32_shadowcopy|wbadmin\s+delete|recoveryenabled\s+no',)),
    (('vbscript','javascript','html'),'self_replication','replication',38,'Worm','Copies its own script file to other locations.',
     (r'scriptfullname|scriptname',r'\.copy(?:file)?\b|copyfile|\.writeline|createtextfile')),
    (('vbscript','javascript','html'),'mass_mailing','replication',42,'Worm','Sends mail to everyone in the Outlook address book.',
     (r'outlook\.application',r'addresslists|addressentries|getnamespace')),
    (('vbscript','javascript','html'),'autorun_registry_write','persistence',22,'Persistence','Writes an autorun registry key from script.',
     (r'regwrite',r'currentversion\\+run')),
    (('vbscript','javascript','html'),'startup_folder_drop','persistence',20,'Persistence','Places a file in the Startup folder from script.',
     (r'specialfolders|startup',r'\.copy|copyfile|createshortcut|createtextfile')),
    (('vbscript','javascript','html'),'shell_activex','obfuscation',12,'Script','Creates a shell or file-system object from script.',
     (r'wscript\.shell|shell\.application',r'scripting\.filesystemobject|\.run\b|\.exec\b')),
    (('javascript','html','vbscript'),'heavy_charcode_obfuscation','obfuscation',18,'Script','Assembles its code from many character codes.',
     (r'(?:(?:string\.fromcharcode|chrw?)\s*\(.{0,20}){12}',)),
    (('javascript','html'),'eval_of_decoded_content','obfuscation',18,'Script','Evaluates decoded or escaped content at runtime.',
     (r'\beval\s*\(\s*(?:unescape|atob|string\.fromcharcode|decodeuri)',)),
    (('html',),'hidden_iframe','download',18,'Exploit','Loads a hidden frame.',(r'<iframe[^>]{0,200}(?:width\s*=\s*["\']?0|height\s*=\s*["\']?0|display\s*:\s*none|visibility\s*:\s*hidden)',)),
    (('batch',),'batch_self_copy','replication',35,'Worm','Copies itself to other files or locations.',(r'copy\s+(?:/\w\s+)*"?%~?[a-z]*0',)),
    (('batch',),'batch_file_infection','replication',42,'Worm','Loops over other program or script files to change or overwrite them.',
     (r'for\s+%%?\w\s+in\s*\([^)\r\n]*\*\.(?:bat|cmd|com|exe)[^)\r\n]*\)\s*do\b[^\r\n]*(?:copy|type|echo|find|>>|call)',)),
    (('batch',),'batch_appends_own_lines','replication',38,'Worm','Copies lines from its own file into another file.',
     (r'(?:find|findstr|type)\b[^\r\n]{0,80}%~?[a-z]*0[^\r\n]{0,80}>>|>>[^\r\n]{0,80}%~?[a-z]*0',)),
    (('vbscript','javascript','html'),'script_rewrites_other_scripts','replication',30,'Virus','Walks folders and rewrites other script or web files.',
     (r'scripting\.filesystemobject',r'getfolder|subfolders|\.files\b',r'opentextfile|createtextfile',r'["\'.](?:vbs|vbe|js|jse|htm|html|hta|asp)\b')),
    (('batch',),'batch_destruction','destruction',60,'Destructive','Formats a drive or deletes Windows or the whole disk.',
     (r'format\s+[a-z]:|del(?:tree)?\s+(?:/\w+\s+)*"?(?:%(?:windir|systemroot|systemdrive)%|c:\\(?:windows|\*))|rd\s+/s\s+/q\s+(?:c:\\|%)',)),
    (('batch',),'batch_autorun','persistence',22,'Persistence','Adds itself to autorun or Startup.',(r'reg\s+add[^\r\n]{0,120}currentversion\\+run|\\+start\s*menu\\+programs\\+startup',)),
    (('batch',),'batch_security_tampering','evasion',28,'Evasion','Stops security services or the firewall.',
     (r'net\s+stop\s+"?(?:windefend|wscsvc|mpssvc|sharedaccess)|taskkill[^\r\n]{0,40}(?:msmpeng|avp|avast|mcafee)|netsh\s+(?:advfirewall|firewall)[^\r\n]{0,40}(?:off|disable)',)),
    (('batch',),'batch_hide_and_flood','obfuscation',12,'Script','Hides files with attributes or loops on itself.',(r'attrib\s+\+[hs]',)),
    # Windows Script Host droppers: launchers and loaders that ordinary software has no reason to ship as loose scripts.
    (('vbscript','javascript','html','batch'),'script_launches_hidden_powershell','launch',30,'Downloader','Starts PowerShell hidden, without a profile or with policy bypass.',
     (r'powershell(?:\.exe)?["\'\s][^\r\n]{0,160}(?:-w(?:indowstyle)?\s+h|-nop\b|-noni\b|-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{16}|bypass)',r'-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{16}|\biex\b|invoke-expression|frombase64string|downloadstring|invoke-webrequest|\biwr\b|net\.webclient')),
    (('vbscript','javascript','batch','powershell'),'lolbin_remote_fetch','download',30,'Downloader','Uses a built-in Windows tool to fetch or run content from the Internet.',
     (r'\b(?:mshta|regsvr32|rundll32|certutil|bitsadmin|curl|msiexec)(?:\.exe)?\b[^\r\n]{0,160}https?://',)),
    (('vbscript','javascript'),'encoded_wsh_script','evasion',30,'Script','Hides its code with legacy Windows script encoding (#@~^).',(r'#@~\^',)),
    (('html',),'hta_script_with_shell','launch',30,'Downloader','An HTML application whose VB or J script creates system objects.',
     (r'<script[^>]{0,60}language\s*=\s*["\']?(?:vb|j)script|hta:application',r'createobject|activexobject|getobject')),
    (('shell','python','perl','ruby','php'),'reverse_shell','remote_control',45,'Backdoor','Opens a reverse shell over the network.',
     (r'/dev/(?:tcp|udp)/|nc\s+(?:-\w+\s+)*-e\s|socket\.socket[^\n]{0,200}\n?.{0,200}(?:dup2|subprocess)|fsockopen\s*\(.{0,120}(?:exec|shell_exec|system)|bash\s+-i\s+>&',)),
    (('shell',),'unix_persistence','persistence',22,'Persistence','Adds a cron job, rc.local entry or authorized SSH key.',(r'crontab\s|/etc/rc\.local|/etc/cron|\.ssh/authorized_keys|/etc/ld\.so\.preload',)),
    (('shell',),'unix_destruction','destruction',55,'Destructive','Wipes the root file system or a disk.',(r'rm\s+-[rf]{2}\s+/(?:\s|\*|$)|dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[sh]d|mkfs\.\w+\s+/dev/',)),
    (('shell',),'botnet_killer_shape','remote_control',22,'Botnet','Fetches and runs per-architecture binaries from a server.',(r'(?:wget|curl|tftp)[^\n]{0,120}(?:mips|arm|x86|mpsl|sh4|ppc)',r'chmod\s+(?:\+x|7\d\d)')),
    (('php',),'webshell','remote_control',45,'Backdoor','Runs code taken directly from a web request.',
     (r'(?:eval|assert|system|shell_exec|passthru|exec|popen)\s*\(.{0,80}\$_(?:get|post|request|cookie)|eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)',)),
)
OBFUSCATOR_ID=re.compile(r'\b_0x[0-9a-f]{4,6}\b',re.I)
RUNTIME_TOKENS=re.compile(r'\b(?:window|document|require|module\.exports|exports|navigator|process\.env)\b')
_COMPILED=[(kinds,code,group,weight,category,text,[re.compile(p,re.I|re.S) for p in patterns]) for kinds,code,group,weight,category,text,patterns in RULES]


def _decode(data):
    raw=bytes(data[:8*1024*1024])
    if raw[:2] in (b'\xff\xfe',b'\xfe\xff'):
        try:return raw.decode('utf-16')
        except UnicodeError:pass
    if raw[:256].count(b'\0')>len(raw[:256])//4:
        try:return raw.decode('utf-16le')
        except UnicodeError:pass
    return raw.decode('utf-8-sig',errors='replace')


def variants_of(data,kind,omissions):
    """Original text plus bounded normalized forms, so concealment does not hide behavior."""
    from sentinelav.detection.content_analysis import normalized_variants
    texts=[_decode(data)]
    if kind in SUFFIX:
        payloads,errors=normalized_variants(data,SUFFIX[kind])
        omissions.extend(errors)
        texts.extend(_decode(payload) for _,payload in payloads)
    return texts


def indicators(data,kind,omissions=None,text=None):
    omissions=[] if omissions is None else omissions
    texts=[text] if text is not None else variants_of(data,kind,omissions)
    found={}
    for kinds,code,group,weight,category,explanation,patterns in _COMPILED:
        if kinds is not None and kind not in kinds:continue
        for candidate in texts:
            if all(pattern.search(candidate[:4*1024*1024]) for pattern in patterns):
                sample=patterns[0].search(candidate[:4*1024*1024]).group()
                found[code]=indicator(code,group,weight,explanation,category=category,evidence=sample[:120])
                break
    # javascript-obfuscator output that never touches a browser or Node.js runtime is a loose Windows Script Host program.
    head=texts[0][:4*1024*1024]
    if kind=='javascript' and len(OBFUSCATOR_ID.findall(head[:1024*1024]))>=30 and not RUNTIME_TOKENS.search(head):
        found['standalone_obfuscated_wsh_script']=indicator('standalone_obfuscated_wsh_script','evasion',35,'A standalone script hides its code with an obfuscator and runs outside any browser or Node.js app.',category='Script')
    if len(texts)>1 and any(t!=texts[0] for t in texts[1:]) and found:
        found['content_concealment']=indicator('content_concealment','obfuscation',10,'Risky behavior became visible only after decoding concealed text.',category='Script')
    return list(found.values())

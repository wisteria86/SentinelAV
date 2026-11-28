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
    # Commodity loaders and stealers: each rule names one technique that loose legitimate scripts have little reason to use.
    (('powershell','batch','vbscript','javascript','html','python'),'defender_exclusion','evasion',40,'Evasion','Adds a Microsoft Defender exclusion so its files are not scanned.',
     (r'add-mppreference\b[^\r\n]{0,200}-exclusion(?:path|process|extension|ipaddress)|\\windows defender\\exclusions\\',)),
    (('batch',),'batch_hidden_payload','loader',45,'Dropper','A batch file reads its own text with PowerShell and decodes or decrypts a payload hidden inside it.',
     (r'%~(?:[dps]*(?:f|nx)[a-z]*)?0\b|%0\b',r'powershell|pwsh',r'frombase64string|createdecryptor|aesmanaged|aes\]::create|gzipstream|deflatestream')),
    (('batch','powershell','vbscript','javascript'),'renamed_system_binary','evasion',40,'Evasion','Copies PowerShell or cmd.exe under another name, a trick to dodge command-line monitoring.',
     (r'(?:copy|xcopy|copy-item|\.copyfile)\b[^\r\n]{0,200}(?:windowspowershell\\v1\.0\\powershell\.exe|system32\\cmd\.exe)[^\r\n]{0,200}\.exe',)),
    (('batch',),'batch_download_and_run','download',40,'Downloader','Downloads a program or script with a built-in tool and then starts it.',
     (r'curl(?:\.exe)?\s[^\r\n]{0,200}(?:-o|--output)\s|bitsadmin[^\r\n]{0,80}/transfer|certutil[^\r\n]{0,40}-urlcache|invoke-webrequest[^\r\n]{0,200}-outfile|\.downloadfile\(',
      r'\bstart\b[^\r\n]{0,80}\.(?:exe|bat|cmd|vbs|js|ps1|hta|scr|msi)\b|\bcall\b[^\r\n]{0,80}\.(?:bat|cmd)\b|start-process|\bmsiexec\b|\bwscript\b|\bcscript\b|\bmshta\b|\brundll32\b')),
    (('batch','powershell','vbscript','javascript','python'),'scheduled_task_persistence','persistence',25,'Persistence','Creates a scheduled task that runs a script or a program from a user-writable folder.',
     (r'schtasks(?:\.exe)?\s[^\r\n]{0,40}/create|register-scheduledtask|new-scheduledtaskaction',r'appdata|%temp%|\\temp\\|programdata|\\users\\public|\$env:(?:appdata|temp|localappdata)|\.vbs\b|\.js\b|powershell')),
    (('powershell','batch'),'decrypt_and_execute','loader',40,'Dropper','Decrypts or decompresses hidden data and then runs it.',
     (r'createdecryptor|aesmanaged|aescryptoserviceprovider|rijndaelmanaged|security\.cryptography\.aes\]::create|gzipstream|deflatestream',r'invoke-expression|\biex\b|assembly\]::load|\.entrypoint\.invoke|invokescript')),
    (('powershell','batch'),'obfuscated_invocation','evasion',30,'Script','Spells Invoke-Expression out of characters of built-in variables to hide what it runs.',
     (r'\$env:comspec\[\d+,\s*\d+,\s*\d+\]|\$pshome\[\d+\]\s*\+\s*\$pshome\[\d+\]|\$shellid\[\d+\]\s*\+|\$verbosepreference\.tostring\(\)\[|\(\s*gv\s+[\'"]?\*mdr\*|\(\s*get-variable\s+[\'"]?\*mdr\*',)),
    (('python',),'python_exec_decoded','loader',40,'Dropper','Runs code that it first decodes, decompresses or unmarshals.',
     (r'\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:__import__\s*\(\s*[\'"](?:base64|zlib|marshal|lzma|bz2|codecs|binascii|gzip)[\'"]\s*\)|(?:base64|zlib|marshal|lzma|bz2|codecs|binascii|gzip)\s*\.\s*\w*(?:decode|decompress|loads|unhexlify)|bytes\.fromhex)',)),
    (('python',),'python_obfuscator','packing',20,'Script','Carries the runtime or markers of a Python obfuscator.',(r'__pyarmor__|pyarmor_runtime|from\s+pytransform\s+import|blankobf|obfuscated\s+(?:with|by)\s+\w+',)),
    (('python',),'python_shellcode_runner','injection',45,'Injector','Allocates executable memory and runs raw machine code from Python.',
     (r'\bctypes\b|\bcffi\b',r'virtualalloc(?:ex)?|ntallocatevirtualmemory|virtualprotect',r'createthread|createremotethread|rtlmovememory|writeprocessmemory|cfunctype|queueuserapc|enumsystemlocales',
      r'b64decode|urlopen|requests\.(?:get|post)|socket\.socket|(?:bytes|bytearray)\.fromhex|decrypt|\^\s*(?:key|k)\b')),
    (('python','powershell','javascript','batch','vbscript'),'chat_webhook_exfiltration','credentials',45,'Stealer','Sends collected browser or wallet data to a chat webhook or bot.',
     (r'discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot',r'login data|local state|cookies|leveldb|cryptunprotectdata|wallet.dat|exodus|metamask')),
    (('python','powershell','javascript','batch','vbscript'),'browser_secret_decryption','credentials',30,'Stealer','Decrypts browser-saved passwords or cookies with the Windows data-protection API.',
     (r'cryptunprotectdata|protecteddata\]::unprotect|win32crypt',r'login data|local state|cookies|encrypted_key|os_crypt')),
    (('python',),'python_download_and_run','download',40,'Downloader','Downloads a program or script and starts it.',
     (r'urlretrieve|\.content\s*\)|wget\.download|\.iter_content\(',r'os\.startfile|subprocess\.(?:popen|call|run|check_call)|os\.system|os\.popen',r'\.exe\b|\.bat\b|\.cmd\b|\.ps1\b|\.vbs\b|\.scr\b|\.msi\b|powershell')),
    (('python',),'python_hidden_process','evasion',20,'Script','Starts a hidden console process.',
     (r'creationflags\s*=\s*(?:0x0*8000000|134217728|subprocess\.create_no_window|create_no_window)|wshowwindow\s*=\s*0',r'powershell|cmd(?:\.exe)?\s*/c|reg\s+add|schtasks|\.exe\b')),
    (('python',),'python_autorun','persistence',25,'Persistence','Adds itself to the Windows autorun registry key.',(r'\bwinreg\b|\breg\s+add\b',r'currentversion\\{1,2}run\b')),
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
    """Turn script bytes into text, detecting UTF-16 and falling back to UTF-8."""
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
    from sentinelav.detection.script_decoders import batch_expand,powershell_normalize
    texts=[_decode(data)]
    raw=bytes(data[:8*1024*1024])
    # cmd.exe reads a batch file as 8-bit text, so a UTF-16 mark in front only hides it from editors and scanners.
    if kind=='batch' and raw[:2] in (b'\xff\xfe',b'\xfe\xff'):texts.append(raw[2:].decode('utf-8','replace'))
    if kind=='batch':texts.extend(text for text in (batch_expand(t) for t in list(texts)) if text)
    if kind in ('batch','powershell'):texts.extend(text for text in (powershell_normalize(t) for t in list(texts)) if text)
    if kind in SUFFIX:
        # Base64 and literal decoding also runs on the expanded forms, where batch-wrapped PowerShell keeps its payload.
        for source in [data]+[t.encode('utf-8','replace') for t in texts[1:4]]:
            payloads,errors=normalized_variants(source,SUFFIX[kind])
            omissions.extend(errors)
            texts.extend(_decode(payload) for _,payload in payloads)
    return list(dict.fromkeys(texts))


def indicators(data,kind,omissions=None,text=None):
    """Check a script against every behaviour rule in RULES.

    The rules are tried on the original text and on all its decoded forms, so hiding code behind
    encoding does not help. If a rule only matched after decoding, an extra 'content concealment'
    indicator is added too.
    """
    omissions=[] if omissions is None else omissions
    texts=[text] if text is not None else variants_of(data,kind,omissions)
    found={};hidden=False
    for kinds,code,group,weight,category,explanation,patterns in _COMPILED:
        if kinds is not None and kind not in kinds:continue
        for index,candidate in enumerate(texts):
            if all(pattern.search(candidate[:4*1024*1024]) for pattern in patterns):
                sample=patterns[0].search(candidate[:4*1024*1024]).group()
                found[code]=indicator(code,group,weight,explanation,category=category,evidence=sample[:120])
                hidden=hidden or index>0
                break
    # javascript-obfuscator output that never touches a browser or Node.js runtime is a loose Windows Script Host program.
    head=texts[0][:4*1024*1024]
    if kind=='javascript' and len(OBFUSCATOR_ID.findall(head[:1024*1024]))>=30 and not RUNTIME_TOKENS.search(head):
        found['standalone_obfuscated_wsh_script']=indicator('standalone_obfuscated_wsh_script','evasion',35,'A standalone script hides its code with an obfuscator and runs outside any browser or Node.js app.',category='Script')
    found.update(_obfuscation(head,kind))
    if hidden:
        found['content_concealment']=indicator('content_concealment','obfuscation',10,'Risky behavior became visible only after decoding concealed text.',category='Script')
    return list(found.values())


SUBSTRING=re.compile(r'%[^%\s:]{1,64}:~-?\d+,-?\d+%')
CHAIN=re.compile(r'(?:%[a-z0-9_#$@]{1,64}%){6,}',re.I)
LONG_LITERAL=re.compile(r"""(['"])[A-Za-z0-9+/=_\-\\x]{4000,}\1""")


def _obfuscation(head,kind):
    """Heavy obfuscation of a loose script is evidence by itself; ordinary admin and build scripts are written to be read."""
    found={}
    if kind=='batch':
        pieces=len(SUBSTRING.findall(head[:1024*1024]))
        sets=len(CHAIN.findall(head[:1024*1024]))
        if pieces>=25 or sets>=5:
            found['batch_heavy_obfuscation']=indicator('batch_heavy_obfuscation','evasion',38,'The batch file rebuilds its commands from many variable fragments, as batch obfuscators do.',
                category='Script',evidence=f'{pieces} substring expansions, {sets} chains of six or more variables')
    if kind=='python':
        imports=len(re.findall(r'__import__\s*\(',head[:1024*1024]))
        if re.search(r'\b(?:exec|eval)\s*\(',head) and (LONG_LITERAL.search(head[:4*1024*1024]) or imports>=5):
            found['python_packed_code']=indicator('python_packed_code','evasion',30,'The script runs a long encoded literal or builds its imports at runtime, as Python packers do.',
                category='Script',evidence=f'{imports} dynamic imports')
    return found

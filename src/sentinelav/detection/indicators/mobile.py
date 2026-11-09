# Purpose: Static Android and Java indicators read in memory from bounded archive members.
# Works with: detection.threat_score, detection.indicators.strings
# Used by: detection.indicators

"""Static Android and Java indicators read in memory from bounded archive members."""
import io
import zipfile
from sentinelav.detection.indicators.strings import extract
from sentinelav.detection.threat_score import indicator

MEMBER_LIMIT=32*1024*1024
PERMISSIONS=('SEND_SMS','RECEIVE_SMS','READ_SMS','READ_CONTACTS','CALL_PHONE','PROCESS_OUTGOING_CALLS','RECORD_AUDIO','READ_CALL_LOG',
    'BIND_DEVICE_ADMIN','BIND_ACCESSIBILITY_SERVICE','SYSTEM_ALERT_WINDOW','RECEIVE_BOOT_COMPLETED','REQUEST_INSTALL_PACKAGES','WRITE_SETTINGS','READ_PHONE_STATE','INTERNET','WRITE_EXTERNAL_STORAGE')
ANDROID_CODE=(
    ('dynamic_code_loading','evasion',18,'Trojan','Loads extra code at runtime.',('dexclassloader','pathclassloader','inmemorydexclassloader')),
    ('shell_or_root_commands','injection',20,'Trojan','Runs shell commands or tries to gain root.',('runtime;->exec','/system/bin/su','/system/xbin/su','supersu','getruntime')),
    ('sms_sending_code','fraud',28,'SmsTrojan','Contains code that sends SMS messages without an interface.',('sendtextmessage','sendmultiparttextmessage')),
    ('sms_interception','credentials',24,'SmsTrojan','Intercepts or aborts incoming SMS messages.',('abortbroadcast','android.provider.telephony.sms_received')),
    ('device_admin_abuse','persistence',18,'Trojan','Requests device-administrator control or locks the device.',('devicepolicymanager','locknow','resetpassword')),
    ('native_exploit_names','injection',32,'Exploit','Names a known Android root exploit technique.',('rageagainstthecage','exploid','zergrush','gingerbreak','psneuter')),
)
JAVA_CODE=(
    ('runtime_exec','injection',20,'Trojan','Launches operating-system commands.',('java/lang/runtime','getruntime'),('exec',)),
    ('remote_class_loading','download',24,'Downloader','Loads classes from a URL at runtime.',('urlclassloader','defineclass'),('java/net/url','openstream','openconnection')),
    ('sandbox_escape_terms','exploit',32,'Exploit','Manipulates the Java security manager, as sandbox exploits do.',('setsecuritymanager','accesscontroller'),('protectiondomain','allpermission')),
    ('remote_control_terms','remote_control',24,'Backdoor','Combines sockets with screen or key capture.',('java/net/socket',),('java/awt/robot','createscreencapture')),
)


def _members(data):
    """Bounded in-memory read of code members; nothing is extracted to disk."""
    result=[];manifest=b'';total=0
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        for item in archive.infolist()[:4096]:
            name=item.filename.casefold()
            if item.flag_bits&1 or item.file_size>MEMBER_LIMIT or total+item.file_size>4*MEMBER_LIMIT:continue
            if name=='androidmanifest.xml' or name=='meta-inf/manifest.mf':
                manifest=archive.read(item);total+=len(manifest)
            elif name.endswith(('.dex','.class')):
                content=archive.read(item);total+=len(content);result.append(content)
    return manifest,result


def android_indicators(data,kind):
    if kind=='apk':
        manifest,code=_members(data)
    else:manifest,code=b'',[bytes(data)]
    found=[]
    # The binary manifest stores names as UTF-16 string-pool entries; read both encodings without XML parsing.
    plain=extract(manifest,4*1024*1024)
    requested={name for name in PERMISSIONS if name.casefold() in plain}
    sms=requested&{'SEND_SMS','RECEIVE_SMS','READ_SMS'}
    if sms and 'RECEIVE_BOOT_COMPLETED' in requested:found.append(indicator('sms_with_boot_start','fraud',26,'Requests SMS access and starts at boot, an unusual pairing for ordinary apps.',category='SmsTrojan',evidence=', '.join(sorted(requested))[:160]))
    elif sms:found.append(indicator('sms_permissions','fraud',14,'Requests SMS permissions.',category='SmsTrojan'))
    surveillance=requested&{'RECORD_AUDIO','READ_CALL_LOG','READ_CONTACTS','PROCESS_OUTGOING_CALLS','CALL_PHONE'}
    if len(surveillance)>=3:found.append(indicator('surveillance_permissions','credentials',22,'Requests several permissions that together allow surveillance of calls and contacts.',category='Spyware',evidence=', '.join(sorted(surveillance))))
    if requested&{'BIND_DEVICE_ADMIN','BIND_ACCESSIBILITY_SERVICE'} and 'SYSTEM_ALERT_WINDOW' in requested:found.append(indicator('overlay_with_admin','persistence',28,'Combines screen overlays with device-admin or accessibility control, as banking trojans do.',category='Banker'))
    text='\n'.join(extract(item,8*1024*1024) for item in code[:16])
    for code_name,group,weight,category,explanation,terms in ANDROID_CODE:
        hits=[term for term in terms if term in text]
        if hits:found.append(indicator(code_name,group,weight,explanation,category=category,evidence=', '.join(hits)[:160]))
    return found


def java_indicators(data,kind):
    if kind=='jar':_,code=_members(data)
    else:code=[bytes(data)]
    text='\n'.join(extract(item,4*1024*1024) for item in code[:256])
    found=[]
    for code_name,group,weight,category,explanation,first,second in JAVA_CODE:
        hit=[t for t in first if t in text];other=[t for t in second if t in text]
        if hit and other:found.append(indicator(code_name,group,weight,explanation,category=category,evidence=', '.join(hit+other)[:160]))
    return found

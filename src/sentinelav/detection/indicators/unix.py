# Purpose: Static ELF and Mach-O indicators using bounded header parsing and strings.
# Works with: detection.threat_score, detection.indicators.strings
# Used by: detection.indicators

"""Static ELF and Mach-O indicators using bounded header parsing and strings."""
import re
import struct
from sentinelav.detection.file_formats import byte_statistics
from sentinelav.detection.indicators.strings import extract
from sentinelav.detection.threat_score import indicator

ELF_RULES=(
    ('iot_botnet_tooling','remote_control',32,'Botnet','Contains IoT botnet traits: busybox probing with telnet or scanning.',2,r'/bin/busybox|\btelnetd?\b|\benable\b.{0,4}\bsystem\b|\blinuxshell\b|\bshell\b.{0,4}\bsh\b|/dev/watchdog|/dev/misc/watchdog|\bdvrhelper\b'),
    ('default_credential_list','remote_control',22,'Botnet','Contains a list of default device logins.',3,r'\b(?:xc3511|vizxv|admin1234|7ujmko0admin|klv123|hikvision|dreambox|realtek|root123|5up)\b'),
    ('ddos_commands','remote_control',28,'Botnet','Contains flood-attack commands.',1,r'\b(?:udp|syn|tcp|http|ack|icmp)[ _-]?flood\b|\bslowloris\b|\bhulk\b.{0,4}flood|\bdns[ _-]?amp'),
    ('watchdog_disable','evasion',18,'Botnet','Opens the hardware watchdog device, which IoT bots do to stop reboots.',1,r'/dev/(?:misc/)?watchdog'),
    ('process_hiding','evasion',22,'Rootkit','Hides from process listings or preloads a library into every program.',1,r'/etc/ld\.so\.preload|ld_preload\s*=|prctl.{0,16}pr_set_name'),
    ('kernel_module_rootkit','evasion',30,'Rootkit','References kernel rootkit techniques.',2,r'sys_call_table|kallsyms_lookup_name|init_module|hide_(?:pid|proc|module)|\bmodule_hide\b'),
    ('unix_persistence','persistence',18,'Persistence','Writes cron, init or SSH-key persistence.',2,r'/etc/crontab|/etc/cron\.|/etc/rc\.local|/etc/init\.d/|\.ssh/authorized_keys|/etc/systemd/system|\.bashrc'),
    ('credential_files','credentials',16,'Stealer','Reads system password files.',1,r'/etc/shadow'),
    ('self_propagation','replication',22,'Worm','Scans remote hosts and copies itself over SSH or telnet.',2,r'\bsshpass\b|\bscp\s|/proc/self/exe|\brandom_ip\b|\bscanner\b|\bexploit\b'),
    ('irc_client','remote_control',18,'Backdoor','Contains IRC bot commands.',3,r'\bprivmsg\b|\bjoin\s+#|\bnick\s|\bpong\b'),
    ('reverse_shell','remote_control',26,'Backdoor','Connects out and attaches a shell to the socket.',2,r'/bin/sh|/bin/bash|\bdup2\b|\bexecve?\b.{0,20}sh\b|\bconnect back\b|\bbackconnect\b'),
)
MACHO_RULES=(
    ('launch_persistence','persistence',22,'Persistence','Installs a launch agent or launch daemon to run at login.',1,r'library/launch(?:agents|daemons)|launchctl\s+load|com\.apple\.loginitems'),
    ('keychain_access','credentials',24,'Stealer','Reads the macOS keychain or browser credentials.',1,r'dump-keychain|secitemcopymatching|seckeychainfind|login\.keychain|library/application support/google/chrome'),
    ('shell_download','download',24,'Downloader','Downloads and runs a payload through a shell.',1,r'curl\s[^\n]{0,120}\|\s*(?:ba)?sh|/bin/(?:ba)?sh\s+-c|chmod\s+\+x\s|osascript\s+-e'),
    ('input_capture','input_capture',24,'Keylogger','Uses event tapping or screen-capture APIs to monitor the user.',2,r'cgeventtapcreate|iohidmanager|cgwindowlistcreateimage|screencapture|avcapture'),
    ('privilege_prompt','injection',16,'Trojan','Requests administrator rights through a security prompt.',1,r'authorizationexecutewithprivileges|\bsudo\s'),
    ('remote_control_traits','remote_control',20,'Backdoor','Combines sockets with launching a shell.',2,r'/bin/sh|\bsocket\b|\bconnect\b.{0,8}\bfailed\b|\breverse\b.{0,8}shell|\bbackdoor\b'),
    ('ransom_wording','ransomware',35,'Ransomware','Contains ransom-note wording.',2,r'files\s+(?:\w+\s+){0,2}encrypted|bitcoin|decrypt|ransom'),
)
_ELF=[(*rule[:6],re.compile(rule[6],re.I|re.S)) for rule in ELF_RULES]
_MACHO=[(*rule[:6],re.compile(rule[6],re.I|re.S)) for rule in MACHO_RULES]


def _apply(rules,text):
    found=[]
    for code,group,weight,category,explanation,minimum,pattern in rules:
        hits={m.group().strip() for _,m in zip(range(64),pattern.finditer(text))}
        if len(hits)>=minimum:found.append(indicator(code,group,weight,explanation,category=category,evidence=', '.join(sorted(hits))[:160]))
    return found


def _packed(data):
    found=[]
    if b'UPX!' in bytes(data[:4096]) or b'UPX!' in bytes(data[-4096:]):
        found.append(indicator('upx_packed','packing',20,'The file is packed with UPX, hiding its code from static inspection.',category='Packed'))
    entropy=byte_statistics(memoryview(data)[:8*1024*1024])['entropy_bits']
    if entropy>=7.4 and len(data)>=4096:
        found.append(indicator('high_entropy_image','packing',20,f'Overall entropy is {entropy:.2f} of 8, so the program is likely compressed or encrypted.',category='Packed'))
    return found


def _elf_header(data):
    found=[]
    if len(data)<52:return [indicator('truncated_elf','structure',10,'The ELF header is truncated.',category='Trojan')]
    wide=data[4]==2;order='<' if data[5]==1 else '>'
    try:
        kind=struct.unpack_from(order+'H',data,16)[0]
        shnum=struct.unpack_from(order+'H',data,60 if wide else 48)[0]
        shoff=struct.unpack_from(order+('Q' if wide else 'I'),data,40 if wide else 32)[0]
    except struct.error:
        return [indicator('truncated_elf','structure',10,'The ELF header is truncated.',category='Trojan')]
    if kind==2 and (not shnum or shoff==0 or shoff>=len(data)):
        found.append(indicator('elf_no_section_table','structure',14,'A static executable has no section table, removing symbols and hindering analysis.',category='Trojan'))
    if b'.dynsym' not in bytes(data[-65536:]) and b'.dynstr' not in bytes(data[-65536:]) and kind==2 and len(data)<4*1024*1024:
        found.append(indicator('elf_static_stripped','structure',6,'A small statically linked binary carries no dynamic symbols, common for IoT implants.',category='Trojan'))
    return found


def elf_indicators(data):
    text=extract(data)
    from sentinelav.detection.indicators.strings import indicators as generic
    return _elf_header(data)+_packed(data)+_apply(_ELF,text)+[item for item in generic(data,'elf',text) if item['group'] in ('ransomware','remote_control')]


def macho_indicators(data):
    text=extract(data)
    found=_packed(data)+_apply(_MACHO,text)
    if b'__LINKEDIT' in bytes(data[:65536]) and b'Apple Root CA' not in bytes(data) and b'Developer ID' not in bytes(data):
        found.append(indicator('macho_not_developer_signed','structure',12,'The macOS program carries no Developer ID signature.',category='Trojan'))
    return found

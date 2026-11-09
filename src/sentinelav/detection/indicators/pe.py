# Purpose: Generic PE structure, packing and imported-capability indicators.
# Works with: detection.threat_score, detection.file_formats, detection.pe_imports
# Used by: detection.indicators

"""Generic PE structure, packing and imported-capability indicators.

Each rule describes a technique. None mentions a malware family, sample name or hash.
"""
from sentinelav.detection.file_formats import byte_statistics
from sentinelav.detection.threat_score import indicator

PACKER_SECTIONS={'upx0','upx1','upx2','.aspack','.adata','aspack','.petite','petite','.nsp0','.nsp1','.packed','.themida',
    '.vmp0','.vmp1','.vmp2','.enigma1','.enigma2','pec1','pec2','.mpress1','.mpress2','.perplex','.yp','.y0da','.spack','fsg!'}
ORDINARY_SECTIONS={'.text','.code','text','code','.data','.rdata','.bss','.idata','.edata','.rsrc','.reloc','.tls','.pdata','.xdata','.didat',
    '.crt','.gfids','.00cfg','.sxdata','.orpc','.cfg','.ndata','.init','.fini','.debug','.buildid','.voltbl','.shared','.mrdata','.retplne',
    '.gehcont','.fptable','data','bss','const','_rdata','_data','_text','.itext','.tsustub','.tsuarch','.wixburn','.ctors','.dtors'}
# required = all groups must match; each group is any-of. (code, group, weight, category, explanation)
CAPABILITIES=(
    ((('openprocess','ntopenprocess','zwopenprocess'),('virtualallocex','ntallocatevirtualmemory','zwallocatevirtualmemory'),
      ('writeprocessmemory','ntwritevirtualmemory','zwwritevirtualmemory'),('createremotethread','createremotethreadex','ntcreatethreadex','rtlcreateuserthread','queueuserapc','setthreadcontext')),
     'process_injection','injection',32,'Injector','Imports the complete set of calls used to inject code into another process.'),
    ((('createprocessa','createprocessw','createprocessinternalw'),('ntunmapviewofsection','zwunmapviewofsection'),('setthreadcontext','wow64setthreadcontext','ntsetcontextthread'),('resumethread','ntresumethread')),
     'process_hollowing','injection',38,'Injector','Imports the calls used to replace the memory of a newly created process (process hollowing).'),
    ((('setwindowshookexa','setwindowshookexw'),('getasynckeystate','getkeystate','getkeyboardstate','getforegroundwindow','callnexthookex')),
     'input_capture','input_capture',22,'Keylogger','Installs a Windows hook and reads keyboard or window state, as keyloggers do.'),
    ((('getasynckeystate',),('getforegroundwindow',),('getwindowtexta','getwindowtextw')),
     'keystroke_polling','input_capture',16,'Keylogger','Polls keystrokes together with the active window title.'),
    ((('urldownloadtofilea','urldownloadtofilew','urldownloadtocachefilea','urldownloadtocachefilew'),),
     'download_to_file','download',20,'Downloader','Imports an API that saves a file directly from a URL.'),
    ((('internetopenurla','internetopenurlw','winhttpopenrequest','httpsendrequesta','httpsendrequestw'),('writefile',),('winexec','shellexecutea','shellexecutew','createprocessa','createprocessw')),
     'download_and_run','download',14,'Downloader','Combines HTTP requests, file writes and program launching.'),
    ((('cryptencrypt','bcryptencrypt','cryptgenkey','bcryptgeneratesymmetrickey'),('findfirstfilea','findfirstfilew','findfirstfileexw'),('findnextfilea','findnextfilew'),('movefilea','movefilew','movefileexa','movefileexw','deletefilea','deletefilew','writefile')),
     'bulk_file_crypto','ransomware',12,'Ransomware','Combines encryption with enumerating and rewriting files.'),
    ((('credenumeratea','credenumeratew','credreadw','credreada','lsaretrieveprivatedata','samiconnect','cryptunprotectdata'),('regopenkeyexa','regopenkeyexw','findfirstfilea','findfirstfilew')),
     'credential_access','credentials',14,'Stealer','Reads stored credentials or protected user secrets.'),
    ((('isdebuggerpresent','checkremotedebuggerpresent'),('ntqueryinformationprocess','zwqueryinformationprocess','outputdebugstringa','ntsetinformationthread','zwsetinformationthread'),('gettickcount','queryperformancecounter','gettickcount64')),
     'anti_analysis','evasion',8,'Evasion','Combines debugger checks with timing checks, which can indicate anti-analysis logic.'),
    ((('openscmanagera','openscmanagerw'),('createservicea','createservicew'),('startservicea','startservicew')),
     'service_install','persistence',10,'Persistence','Creates and starts a Windows service.'),
    ((('adjusttokenprivileges',),('lookupprivilegevaluea','lookupprivilegevaluew'),('createtoolhelp32snapshot','process32first','process32firstw','openprocess')),
     'privileged_process_access','injection',8,'Trojan','Enables privileges and then enumerates or opens other processes.'),
    ((('wsastartup',),('socket',),('connect','wsaconnect','sendto'),('createprocessa','createprocessw','winexec','createpipe')),
     'remote_shell_shape','remote_control',14,'Backdoor','Combines raw sockets with launching programs, the shape of a remote shell.'),
    ((('createfilemappinga','createfilemappingw'),('mapviewoffile',),('findfirstfilea','findfirstfilew'),('setfileattributesa','setfileattributesw'),('setfiletime',)),
     'file_infector_shape','replication',10,'Virus','Maps and rewrites other files while restoring their attributes and timestamps, as file infectors do.'),
    ((('copyfilea','copyfilew'),('getmodulefilenamea','getmodulefilenamew'),('regsetvalueexa','regsetvalueexw','regcreatekeyexa','regcreatekeyexw')),
     'self_copy_persist','persistence',12,'Dropper','Copies its own image and writes the registry.'),
)


def _names(analysis):
    names=set()
    for table in ('imports','delay_imports'):
        for library in (analysis or {}).get(table,{}).get('libraries',[]):
            for symbol in library.get('symbols',[]):
                if 'name' in symbol:names.add(symbol['name'].casefold())
    return names


def _capabilities(names):
    # A runtime or framework importing hundreds of APIs satisfies many combinations by coincidence, so density discounts them.
    density=1 if len(names)<150 else .5 if len(names)<400 else .25
    return [indicator(code,group,round(weight*density),text,category=category,evidence=', '.join(sorted({n for options in required for n in options if n in names}))[:160])
        for required,code,group,weight,category,text in CAPABILITIES if all(names&set(options) for options in required)]


def _packing(metadata,analysis,names):
    found=[];sections=metadata['sections']
    code=[s for s in sections if s['executable']]
    hot=[s for s in code if s['statistics']['entropy_bits']>=7.2 and s['raw_bytes']>=1024]
    if hot:found.append(indicator('high_entropy_code','packing',20,f"Executable section '{hot[0]['name']}' has entropy {hot[0]['statistics']['entropy_bits']:.2f} of 8, so its code is likely compressed or encrypted.",category='Packed'))
    packed={s['name'].casefold() for s in sections}&PACKER_SECTIONS
    if packed:found.append(indicator('packer_section_name','packing',14,'Section names match a known executable packer: '+', '.join(sorted(packed)),category='Packed'))
    if any(s['writable'] and s['executable'] for s in sections):found.append(indicator('writable_executable_section','packing',12,'A section is both writable and executable, which self-modifying and unpacking code needs.',category='Packed'))
    if any(s['executable'] and s['raw_bytes'] and s['virtual_bytes']>12*s['raw_bytes'] and s['virtual_bytes']>65536 for s in sections) or any(s['executable'] and not s['raw_bytes'] and s['virtual_bytes']>65536 for s in sections):
        found.append(indicator('unpacks_into_empty_section','packing',12,'An executable section is far larger in memory than on disk, leaving room to unpack code at runtime.',category='Packed'))
    status=analysis.get('imports',{}).get('status') if analysis else None
    if status=='Complete' and not names:found.append(indicator('no_named_imports','packing',14,'The program declares no named imports, so it must resolve every API at runtime.',category='Packed'))
    elif status=='Complete' and len(names)<=12 and names&{'getprocaddress'} and names&{'loadlibrarya','loadlibraryw','ldrloaddll','loadlibraryexa','loadlibraryexw'}:
        found.append(indicator('dynamic_api_resolution','packing',16,'Very few imports plus GetProcAddress and LoadLibrary, so most APIs are hidden until runtime.',category='Packed'))
    return found


def _structure(data,metadata,analysis):
    found=[];sections=metadata['sections']
    entry=metadata.get('entrypoint_sections') or []
    if metadata.get('entrypoint_rva') and not entry:found.append(indicator('entrypoint_outside_sections','structure',20,'The entry point lies outside every declared section.',category='Trojan'))
    elif entry and len(sections)>1 and entry[0]==len(sections)-1 and sections[entry[0]]['name'].casefold() not in ('.text','.code','text','code','.itext'):
        found.append(indicator('entrypoint_in_last_section','structure',14,'Execution starts in the last section, a common trait of infected and packed files.',category='Virus'))
    elif entry and not sections[entry[0]]['executable']:found.append(indicator('entrypoint_not_executable','structure',16,'The entry point is in a section not marked executable.',category='Trojan'))
    if metadata.get('raw_overlaps'):found.append(indicator('overlapping_raw_sections','structure',15,'Section data ranges overlap, which compilers do not produce.',category='Trojan'))
    odd=[s['name'] for s in sections if not s['name'].strip() or any(ord(c)<32 or ord(c)>126 for c in s['name'])]
    if odd:found.append(indicator('unprintable_section_name','structure',10,'A section name is empty or contains unprintable characters.',category='Packed'))
    unusual=[s['name'] for s in sections if s['executable'] and s['name'].casefold() not in ORDINARY_SECTIONS and s['name'].casefold() not in PACKER_SECTIONS]
    if unusual:found.append(indicator('unusual_code_section_name','structure',6,'Executable code lives in a section with an unusual name: '+', '.join(map(repr,unusual[:4])),category='Trojan'))
    details=(analysis or {}).get('image_details',{})
    if details.get('tls_callbacks'):found.append(indicator('tls_callbacks','structure',5,'TLS callbacks run code before the program entry point.',category='Evasion'))
    trailing=metadata.get('trailing_bytes',0)
    if trailing>=4096 and trailing>len(data)*.3 and not details.get('certificate',{}).get('present'):
        statistics=byte_statistics(memoryview(data)[len(data)-trailing:][:4*1024*1024])
        if statistics['entropy_bits']>=7.5:found.append(indicator('high_entropy_overlay','packing',6,'A large high-entropy payload follows the end of the image.',category='Dropper'))
    start=sections[0]['raw_offset'] if sections else 0
    hits=_embedded_images(data,max(start,512))
    if hits:found.append(indicator('embedded_executable','dropper',18,f'The file carries {hits} additional complete Windows program image(s) inside it.',category='Dropper'))
    return found


def _embedded_images(data,start):
    view=bytes(data);count=0;position=view.find(b'MZ',start)
    while position>=0 and count<8:
        if position+0x40<=len(view):
            offset=int.from_bytes(view[position+0x3c:position+0x40],'little')
            if 0<offset<4096 and view[position+offset:position+offset+4]==b'PE\0\0':count+=1
        position=view.find(b'MZ',position+2)
    return count


def indicators(data,metadata,analysis,malformed=''):
    if malformed or not metadata or metadata.get('format')!='PE':
        return [indicator('malformed_pe','structure',25,'The Windows program header is damaged or deliberately malformed: '+(malformed or 'not parseable')[:160],category='Trojan')]
    names=_names(analysis)
    return _capabilities(names)+_packing(metadata,analysis,names)+_structure(data,metadata,analysis)

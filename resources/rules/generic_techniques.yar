// Original SentinelAV technique rules. They describe behaviors rather than malware
// families, and their matches add weight to the threat score instead of deciding it.

rule generic_peb_walk_shellcode
{
    meta:
        description = "Position-independent code that walks the process environment block to find APIs"
        weight = 22
        category = "Shellcode"
    strings:
        $x86_peb = { 64 A1 30 00 00 00 8B 40 0C }
        $x86_peb2 = { 64 8B ?? 30 00 00 00 8B ?? 0C 8B ?? 14 }
        $x64_peb = { 65 48 8B ?? 25 60 00 00 00 48 8B ?? 18 }
    condition:
        any of them
}

rule generic_api_hash_resolver
{
    meta:
        description = "Resolves Windows APIs by hashing their names, which hides them from static imports"
        weight = 24
        category = "Shellcode"
    strings:
        $ror13_x86 = { C1 CF 0D 01 C7 }
        $ror13_alt = { C1 CA 0D 03 D0 }
        $ror13_x64 = { 41 C1 C9 0D 41 01 C1 }
    condition:
        any of them
}

rule generic_reflective_loader
{
    meta:
        group = "injection"
        description = "Exports or names a reflective loader that maps a program directly from memory"
        weight = 30
        category = "Injector"
    strings:
        $a = "ReflectiveLoader" ascii wide
        $b = "_ReflectiveLoader@" ascii
    condition:
        any of them
}

rule generic_encoded_program_in_text
{
    meta:
        group = "dropper"
        description = "Text content embeds a Base64-encoded Windows program"
        weight = 35
        category = "Dropper"
    strings:
        $b64_mz1 = "TVqQAAMAAAAEAAAA" ascii wide
        $b64_mz2 = "TVpQAAIAAAAEAA8A" ascii wide
        $b64_mz3 = "TVoAAAAAAAAAAAAA" ascii wide
        $hex_mz = "4D5A90000300000004000000" ascii wide nocase
    condition:
        any of them
}

rule generic_process_hollowing_strings
{
    meta:
        group = "injection"
        description = "Resolves the process-hollowing APIs by name at runtime"
        weight = 28
        category = "Injector"
    strings:
        $a = "NtUnmapViewOfSection" ascii wide
        $b = "ZwUnmapViewOfSection" ascii wide
        $c = "SetThreadContext" ascii wide
        $d = "WriteProcessMemory" ascii wide
        $e = "ResumeThread" ascii wide
    condition:
        ($a or $b) and $c and $d and $e
}

rule generic_stack_built_api_names
{
    meta:
        description = "Builds API names one character at a time on the stack to avoid string scanning"
        weight = 20
        category = "Evasion"
    strings:
        $virtualalloc = { C6 45 ?? 56 C6 45 ?? 69 C6 45 ?? 72 C6 45 ?? 74 C6 45 ?? 75 C6 45 ?? 61 C6 45 ?? 6C }
        $loadlibrary = { C6 45 ?? 4C C6 45 ?? 6F C6 45 ?? 61 C6 45 ?? 64 C6 45 ?? 4C C6 45 ?? 69 }
    condition:
        any of them
}

rule generic_mbr_overwrite
{
    meta:
        group = "destruction"
        description = "Program that opens the first physical disk directly and imports file-write calls"
        weight = 30
        category = "Bootkit"
    strings:
        $disk_a = "\\\\.\\PhysicalDrive0" ascii wide nocase
        $write = "WriteFile" ascii
    condition:
        uint16(0) == 0x5A4D and $disk_a and $write
}

rule generic_ransom_note_template
{
    meta:
        group = "ransomware"
        description = "Embeds an instruction template for paying to recover encrypted files"
        weight = 30
        category = "Ransomware"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "files are encrypted" ascii wide nocase
        $c = "to decrypt your files" ascii wide nocase
        $d = "how to decrypt" ascii wide nocase
        $e = "private key" ascii wide nocase
        $f = "bitcoin" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and ($a or $b or $c or $d) and ($e or $f)
}

rule generic_macro_virus_copy_routine
{
    meta:
        group = "replication"
        description = "Office macro code that copies itself through the VBA project object model"
        weight = 30
        category = "MacroVirus"
    strings:
        $a = "VBComponents" ascii wide nocase
        $b = "CodeModule" ascii wide nocase
        $c = "InsertLines" ascii wide nocase
        $d = "AddFromString" ascii wide nocase
        $e = "NormalTemplate" ascii wide nocase
    condition:
        2 of them
}

rule generic_elf_scanner_bot
{
    meta:
        group = "remote_control"
        description = "Linux program that combines busybox probing with network scanning"
        weight = 26
        category = "Botnet"
    strings:
        $busy = "/bin/busybox" ascii
        $proc = "/proc/net/tcp" ascii
        $wd1 = "/dev/watchdog" ascii
        $wd2 = "/dev/misc/watchdog" ascii
        $tftp = "tftp" ascii
        $wget = "wget" ascii
    condition:
        uint32(0) == 0x464C457F and $busy and ($proc or $wd1 or $wd2 or $tftp or $wget)
}

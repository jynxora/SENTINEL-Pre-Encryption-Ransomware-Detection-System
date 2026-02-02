rule Win32_Ransomware_LockBit
{
    meta:
        description = "Detects LockBit ransomware (including variants like LockBit 3.0/4.0)"
        author = "Jinay Shah (from ReversingLabs, Ransomware.live, CISA)"
        severity = "critical"
        reference = "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/yara/ransomware/Win32.Ransomware.LockBit.yara; https://www.ransomware.live/yara/LockBit3/LockBit.yar"
        date = "2026-01-30"
        mitre_technique = "T1486"
        false_positive_risk = "Low"
        hash_example = "b895399bdd8b07b14e1e613329b76911ebe37ab038e4b760f41e237f863b4964"

    strings:
        // Code patterns (from ReversingLabs)
        $enum_resources_v1 = { 55 8B EC 83 EC ?? 57 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 51 6A ?? 6A ?? 6A ?? C7 45 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
        $code1 = { 64 A1 30 00 00 00 8B B0 A4 00 00 00 8B B8 A8 00 00 00 }  // Packer/encryption routine

        // Strings
        $str1 = "LockBit" ascii wide nocase
        $str2 = "lockbitapt" ascii nocase
        $str3 = "Restore-My-Files.txt" ascii nocase
        $str4 = "All your files are encrypted by LockBit" ascii wide nocase
        $str5 = ".lockbit" ascii nocase  // File extension
        $str6 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide nocase  // Mutex

    condition:
        uint16(0) == 0x5A4D and  // PE magic
        filesize > 30KB and filesize < 5MB and
        ((1 of ($enum_resources*) or 1 of ($code*)) or  // Code patterns
        2 of ($str*))  // Strings
}

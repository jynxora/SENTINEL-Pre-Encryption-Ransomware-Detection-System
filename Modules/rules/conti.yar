import "pe"

rule Win32_Ransomware_Conti
{
    meta:
        description = "Detects Conti ransomware"
        author = "Jinay Shah (from ReversingLabs, CISA, SOC Prime)"
        severity = "critical"
        reference = "https://github.com/reversinglabs/reversinglabs-yara-rules/blob/develop/yara/ransomware/Win32.Ransomware.Conti.yara; https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a"
        date = "2026-01-30"
        mitre_technique = "T1486"
        false_positive_risk = "Low"
        hash_example = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"

    strings:
        // Code patterns (MurmurHash2 from Conti leak)
        $murmur_hash = { F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B C8 B8 09 04 02 81 83 C1 7F F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B C8 88 4C 3C 39 }

        // Strings
        $str1 = "conti" ascii wide nocase
        $str2 = "CONTI" ascii wide nocase
        $str3 = "All of your files are currently encrypted by CONTI ransomware" ascii wide nocase
        $str4 = "CONTI.txt" ascii nocase
        $str5 = ".conti" ascii nocase  // Extension
        $str6 = "CONTILOCKER" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        pe.imphash() == "6e8ca501c45a9b85fff2378cffaa24b2" and  // Specific import hash
        filesize < 5MB and
        ($murmur_hash or  // Hashing algo
        2 of ($str*))  // Strings
}

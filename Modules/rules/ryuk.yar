rule Win32_Ransomware_Ryuk
{
    meta:
        description = "Detects Ryuk ransomware"
        author = "Jinay Shah (from Elastic, McAfee, CISA)"
        severity = "critical"
        reference = "https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Ransomware_Ryuk.yar; https://www.mcafee.com/blogs/other-blogs/mcafee-labs/ryuk-ransomware-attack-rush-to-attribution-misses-the-point"
        date = "2026-01-30"
        mitre_technique = "T1486"
        false_positive_risk = "Low"
        hash_example = "fe55650d8b1b78d5cdb4ad94c0d7ba7052351630be9e8c273cc135ad3fa81a75"

    strings:
        // Code patterns (AES/RSA encryption)
        $encrypt = { 57 72 69 74 65 46 69 6c 65 }  // WriteFile for encryption
        $code1 = { 41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 }

        // Strings
        $str1 = "Ryuk" ascii wide nocase
        $str2 = "RyukReadMe.html" ascii wide nocase
        $str3 = "RyukReadMe.txt" ascii wide nocase
        $str4 = "Your network has been penetrated and all files encrypted" ascii wide nocase
        $str5 = ".ryk" ascii nocase  // Extension
        $str6 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide nocase  // From Ryuk variants

    condition:
        uint16(0) == 0x5A4D and
        filesize > 30KB and filesize < 1MB and
        ((1 of ($code*) or 1 of ($encrypt*)) or  // Encryption code
        2 of ($str*))  // Strings
}

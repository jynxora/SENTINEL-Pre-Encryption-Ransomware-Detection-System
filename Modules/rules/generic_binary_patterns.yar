import "pe"

rule Ransomware_Generic_Binary_Patterns
{
    meta:
        description = "Detects common binary patterns in ransomware (imports, hashing, packers)"
        author = "Jinay Shah (from SOC Prime, cocomelonc, Malpedia)"
        severity = "high"
        reference = "https://github.com/cocomelonc/malware-analysis; https://malpedia.caad.fkie.fraunhofer.de/details/win.conti"
        date = "2026-01-30"
        mitre_technique = "T1027"  // Obfuscated Files or Information
        false_positive_risk = "Medium"

    strings:
        // Common Imports (encryption APIs)
        $import1 = "CryptEncrypt" ascii
        $import2 = "CryptAcquireContext" ascii
        $import3 = "RtlAdjustPrivilege" ascii  // Privilege escalation
        $import4 = "NetShareEnum" ascii  // Network discovery

        // Hashing (MurmurHash2 from Conti/Ryuk)
        $murmur = { F7 E9 03 D1 C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F 2B C8 }

        // Packers/Evasion
        $packer1 = { 55 8B EC 83 EC ?? 57 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 51 6A ?? }  // Common packer prologue

    condition:
        uint16(0) == 0x5A4D and
        filesize > 30KB and filesize < 5MB and
        (pe.number_of_imports > 5 and  // Ransomware often has many imports
        2 of ($import*) or
        $murmur or
        $packer1)
}

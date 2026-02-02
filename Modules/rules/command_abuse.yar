rule Ransomware_Command_Abuse
{
    meta:
        description = "Detects command-line abuse common in ransomware (e.g., shadow copy deletion, boot tampering)"
        author = "Jinay Shah (inspired by CISA, MITRE ATT&CK, SOC Prime)"
        severity = "critical"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a; https://attack.mitre.org/techniques/T1490/"
        date = "2026-01-30"
        mitre_technique = "T1490"  // Inhibit System Recovery
        false_positive_risk = "Medium - admins may use similar commands"

    strings:
        // Shadow Copy Deletion
        $shadow1 = "vssadmin delete shadows" ascii nocase
        $shadow2 = "vssadmin.exe delete shadows" ascii nocase
        $shadow3 = "delete shadows /all" ascii nocase
        $shadow4 = "wmic shadowcopy delete" ascii nocase
        $shadow5 = "resize shadowstorage /maxsize" ascii nocase
        $shadow6 = "vssadmin resize shadowstorage /maxsize=401mb" ascii nocase  // Ryuk-specific

        // Boot Manipulation
        $boot1 = "bcdedit /set" ascii nocase
        $boot2 = "bootstatuspolicy ignoreallfailures" ascii nocase
        $boot3 = "recoveryenabled no" ascii nocase
        $boot4 = "bcdedit.exe /set {default}" ascii nocase
        $boot5 = "bcdedit /deletevalue" ascii nocase

        // Backup Deletion
        $backup1 = "wbadmin delete catalog" ascii nocase
        $backup2 = "wbadmin delete backup" ascii nocase
        $backup3 = "wbadmin delete systemstatebackup" ascii nocase
        $backup4 = "catalog -quiet" ascii nocase
        $backup5 = "vssadmin delete" ascii nocase  // Overlap with shadow

        // Service Manipulation (Stops services to free files for encryption)
        $service1 = "net stop" ascii nocase
        $service2 = "sc stop" ascii nocase
        $service3 = "sc config" ascii nocase
        $service4 = "set start= disabled" ascii nocase
        $service5 = "vss" ascii nocase  // Volume Shadow Copy
        $service6 = "sql" ascii nocase  // SQL services
        $service7 = "backup" ascii nocase
        $service8 = "veeam" ascii nocase  // Backup tools
        $service9 = "sophos" ascii nocase  // AV

        // Encryption Activity
        $encrypt1 = "cipher /w" ascii nocase  // Wipes free space
        $encrypt2 = "cipher.exe" ascii nocase
        $encrypt3 = "/e /s" ascii nocase  // Encrypt directories
        $encrypt4 = "vssadmin resize shadowstorage /maxsize=unbounded" ascii nocase  // Ryuk

        // Lateral Movement/Network Discovery
        $lateral1 = "psexec" ascii nocase
        $lateral2 = "wmic /node" ascii nocase
        $lateral3 = "net view" ascii nocase
        $lateral4 = "net share" ascii nocase
        $lateral5 = "net use \\\\" ascii nocase  // UNC paths

    condition:
        (
            (2 of ($shadow*)) or
            (2 of ($boot*)) or
            (1 of ($shadow*) and 1 of ($boot*)) or
            (2 of ($backup*)) or
            (3 of ($service*)) or
            (2 of ($encrypt*)) or
            (2 of ($lateral*)) or
            (1 of ($shadow*) and 1 of ($service*)) or
            (1 of ($boot*) and 1 of ($backup*))
        )
}

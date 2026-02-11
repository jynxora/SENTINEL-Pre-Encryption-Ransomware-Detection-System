"""
Behavior Tags Configuration
Centralized taxonomy with ransomware-specific classifications.

RANSOMWARE DETECTION PHILOSOPHY:
- Each tag represents a DEFENDABLE claim based on observable behavior
- Ransomware indicators carry higher weight than general suspicious activity
- Tags accumulate to build confidence in detection
- Context emerges from pattern accumulation over time

THREAT INTELLIGENCE SOURCES:
- MITRE ATT&CK Framework (T1486, T1490, T1070, T1135)
- Lockbit 3.0, REvil, Ryuk, Conti, BlackCat/ALPHV analysis
- Public incident reports and IOC feeds
- CISA ransomware advisories

MAINTENANCE SCHEDULE:
- Review quarterly for new ransomware TTPs
- Update thresholds based on baseline telemetry
- Add exclusion rules as environment evolves
- Validate against known-good activity monthly
"""

from typing import Dict, Set, List
from typing import Optional

# ============================================================================
# TAG TAXONOMY WITH RANSOMWARE FOCUS
# ============================================================================

TAG_DESCRIPTIONS = {
    # Tool Classification Tags
    "interactive_shell": "Process is an interactive command shell (cmd.exe, powershell.exe)",
    "script_engine": "Process can execute scripts/code (PowerShell, WSH, Python)",
    "system_utility": "Windows built-in administrative utility",
    "system_loader": "Windows DLL/binary loader utility (rundll32, regsvr32)",
    "remote_execution": "Tool designed for remote command execution",
    "archive_utility": "Compression/archive manipulation tool",
    "interpreter": "Programming language interpreter",
    "deprecated_tool": "Tool deprecated by Microsoft (e.g., WMIC)",
    "download_capable": "Tool can download files from internet",
    
    # RANSOMWARE-SPECIFIC TOOL TAGS
    "ransomware_tool": "Tool commonly used by ransomware (vssadmin, bcdedit, cipher)",
    "backup_manipulation": "Tool that can manipulate backups (vssadmin, wbadmin)",
    "boot_configuration": "Tool that modifies boot configuration (bcdedit)",
    "encryption_tool": "Tool capable of file encryption (cipher.exe)",
    "file_system_manipulation": "Tool that modifies file system (fsutil)",
    "permission_manipulation": "Tool that changes permissions (icacls, takeown)",
    
    # Behavioral Tags (General)
    "living_off_the_land": "Binary commonly abused by attackers (LOLBin)",
    "known_admin_tool": "Recognized legitimate admin/dev tool",
    "non_interactive_execution": "Executed with non-interactive flags (/c, -command)",
    "obfuscated_execution": "Command line shows obfuscation (base64, encoding)",
    "download_activity": "Command suggests file download operation",
    "persistence_attempt": "Command suggests persistence mechanism (registry, scheduled task)",
    "credential_access_attempt": "Command suggests credential access (mimikatz, lsass dump)",
    
    # CRITICAL RANSOMWARE BEHAVIORAL TAGS
    "shadow_copy_deletion": "CRITICAL: Shadow copy deletion detected (vssadmin delete)",
    "boot_manipulation": "CRITICAL: Boot configuration tampering (bcdedit)",
    "backup_deletion": "CRITICAL: Backup deletion detected (wbadmin delete)",
    "service_manipulation": "Service stop/disable detected (common ransomware prep)",
    "encryption_activity": "File encryption activity detected (cipher, suspicious patterns)",
    "network_share_discovery": "Network share enumeration (net view, net share)",
    "lateral_movement": "Lateral movement attempt (psexec, wmic /node)",
    "privilege_escalation": "Privilege escalation attempt detected",
    
    # Relationship Tags
    "document_spawned_process": "Spawned by document application (Office, PDF)",
    "browser_spawned_process": "Spawned by web browser",
    "suspicious_parent_child": "Unusual parent-child relationship (Office → LOLBin)",
    
    # Session Context Tags
    "repeated_shell_activity": "User has spawned multiple shells in session",
    "multiple_lolbin_usage": "User has used multiple LOLBins in session",
    "heavy_scripting_activity": "User has heavy script execution in session",
    "diverse_tool_usage": "User has used many different tools in session",
    
    # RANSOMWARE SESSION TAGS
    "multiple_ransomware_indicators": "Multiple ransomware indicators in single session",
    "shadow_copy_activity": "Shadow copy operations detected in session",
    "multiple_ransomware_tools": "Multiple ransomware-associated tools used",
}


# ============================================================================
# ENHANCED BEHAVIOR TAG WEIGHTS (Ransomware-Prioritized)
# ============================================================================

BEHAVIOR_TAGS = {
    # General suspicious behaviors
    "interactive_shell": {
        "weight": 1,
        "scope": "session",
        "confidence_impact": "low",
        "rationale": "Common in both legitimate admin work and post-exploitation"
    },
    
    "script_engine_execution": {
        "weight": 2,
        "scope": "event",
        "confidence_impact": "low",
        "rationale": "Scripts widely used legitimately, but also by ransomware"
    },
    
    "lolbin_abuse": {
        "weight": 3,
        "scope": "event",
        "confidence_impact": "medium",
        "rationale": "Living-off-the-land binaries are ransomware staples"
    },
    
    "obfuscated_execution": {
        "weight": 4,
        "scope": "event",
        "confidence_impact": "medium",
        "rationale": "Encoded commands significantly indicate malicious intent"
    },
    
    # CRITICAL RANSOMWARE BEHAVIORS (High Weight)
    "shadow_copy_deletion": {
        "weight": 20,
        "scope": "event",
        "confidence_impact": "critical",
        "rationale": "DEFINITIVE ransomware indicator - inhibits system recovery (MITRE T1490)",
        "mitre_technique": "T1490",
        "false_positive_risk": "Very Low - rarely legitimate outside of specific backup software"
    },
    
    "boot_manipulation": {
        "weight": 20,
        "scope": "event",
        "confidence_impact": "critical",
        "rationale": "DEFINITIVE ransomware indicator - prevents recovery boot (MITRE T1490)",
        "mitre_technique": "T1490",
        "false_positive_risk": "Very Low - extremely rare in normal operations"
    },
    
    "backup_deletion": {
        "weight": 18,
        "scope": "event",
        "confidence_impact": "critical",
        "rationale": "Strong ransomware indicator - removes recovery options (MITRE T1490)",
        "mitre_technique": "T1490",
        "false_positive_risk": "Low - legitimate only in controlled backup management"
    },
    
    "encryption_activity": {
        "weight": 15,
        "scope": "event",
        "confidence_impact": "high",
        "rationale": "Potential data encryption for impact (MITRE T1486)",
        "mitre_technique": "T1486",
        "false_positive_risk": "Medium - cipher.exe has legitimate uses"
    },
    
    "service_manipulation": {
        "weight": 8,
        "scope": "event",
        "confidence_impact": "medium",
        "rationale": "Ransomware stops services to release file locks (MITRE T1489)",
        "mitre_technique": "T1489",
        "false_positive_risk": "High - common in legitimate admin and deployment"
    },
    
    "lateral_movement": {
        "weight": 12,
        "scope": "event",
        "confidence_impact": "high",
        "rationale": "Ransomware spreads across network (MITRE T1021)",
        "mitre_technique": "T1021",
        "false_positive_risk": "Medium - legitimate remote admin tools exist"
    },
    
    "credential_access_attempt": {
        "weight": 10,
        "scope": "session",
        "confidence_impact": "high",
        "rationale": "Credential harvesting for privilege escalation (MITRE T1003)",
        "mitre_technique": "T1003",
        "false_positive_risk": "Medium - security tools may trigger this"
    },
    
    "network_share_discovery": {
        "weight": 6,
        "scope": "session",
        "confidence_impact": "medium",
        "rationale": "Ransomware enumerates network shares for encryption (MITRE T1135)",
        "mitre_technique": "T1135",
        "false_positive_risk": "High - very common in legitimate network operations"
    },
}


# ============================================================================
# ENHANCED RISK THRESHOLDS (Weighted Scoring)
# ============================================================================

RISK_THRESHOLDS = {
    "low": 5,      # Normal activity or single weak signal
    "medium": 15,  # Multiple weak signals or one moderate signal  
    "high": 25,    # Strong signals or critical ransomware indicator
    "critical": 40 # Multiple critical ransomware indicators (immediate response)
}


# ============================================================================
# CONFIDENCE LEVEL DEFINITIONS (Enhanced)
# ============================================================================

CONFIDENCE_LEVELS = {
    "low": {
        "description": "Single weak signal; needs context",
        "threshold": "Most benign activity falls here",
        "action": "Log and accumulate for pattern analysis",
        "response_time": "None - monitoring only"
    },
    "medium": {
        "description": "Multiple weak signals or one moderate signal",
        "threshold": "Worth attention but needs investigation",
        "action": "Flag for analyst review within 24 hours",
        "response_time": "24 hours"
    },
    "high": {
        "description": "Strong signal or multiple concerning patterns",
        "threshold": "Likely malicious or highly anomalous",
        "action": "Priority investigation - review within 4 hours",
        "response_time": "4 hours"
    },
    "critical": {
        "description": "RANSOMWARE INDICATORS DETECTED",
        "threshold": "Shadow copy deletion, boot manipulation, or multiple ransomware signals",
        "action": "IMMEDIATE RESPONSE - Isolate system, begin incident response",
        "response_time": "IMMEDIATE (<15 minutes)"
    }
}


# ============================================================================
# TUNABLE THRESHOLDS - ENVIRONMENT-SPECIFIC CALIBRATION REQUIRED
# ============================================================================

class ThresholdConfig:
    """
    Tunable thresholds for behavioral detection.
    
    CALIBRATION WORKFLOW:
    1. Run system on 7-14 days of NORMAL activity
    2. Collect enriched_events.jsonl for baseline
    3. Analyze false positive rate per threshold
    4. Adjust thresholds below to reduce FPs to acceptable level
    5. Document your decisions and rationale
    6. Re-validate quarterly
    
    ACCEPTABLE FALSE POSITIVE RATES:
    - Low confidence: 20-30% FP acceptable (monitoring only)
    - Medium confidence: 5-10% FP acceptable (requires review)
    - High confidence: <2% FP acceptable (priority investigation)
    - Critical confidence: <0.1% FP acceptable (immediate response)
    """
    
    # Session accumulation thresholds
    SHELL_REPETITION_THRESHOLD = 5      # shells in session before flagging
    LOLBIN_DIVERSITY_THRESHOLD = 3      # unique LOLBins before flagging
    SCRIPT_ACTIVITY_THRESHOLD = 4       # script executions before flagging
    TOOL_DIVERSITY_THRESHOLD = 10       # unique process names before flagging
    
    # RANSOMWARE-SPECIFIC THRESHOLDS
    RANSOMWARE_INDICATOR_THRESHOLD = 2  # ransomware indicators to flag session
    SHADOW_COPY_OPERATIONS_THRESHOLD = 1  # ANY shadow copy deletion = critical
    RANSOMWARE_TOOL_DIVERSITY = 2       # different ransomware tools used
    
    # Time windows
    SESSION_TIMEOUT_MINUTES = 30        # session inactivity timeout
    
    # Confidence elevation rules
    MULTI_SIGNAL_THRESHOLD = 2          # # of concerning tags to elevate confidence
    
    # Alert throttling (prevent alert storms)
    MAX_ALERTS_PER_USER_PER_HOUR = 10   # max alerts per user per hour
    MAX_ALERTS_SYSTEM_PER_MINUTE = 5    # max system-wide alerts per minute


# ============================================================================
# RANSOMWARE ATTACK CHAIN PATTERNS
# ============================================================================

ATTACK_CHAIN_PATTERNS = [
    {
        "name": "Classic Ransomware Kill Chain",
        "stages": [
            "Initial Access (phishing/exploit)",
            "Credential Harvesting",
            "Lateral Movement", 
            "Shadow Copy Deletion",
            "Boot Manipulation",
            "Service Termination",
            "File Encryption"
        ],
        "indicators": [
            "document_spawned_process",
            "credential_access_attempt",
            "lateral_movement",
            "shadow_copy_deletion",
            "boot_manipulation",
            "service_manipulation",
            "encryption_activity"
        ],
        "confidence": "critical",
        "response": "Immediate isolation and incident response"
    },
    {
        "name": "Hands-on-Keyboard Ransomware",
        "stages": [
            "Initial Compromise",
            "Reconnaissance",
            "Defense Evasion",
            "Persistence",
            "Impact"
        ],
        "indicators": [
            "repeated_shell_activity",
            "network_share_discovery",
            "obfuscated_execution",
            "persistence_attempt",
            "shadow_copy_deletion"
        ],
        "confidence": "high",
        "response": "Priority investigation"
    }
]


# ============================================================================
# PRIORITY INVESTIGATION COMBINATIONS (Enhanced)
# ============================================================================

PRIORITY_COMBINATIONS = [
    {
        "name": "Shadow Copy Deletion (CRITICAL)",
        "tags": {"shadow_copy_deletion"},
        "rationale": "DEFINITIVE ransomware indicator - immediate response required",
        "false_positive_risk": "Very Low",
        "mitre_technique": "T1490",
        "recommended_action": "Isolate system immediately, begin incident response",
        "priority": "CRITICAL"
    },
    {
        "name": "Boot Manipulation (CRITICAL)",
        "tags": {"boot_manipulation"},
        "rationale": "Prevents system recovery - definitive ransomware",
        "false_positive_risk": "Very Low",
        "mitre_technique": "T1490",
        "recommended_action": "Isolate system immediately, begin incident response",
        "priority": "CRITICAL"
    },
    {
        "name": "Ransomware Tool Chain",
        "tags": {"shadow_copy_deletion", "boot_manipulation", "service_manipulation"},
        "rationale": "Complete ransomware preparation sequence",
        "false_positive_risk": "Essentially Zero",
        "mitre_technique": "T1490, T1489",
        "recommended_action": "System likely compromised - full incident response",
        "priority": "CRITICAL"
    },
    {
        "name": "Office → Shell (Macro)",
        "tags": {"document_spawned_process", "interactive_shell"},
        "rationale": "Classic macro/exploit behavior - common ransomware delivery",
        "false_positive_risk": "Low",
        "mitre_technique": "T1566.001",
        "recommended_action": "Investigate user, check for additional indicators",
        "priority": "HIGH"
    },
    {
        "name": "Encoded PowerShell",
        "tags": {"script_engine", "obfuscated_execution"},
        "rationale": "Common malware delivery technique",
        "false_positive_risk": "Medium",
        "mitre_technique": "T1059.001",
        "recommended_action": "Review command line, check for malware",
        "priority": "MEDIUM"
    },
    {
        "name": "Credential Dumping",
        "tags": {"credential_access_attempt"},
        "rationale": "Direct indicator of compromise - preparation for lateral movement",
        "false_positive_risk": "Low",
        "mitre_technique": "T1003",
        "recommended_action": "Investigate immediately, check for lateral movement",
        "priority": "HIGH"
    },
    {
        "name": "Lateral Movement + Ransomware Tools",
        "tags": {"lateral_movement", "ransomware_tool"},
        "rationale": "Active ransomware spread across network",
        "false_positive_risk": "Very Low",
        "mitre_technique": "T1021, T1490",
        "recommended_action": "Network-wide incident - isolate affected systems",
        "priority": "CRITICAL"
    },
]


# ============================================================================
# EXCLUSION RULES - ENVIRONMENT-SPECIFIC (Critical for FP Reduction)
# ============================================================================

class ExclusionRules:
    """
    Known-good patterns that should NOT trigger alerts.
    
    WARNING: Building accurate exclusions requires DEEP knowledge of your environment.
    
    EXCLUSION BUILDING PROCESS:
    1. Run system on baseline for 7-14 days
    2. Review all medium+ confidence alerts
    3. For each false positive:
       a. Document: What triggered it?
       b. Document: Why is it legitimate?
       c. Create specific exclusion rule below
       d. Test that exclusion doesn't over-exclude
    4. Re-validate exclusions monthly
    
    ANTI-PATTERN WARNING:
    - Do NOT exclude by username alone (attackers use compromised accounts)
    - Do NOT exclude entire processes (e.g., all PowerShell)
    - DO use specific command-line patterns or parent-child combos
    - DO require multiple identifying factors (path + command + parent)
    """
    
    # Legitimate admin usernames (CUSTOMIZE THIS)
    KNOWN_ADMIN_USERS = frozenset([
        "administrator",
        "domain\\admin",
        # TODO: Add your legitimate admin accounts
        # WARNING: Attackers compromise admin accounts - use cautiously
    ])
    
    # Legitimate service accounts (CUSTOMIZE THIS)
    KNOWN_SERVICE_ACCOUNTS = frozenset([
        "nt authority\\system",
        "nt authority\\network service",
        "nt authority\\local service",
        # TODO: Add your service accounts
    ])
    
    # Legitimate backup software paths (CUSTOMIZE THIS)
    BACKUP_SOFTWARE_PATHS = frozenset([
        "veeam",
        "acronis",
        "commvault",
        # TODO: Add your backup software paths
    ])
    
    # Legitimate deployment tools (CUSTOMIZE THIS)
    DEPLOYMENT_TOOLS = frozenset([
        "jenkins",
        "ansible",
        "puppet",
        "chef",
        "sccm",
        "intune",
        # TODO: Add your deployment tools
    ])
    
    @staticmethod
    def is_known_good_pattern(event_data: Dict) -> bool:
        """
        Check if event matches known-good patterns.
        Returns True if event should be de-prioritized.
        
        CRITICAL: This is a TRUST decision. Wrong exclusions = missed ransomware.
        """
        proc = event_data.get("process_name", "").lower()
        cmdline = event_data.get("command_line", "").lower()
        parent = event_data.get("parent_process_name", "").lower()
        username = event_data.get("username", "").lower()
        exe_path = event_data.get("executable_path", "").lower()
        
        # System processes (generally safe)
        if username in ["nt authority\\system", "nt authority\\network service"]:
            # EXCEPTION: System account + ransomware tools = still suspicious
            if proc in ["vssadmin.exe", "bcdedit.exe", "cipher.exe"]:
                # Check if it's from legitimate backup software
                if exe_path and any(backup in exe_path for backup in ExclusionRules.BACKUP_SOFTWARE_PATHS):
                    return True
                # Otherwise, still flag it (ransomware can run as SYSTEM)
                return False
            return True
        
        # Windows Update service
        if parent == "svchost.exe" and proc in ["wuauclt.exe", "wuapihost.exe"]:
            return True
        
        # System installers (MSI)
        if "msiexec.exe" in parent and "/i" in cmdline:
            return True
        
        # Legitimate backup software using vssadmin
        if proc == "vssadmin.exe":
            # Only exclude if path matches known backup software
            if exe_path and any(backup in exe_path for backup in ExclusionRules.BACKUP_SOFTWARE_PATHS):
                return True
            # Otherwise, flag it (could be ransomware)
            return False
        
        # Legitimate deployment tools
        if any(tool in exe_path for tool in ExclusionRules.DEPLOYMENT_TOOLS):
            return True
        
        # TODO: ADD YOUR ENVIRONMENT-SPECIFIC EXCLUSIONS HERE
        # Examples to consider:
        # - Specific admin scripts (verify by full path + signature)
        # - Known update mechanisms
        # - Scheduled maintenance tasks
        # - Development/testing environments (separate monitoring?)
        
        return False
    
    @staticmethod
    def is_trusted_admin_activity(event_data: Dict) -> bool:
        """
        Determine if activity is from trusted admin (reduces confidence, doesn't exclude).
        
        WARNING: Use VERY carefully. Ransomware often uses compromised admin accounts.
        """
        username = event_data.get("username", "").lower()
        
        # TODO: Implement time-based checks
        # Example: Admins working at 3 AM = suspicious even if known admin
        
        # TODO: Implement location-based checks
        # Example: Admin account from unusual IP/location = suspicious
        
        # For now, just check username
        if username in ExclusionRules.KNOWN_ADMIN_USERS:
            # Still flag if ransomware indicators present
            tags = event_data.get("tags", [])
            if "shadow_copy_deletion" in tags or "boot_manipulation" in tags:
                return False  # Never trust these, even from admins
            return True
        
        return False


# ============================================================================
# BASELINE METRICS - ENVIRONMENT CALIBRATION
# ============================================================================

class BaselineMetrics:
    """
    Normal activity baselines for your environment.
    
    CALIBRATION WORKFLOW:
    1. Run tagger on 14+ days of NORMAL data
    2. Calculate statistics below
    3. Hard-code them here
    4. Use for anomaly detection in confidence scoring
    5. Recalculate quarterly
    """
    
    # Average process creation rate per user
    AVG_PROCESSES_PER_HOUR = None  # TODO: Calculate from baseline
    STDDEV_PROCESSES_PER_HOUR = None
    
    # Common process frequencies
    COMMON_PROCESS_DISTRIBUTION = {
        # "process_name": percentage_of_total
        # Example:
        # "explorer.exe": 15.2,
        # "chrome.exe": 12.8,
        # TODO: Fill from your data
    }
    
    # Typical session characteristics
    AVG_SESSION_DURATION_MINUTES = None
    AVG_SHELLS_PER_SESSION = None
    AVG_UNIQUE_TOOLS_PER_SESSION = None
    
    # Time-of-day patterns
    BUSINESS_HOURS = {
        "start": 8,   # 8 AM
        "end": 18,    # 6 PM
    }
    
    # Day-of-week patterns
    BUSINESS_DAYS = [0, 1, 2, 3, 4]  # Monday=0, Sunday=6
    
    # Ransomware tool usage in normal environment
    VSSADMIN_NORMAL_EXECUTIONS_PER_DAY = None  # Should be VERY low (near zero)
    BCDEDIT_NORMAL_EXECUTIONS_PER_DAY = None   # Should be VERY low (near zero)


# ============================================================================
# VALIDATION DATASET - TEST YOUR DETECTION
# ============================================================================

VALIDATION_SAMPLES = {
    "ransomware_positive": {
        "description": "Known ransomware command lines for validation testing",
        "examples": [
            {
                "name": "Lockbit shadow copy deletion",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "expected_tags": ["ransomware_tool", "shadow_copy_deletion", "backup_manipulation"],
                "expected_confidence": "high",
                "source": "Lockbit 3.0 analysis"
            },
            {
                "name": "Ryuk boot manipulation",
                "command_line": "bcdedit /set {default} recoveryenabled no",
                "expected_tags": ["ransomware_tool", "boot_manipulation", "boot_configuration"],
                "expected_confidence": "high",
                "source": "Ryuk ransomware analysis"
            },
            {
                "name": "Conti backup deletion",
                "command_line": "wbadmin delete catalog -quiet",
                "expected_tags": ["ransomware_tool", "backup_deletion", "backup_manipulation"],
                "expected_confidence": "high",
                "source": "Conti ransomware analysis"
            },
            {
                "name": "REvil service stop",
                "command_line": "net stop vss & net stop sql",
                "expected_tags": ["system_utility", "service_manipulation"],
                "expected_confidence": "medium",
                "source": "REvil/Sodinokibi analysis"
            }
        ]
    },
    "benign_negative": {
        "description": "Known benign command lines that should NOT alert",
        "examples": [
            {
                "name": "Windows Update",
                "command_line": "wuauclt.exe /detectnow",
                "expected_tags": [],
                "expected_confidence": "low",
                "should_exclude": True
            },
            {
                "name": "Normal user PowerShell",
                "command_line": "powershell.exe Get-Process",
                "expected_tags": ["interactive_shell", "script_engine"],
                "expected_confidence": "low",
                "should_exclude": False
            }
        ]
    }
}


# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

def get_threshold(name: str) -> int:
    """Retrieve threshold value by name."""
    return getattr(ThresholdConfig, name, None)


def get_tag_description(tag: str) -> str:
    """Get human-readable description of a tag."""
    return TAG_DESCRIPTIONS.get(tag, "No description available")


def should_exclude(event_data: Dict) -> bool:
    """Check if event should be excluded from alerts."""
    return ExclusionRules.is_known_good_pattern(event_data)


def is_critical_indicator(tags: List[str]) -> bool:
    """Check if any tags are critical ransomware indicators."""
    critical_tags = {
        "shadow_copy_deletion",
        "boot_manipulation",
        "backup_deletion"
    }
    return any(tag in critical_tags for tag in tags)


def get_mitre_technique(tag: str) -> Optional[str]:
    """Get MITRE ATT&CK technique ID for a tag."""
    tag_info = BEHAVIOR_TAGS.get(tag)
    if tag_info:
        return tag_info.get("mitre_technique")
    return None

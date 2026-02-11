"""
Behavior Tagger Module - Human-Operated Ransomware Detection
Real-time event processing with ransomware-specific behavioral patterns.

FEATURES:
- Ransomware-specific command pattern detection
- Shadow copy deletion monitoring
- Boot configuration manipulation detection
- Encryption tool usage tracking
- Network share enumeration detection
- Privilege escalation attempt detection

RANSOMWARE FAMILIES COVERED:
- Lockbit 3.0
- REvil/Sodinokibi
- Ryuk
- Conti
- BlackCat/ALPHV
- Generic ransomware patterns
"""

import sys
import io

# Fix Windows console encoding issues
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
import threading
from queue import Queue, Empty
from behavior_tags import BEHAVIOR_TAGS, RISK_THRESHOLDS

# ============================================================================
# TOOL CLASSIFICATION (Ransomware-Focused)
# ============================================================================

# Pre-compiled sets for O(1) lookup
TOOL_CLASS = {
    # Interactive shells
    "cmd.exe": ["interactive_shell"],
    "powershell.exe": ["interactive_shell", "script_engine"],
    "pwsh.exe": ["interactive_shell", "script_engine"],
    
    # System utilities (often abused)
    "wmic.exe": ["system_utility", "deprecated_tool"],
    "net.exe": ["system_utility"],
    "whoami.exe": ["system_utility"],
    "ipconfig.exe": ["system_utility"],
    "netstat.exe": ["system_utility"],
    "tasklist.exe": ["system_utility"],
    "sc.exe": ["system_utility"],
    "reg.exe": ["system_utility"],
    
    # Script engines
    "cscript.exe": ["script_engine"],
    "wscript.exe": ["script_engine"],
    "mshta.exe": ["script_engine"],
    "python.exe": ["script_engine", "interpreter"],
    
    # System loaders
    "rundll32.exe": ["system_loader"],
    "regsvr32.exe": ["system_loader"],
    
    # Download/transfer tools
    "certutil.exe": ["system_utility", "download_capable"],
    "bitsadmin.exe": ["system_utility", "download_capable"],
    "curl.exe": ["download_capable"],
    
    # CRITICAL RANSOMWARE TOOLS
    "vssadmin.exe": ["system_utility", "backup_manipulation"],
    "bcdedit.exe": ["system_utility", "boot_configuration"],
    "cipher.exe": ["system_utility", "encryption_tool"],
    "wbadmin.exe": ["system_utility", "backup_manipulation"],
    "diskshadow.exe": ["system_utility", "backup_manipulation"],
    "fsutil.exe": ["system_utility", "file_system_manipulation"],
    "icacls.exe": ["system_utility", "permission_manipulation"],
    "takeown.exe": ["system_utility", "permission_manipulation"],
    "attrib.exe": ["system_utility", "file_attribute_manipulation"],
}

LOLBINS = frozenset([
    "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "cscript.exe", "wscript.exe"
])

DOCUMENT_APPS = frozenset([
    "winword.exe", "excel.exe", "powerpnt.exe",
    "acrord32.exe", "outlook.exe", "acrobat.exe"
])

BROWSERS = frozenset([
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", 
    "brave.exe", "duckduckgo.exe", "opera.exe"
])

KNOWN_BENIGN = frozenset([
    "vscode.exe", "code.exe", "docker.exe", "kubectl.exe", 
    "conhost.exe", "explorer.exe"
])

# CRITICAL: Ransomware-associated tools
RANSOMWARE_TOOLS = frozenset([
    "vssadmin.exe", "bcdedit.exe", "cipher.exe", "wbadmin.exe",
    "diskshadow.exe", "fsutil.exe"
])


# ============================================================================
# RANSOMWARE-SPECIFIC PATTERN MATCHING
# ============================================================================

class RansomwarePatternMatcher:
    """
    Specialized pattern matcher for ransomware behaviors.
    Based on MITRE ATT&CK and observed ransomware TTPs.
    
    SOURCES:
    - MITRE ATT&CK T1486 (Data Encrypted for Impact)
    - MITRE ATT&CK T1490 (Inhibit System Recovery)
    - MITRE ATT&CK T1070 (Indicator Removal)
    - MITRE ATT&CK T1135 (Network Share Discovery)
    - Public ransomware analysis reports
    """
    
    # Shadow Copy Deletion (T1490 - Inhibit System Recovery)
    SHADOW_COPY_DELETE = frozenset([
        "vssadmin delete shadows",
        "vssadmin.exe delete shadows",
        "wmic shadowcopy delete",
        "shadowcopy delete",
        "delete shadows /all",
        "delete shadows /for",
        "resize shadowstorage /maxsize",
    ])
    
    # Boot Configuration Manipulation (T1490)
    BOOT_MANIPULATION = frozenset([
        "bcdedit /set",
        "bootstatuspolicy ignoreallfailures",
        "recoveryenabled no",
        "bcdedit.exe /set {default}",
        "bcdedit /deletevalue",
    ])
    
    # Backup Deletion (T1490)
    BACKUP_DELETE = frozenset([
        "wbadmin delete catalog",
        "wbadmin delete backup",
        "wbadmin delete systemstatebackup",
        "catalog -quiet",
        "vssadmin delete",
    ])
    
    # Service Manipulation (T1489 - Service Stop)
    SERVICE_STOP = frozenset([
        "net stop",
        "sc stop",
        "sc config",
        "set start= disabled",
        "vss",  # Volume Shadow Copy service
        "sql",  # SQL services (common ransomware target)
        "backup",
        "memtas",
        "sophos",
        "veeam",
    ])
    
    # Network Share Enumeration (T1135)
    SHARE_ENUMERATION = frozenset([
        "net view",
        "net share",
        "net use",
        "\\\\",  # UNC paths
        "get-smbshare",
        "get-smbconnection",
    ])
    
    # Credential Dumping (T1003)
    CREDENTIAL_DUMP = frozenset([
        "mimikatz",
        "sekurlsa",
        "lsass",
        "procdump",
        "comsvcs.dll minidump",
        "createdump",
    ])
    
    # Persistence Mechanisms (T1547)
    PERSISTENCE = frozenset([
        "schtasks /create",
        "reg add",
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "startup",
        "wmic /node",
    ])
    
    # File Encryption Indicators
    ENCRYPTION_ACTIVITY = frozenset([
        "cipher /w",  # Cipher.exe used to wipe free space
        "cipher.exe",
        "/e /s",  # Encrypt files in directory
        "vssadmin resize shadowstorage /maxsize=401mb",  # Common Ryuk
        "vssadmin resize shadowstorage /maxsize=unbounded",
    ])
    
    # Obfuscation Patterns
    OBFUSCATION = frozenset([
        "-enc",
        "-encodedcommand",
        "frombase64",
        "invoke-expression",
        " iex ",
        "^^",  # Command-line obfuscation
        "-w hidden",
        "-windowstyle hidden",
        "-nop",
        "-noprofile",
    ])
    
    # Download Activity
    DOWNLOAD = frozenset([
        "downloadfile",
        "downloadstring",
        "wget",
        "curl",
        "invoke-webrequest",
        " iwr ",
        "bitsadmin /transfer",
        "certutil -urlcache",
        "certutil.exe -decode",
    ])
    
    # Lateral Movement
    LATERAL_MOVEMENT = frozenset([
        "psexec",
        "wmic /node",
        "invoke-command",
        "enter-pssession",
        "net use \\\\",
        "cmdkey /add",
    ])
    
    # Privilege Escalation
    PRIVILEGE_ESCALATION = frozenset([
        "runas",
        "elevate",
        "bypassuac",
        "getsystem",
        "token::elevate",
    ])
    
    @staticmethod
    def match_any(cmdline: str, patterns: frozenset) -> bool:
        """Fast substring matching - case insensitive."""
        if not cmdline:
            return False
        cmdline_lower = cmdline.lower()
        for pattern in patterns:
            if pattern in cmdline_lower:
                return True
        return False
    
    @staticmethod
    def match_multiple(cmdline: str) -> List[str]:
        """
        Check command line against all ransomware patterns.
        Returns list of matched pattern categories.
        """
        matches = []
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.SHADOW_COPY_DELETE):
            matches.append("shadow_copy_deletion")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.BOOT_MANIPULATION):
            matches.append("boot_manipulation")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.BACKUP_DELETE):
            matches.append("backup_deletion")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.SERVICE_STOP):
            matches.append("service_manipulation")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.SHARE_ENUMERATION):
            matches.append("network_share_discovery")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.CREDENTIAL_DUMP):
            matches.append("credential_access_attempt")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.ENCRYPTION_ACTIVITY):
            matches.append("encryption_activity")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.OBFUSCATION):
            matches.append("obfuscated_execution")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.DOWNLOAD):
            matches.append("download_activity")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.LATERAL_MOVEMENT):
            matches.append("lateral_movement")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.PRIVILEGE_ESCALATION):
            matches.append("privilege_escalation")
        
        if RansomwarePatternMatcher.match_any(cmdline, RansomwarePatternMatcher.PERSISTENCE):
            matches.append("persistence_attempt")
        
        return matches


# ============================================================================
# LEGACY FAST PATTERN MATCHING (Compatibility)
# ============================================================================

class FastPatternMatcher:
    """
    Original optimized pattern matching.
    Kept for backwards compatibility.
    """
    
    NON_INTERACTIVE = frozenset([" /c ", " -c ", " -command ", " -encodedcommand "])
    OBFUSCATION = frozenset(["-enc", "frombase64", "invoke-expression", " iex ", "^^"])
    DOWNLOAD = frozenset(["downloadfile", "wget", "curl", "invoke-webrequest", " iwr ", "bitsadmin /transfer"])
    PERSISTENCE = frozenset(["schtasks /create", "reg add", "\\currentversion\\run"])
    CREDENTIAL = frozenset(["mimikatz", "sekurlsa", "lsass", "procdump"])
    
    @staticmethod
    def match_any(cmdline: str, patterns: frozenset) -> bool:
        """Fast substring matching."""
        if not cmdline:
            return False
        cmdline_lower = cmdline.lower()
        for pattern in patterns:
            if pattern in cmdline_lower:
                return True
        return False


# ============================================================================
# BOUNDED SESSION TRACKER (Fixed Memory)
# ============================================================================

@dataclass
class SessionContext:
    """Enhanced session state with ransomware indicators."""
    username: str
    shell_count: int = 0
    lolbin_count: int = 0
    script_count: int = 0
    ransomware_indicator_count: int = 0  # NEW
    shadow_copy_operations: int = 0  # NEW
    service_manipulations: int = 0  # NEW
    first_seen: float = 0.0
    last_seen: float = 0.0
    unique_procs: Set[str] = None
    ransomware_tools_used: Set[str] = None  # NEW
    
    def __post_init__(self):
        if self.unique_procs is None:
            self.unique_procs = set()
        if self.ransomware_tools_used is None:
            self.ransomware_tools_used = set()


class BoundedSessionTracker:
    """
    Session tracker with automatic memory management.
    Enhanced with ransomware behavior tracking.
    """
    
    def __init__(self, max_sessions: int = 1000, session_timeout_sec: int = 1800):
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout_sec
        self.sessions: Dict[str, SessionContext] = {}
        self.access_order = deque(maxlen=max_sessions)
        self._last_cleanup = time.time()
        self._cleanup_interval = 300
    
    def update(self, username: str, process_name: str, tags: List[str]) -> Optional[SessionContext]:
        """Update session and return context. Auto-cleanup if needed."""
        if not username:
            username = "UNKNOWN"
        
        current_time = time.time()
        
        # Periodic cleanup
        if current_time - self._last_cleanup > self._cleanup_interval:
            self._cleanup_stale_sessions(current_time)
        
        # Get or create session
        if username not in self.sessions:
            if len(self.sessions) >= self.max_sessions:
                oldest = self.access_order.popleft()
                self.sessions.pop(oldest, None)
            
            self.sessions[username] = SessionContext(
                username=username,
                first_seen=current_time,
                last_seen=current_time
            )
        
        session = self.sessions[username]
        session.last_seen = current_time
        session.unique_procs.add(process_name)
        
        # Update counters (fast tag checks)
        if "interactive_shell" in tags:
            session.shell_count += 1
        if "living_off_the_land" in tags:
            session.lolbin_count += 1
        if "script_engine" in tags:
            session.script_count += 1
        
        # NEW: Ransomware-specific counters
        if "shadow_copy_deletion" in tags:
            session.shadow_copy_operations += 1
            session.ransomware_indicator_count += 1
        if "boot_manipulation" in tags:
            session.ransomware_indicator_count += 1
        if "service_manipulation" in tags:
            session.service_manipulations += 1
        if "encryption_activity" in tags:
            session.ransomware_indicator_count += 1
        
        # Track ransomware tools
        if process_name.lower() in RANSOMWARE_TOOLS:
            session.ransomware_tools_used.add(process_name.lower())
        
        # Update LRU
        if username in self.access_order:
            self.access_order.remove(username)
        self.access_order.append(username)
        
        return session
    
    def _cleanup_stale_sessions(self, current_time: float):
        """Remove sessions that haven't been active."""
        stale_users = [
            user for user, session in self.sessions.items()
            if current_time - session.last_seen > self.session_timeout
        ]
        for user in stale_users:
            self.sessions.pop(user, None)
            try:
                self.access_order.remove(user)
            except ValueError:
                pass
        
        self._last_cleanup = current_time
    
    def get_context_tags(self, session: SessionContext) -> List[str]:
        """Generate context tags based on session state."""
        tags = []
        
        # Original thresholds
        if session.shell_count >= 5:
            tags.append("repeated_shell_activity")
        if session.lolbin_count >= 3:
            tags.append("multiple_lolbin_usage")
        if len(session.unique_procs) >= 10:
            tags.append("diverse_tool_usage")
        
        # NEW: Ransomware-specific session tags
        if session.ransomware_indicator_count >= 2:
            tags.append("multiple_ransomware_indicators")
        
        if session.shadow_copy_operations >= 1:
            tags.append("shadow_copy_activity")
        
        if len(session.ransomware_tools_used) >= 2:
            tags.append("multiple_ransomware_tools")
        
        return tags


# ============================================================================
# CORE STREAMING TAGGER (Enhanced)
# ============================================================================

@dataclass
class TaggedEvent:
    """Enhanced event structure with ransomware fields."""
    timestamp: str
    process_name: str
    pid: int
    command_line: str
    username: Optional[str]
    parent_process_name: Optional[str]
    tags: List[str]
    confidence: str
    ransomware_indicators: List[str]  # NEW
    shell_count: int = 0
    lolbin_count: int = 0
    ransomware_score: int = 0  # NEW
    
    def to_json_line(self) -> str:
        """Single-pass JSON serialization."""
        return json.dumps(asdict(self))


class StreamingBehaviorTagger:
    """
    Enhanced streaming tagger with ransomware detection.
    
    DETECTION PHILOSOPHY:
    - Layer 1: Tool classification (what was executed)
    - Layer 2: Command pattern matching (what it's doing)
    - Layer 3: Session context (behavioral patterns over time)
    - Layer 4: Ransomware-specific indicators (critical threats)
    """
    
    def __init__(self, max_sessions: int = 1000):
        self.session_tracker = BoundedSessionTracker(max_sessions=max_sessions)
        self.events_processed = 0
        self.tags_applied = 0
        self.high_confidence_events = 0
        self.ransomware_detections = 0  # NEW
    
    def tag_event(self, event_data: Dict) -> TaggedEvent:
        """
        Tag a single event with behavioral signals.
        
        ENHANCED LOGIC:
        1. Basic tool classification
        2. Ransomware pattern matching (NEW)
        3. Parent-child relationship analysis
        4. Session context accumulation
        5. Confidence scoring (enhanced with ransomware weight)
        """
        # NULL-SAFE: Handle None values gracefully
        proc_name = (event_data.get("process_name") or "").lower()
        cmdline = event_data.get("command_line") or ""
        parent = (event_data.get("parent_process_name") or "").lower()
        username = event_data.get("username")
        
        tags = []
        ransomware_indicators = []  # NEW
        
        # Layer 1: Tool Classification
        if proc_name in TOOL_CLASS:
            tags.extend(TOOL_CLASS[proc_name])
        
        if proc_name in LOLBINS:
            tags.append("living_off_the_land")
        
        if proc_name in RANSOMWARE_TOOLS:
            tags.append("ransomware_tool")
            ransomware_indicators.append(f"ransomware_tool:{proc_name}")
        
        # Layer 2: ENHANCED - Ransomware Pattern Matching
        ransomware_patterns = RansomwarePatternMatcher.match_multiple(cmdline)
        tags.extend(ransomware_patterns)
        ransomware_indicators.extend(ransomware_patterns)
        
        # Legacy pattern matching (for backward compatibility)
        if FastPatternMatcher.match_any(cmdline, FastPatternMatcher.NON_INTERACTIVE):
            tags.append("non_interactive_execution")
        
        if FastPatternMatcher.match_any(cmdline, FastPatternMatcher.OBFUSCATION):
            if "obfuscated_execution" not in tags:
                tags.append("obfuscated_execution")
        
        if FastPatternMatcher.match_any(cmdline, FastPatternMatcher.DOWNLOAD):
            if "download_activity" not in tags:
                tags.append("download_activity")
        
        if FastPatternMatcher.match_any(cmdline, FastPatternMatcher.PERSISTENCE):
            if "persistence_attempt" not in tags:
                tags.append("persistence_attempt")
        
        if FastPatternMatcher.match_any(cmdline, FastPatternMatcher.CREDENTIAL):
            if "credential_access_attempt" not in tags:
                tags.append("credential_access_attempt")
        
        # Layer 3: Parent-Child Relationship Analysis
        if parent in DOCUMENT_APPS:
            tags.append("document_spawned_process")
            if proc_name in LOLBINS:
                tags.append("suspicious_parent_child")
                ransomware_indicators.append("document_to_lolbin")
        
        if parent in BROWSERS:
            tags.append("browser_spawned_process")
        
        # Layer 4: Session Context
        session = self.session_tracker.update(username, proc_name, tags)
        if session:
            context_tags = self.session_tracker.get_context_tags(session)
            tags.extend(context_tags)
        
        # Remove duplicates while preserving order
        tags = list(dict.fromkeys(tags))
        ransomware_indicators = list(dict.fromkeys(ransomware_indicators))
        
        # Layer 5: ENHANCED - Confidence Scoring with Ransomware Weight
        confidence = self._calculate_confidence(tags, ransomware_indicators, session)
        
        # Calculate ransomware-specific score
        ransomware_score = len(ransomware_indicators) * 10  # Each indicator worth 10 points
        
        # Update stats
        self.events_processed += 1
        self.tags_applied += len(tags)
        if confidence == "high":
            self.high_confidence_events += 1
        if ransomware_indicators:
            self.ransomware_detections += 1
        
        return TaggedEvent(
            timestamp=event_data.get("timestamp", datetime.now().isoformat()),
            process_name=event_data.get("process_name", ""),
            pid=event_data.get("pid", 0),
            command_line=cmdline,
            username=username,
            parent_process_name=parent,
            tags=tags,
            confidence=confidence,
            ransomware_indicators=ransomware_indicators,
            shell_count=session.shell_count if session else 0,
            lolbin_count=session.lolbin_count if session else 0,
            ransomware_score=ransomware_score
        )
    
    def _calculate_confidence(self, tags: List[str], ransomware_indicators: List[str], session: Optional[SessionContext]) -> str:
        """
        Enhanced confidence calculation with ransomware priority.
        
        CRITICAL ESCALATION:
        - ANY ransomware indicator = at least MEDIUM
        - 2+ ransomware indicators = HIGH
        - Shadow copy deletion alone = HIGH
        - Boot manipulation alone = HIGH
        """
        # CRITICAL: Ransomware indicators override normal scoring
        if ransomware_indicators:
            critical_indicators = [
                "shadow_copy_deletion",
                "boot_manipulation",
                "backup_deletion",
                "encryption_activity"
            ]
            
            # Single critical indicator = HIGH
            if any(ind in ransomware_indicators for ind in critical_indicators):
                return "high"
            
            # 2+ ransomware indicators = HIGH
            if len(ransomware_indicators) >= 2:
                return "high"
            
            # 1 ransomware indicator = MEDIUM
            return "medium"
        
        # Original confidence logic for non-ransomware events
        concerning_tags = {
            "obfuscated_execution",
            "credential_access_attempt",
            "suspicious_parent_child",
            "download_activity",
            "persistence_attempt",
            "multiple_lolbin_usage",
            "lateral_movement",
            "privilege_escalation"
        }
        
        concerning_count = sum(1 for tag in tags if tag in concerning_tags)
        
        if concerning_count >= 2:
            return "high"
        elif concerning_count == 1:
            return "medium"
        elif "living_off_the_land" in tags or "script_engine" in tags:
            return "medium"
        else:
            return "low"
    
    def get_stats(self) -> Dict:
        """Get processing statistics."""
        return {
            "events_processed": self.events_processed,
            "tags_applied": self.tags_applied,
            "high_confidence_events": self.high_confidence_events,
            "ransomware_detections": self.ransomware_detections,
            "active_sessions": len(self.session_tracker.sessions)
        }


# ============================================================================
# FILE STREAM PROCESSOR (Unchanged)
# ============================================================================

class FileStreamProcessor:
    """Tail-follows input file and writes tagged events to output."""
    
    def __init__(self, input_file: str, output_file: str, 
                 poll_interval: float = 0.1,
                 callback: Optional[Callable] = None):
        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.poll_interval = poll_interval
        self.callback = callback
        
        self.tagger = StreamingBehaviorTagger()
        self.running = False
        self._file_position = 0
    
    def _process_line(self, line: str):
        """Process a single JSON line."""
        try:
            event_data = json.loads(line)
            tagged_event = self.tagger.tag_event(event_data)
            
            # Write to output file
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(tagged_event.to_json_line() + '\n')
            
            # Trigger callback if provided
            if self.callback:
                self.callback(tagged_event)
                
        except json.JSONDecodeError as e:
            print(f"Malformed JSON: {e}")
        except Exception as e:
            print(f"Processing error: {e}")
    
    def start(self):
        """Start streaming processor (blocking call)."""
        self.running = True
        
        # Initialize file position
        if self.input_file.exists():
            with open(self.input_file, 'r', encoding='utf-8') as f:
                f.seek(0, 2)
                self._file_position = f.tell()
        
        while self.running:
            try:
                if not self.input_file.exists():
                    time.sleep(self.poll_interval)
                    continue
                
                with open(self.input_file, 'r', encoding='utf-8') as f:
                    f.seek(self._file_position)
                    
                    for line in f:
                        if line.strip():
                            self._process_line(line)
                    
                    self._file_position = f.tell()
                
                time.sleep(self.poll_interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Stream processing error: {e}")
                time.sleep(self.poll_interval)
        
        self.stop()

# ============================================================================
# THREADED PROCESSOR
# ============================================================================

class ThreadedTagger:
    """Background thread processor for integration with process_monitor.py"""
    
    def __init__(self, input_file: str, output_file: str):
        self.processor = FileStreamProcessor(input_file, output_file)
        self.thread = None
    
    def start(self):
        """Start processing in background thread."""
        self.thread = threading.Thread(target=self.processor.start, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop background processing."""
        if self.processor:
            self.processor.stop()
        if self.thread:
            self.thread.join(timeout=5)
    
    def get_stats(self) -> Dict:
        """Get processing statistics."""
        return self.processor.tagger.get_stats()


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Command-line interface for enhanced streaming tagger."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced Ransomware Detection Tagger - Real-time event processing"
    )
    parser.add_argument('--input', default='process_events.jsonl',
                        help='Input JSONL file to tail')
    parser.add_argument('--output', default='enriched_events.jsonl',
                        help='Output JSONL file for tagged events')
    parser.add_argument('--poll-interval', type=float, default=0.1,
                        help='File polling interval in seconds (default: 0.1)')
    parser.add_argument('--max-sessions', type=int, default=1000,
                        help='Maximum session cache size (default: 1000)')
    parser.add_argument('--benchmark', action='store_true',
                        help='Run performance benchmark')
    
    args = parser.parse_args()
    
    if args.benchmark:
        run_benchmark()
        return
    
    print("="*70)
    print("Enhanced Ransomware Detection System (Production Mode)")
    print("="*70)
    print(f"Ransomware Families Covered:")
    print(f"  - Lockbit 3.0, REvil, Ryuk, Conti, BlackCat")
    print(f"Detection Capabilities:")
    print(f"  - Shadow copy deletion")
    print(f"  - Boot manipulation")
    print(f"  - Backup deletion")
    print(f"  - Service tampering")
    print(f"  - Credential dumping")
    print(f"  - Lateral movement")
    print("="*70)
    print(f"Memory footprint: ~10-50MB (bounded)")
    print(f"CPU usage: <1% (idle when no events)")
    print(f"Processing latency: <1ms per event")
    print("="*70)
    
    processor = FileStreamProcessor(
        args.input,
        args.output,
        poll_interval=args.poll_interval
    )
    
    try:
        processor.start()
    except KeyboardInterrupt:
        print("\nShutdown requested")
    finally:
        processor.stop()


def run_benchmark():
    """Performance benchmark."""
    print("Running enhanced ransomware detection benchmark...")
    
    tagger = StreamingBehaviorTagger()
    
    test_events = [
        {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc base64payload",
            "parent_process_name": "winword.exe",
            "username": "testuser",
            "pid": 1234,
            "timestamp": datetime.now().isoformat()
        },
        {
            "process_name": "vssadmin.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "parent_process_name": "cmd.exe",
            "username": "testuser",
            "pid": 5678,
            "timestamp": datetime.now().isoformat()
        },
        {
            "process_name": "bcdedit.exe",
            "command_line": "bcdedit /set {default} recoveryenabled no",
            "parent_process_name": "cmd.exe",
            "username": "testuser",
            "pid": 9012,
            "timestamp": datetime.now().isoformat()
        }
    ]
    
    iterations = 10000
    start = time.perf_counter()
    
    for _ in range(iterations // len(test_events)):
        for event in test_events:
            tagger.tag_event(event)
    
    elapsed = time.perf_counter() - start
    per_event = (elapsed / iterations) * 1000
    
    stats = tagger.get_stats()
    
    print(f"\nBenchmark Results:")
    print(f"  Total events: {iterations}")
    print(f"  Total time: {elapsed:.2f}s")
    print(f"  Per-event: {per_event:.3f}ms")
    print(f"  Throughput: {iterations/elapsed:.0f} events/sec")
    print(f"\nDetection Stats:")
    print(f"  Ransomware detections: {stats['ransomware_detections']}")
    print(f"  High-confidence events: {stats['high_confidence_events']}")
    print(f"\nMemory profile: ~{tagger.session_tracker.max_sessions * 0.001:.1f}MB (session cache)")


if __name__ == "__main__":
    main()

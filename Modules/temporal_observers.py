"""
Module 3: Temporal Behavior Observers
Real-time detection of behaviors that emerge over time.

DESIGN PHILOSOPHY:
- Observe behaviors that don't exist at process creation
- No kernel drivers, no network IDS fantasy
- User-mode only, realistic Windows APIs
- Host-observable signals only
- Time-windowed pattern detection

WHAT THIS DETECTS:
1. Privilege Escalation (medium → high integrity)
2. Lateral Movement (psexec, wmic, winrm usage)
3. Mass File I/O (pre-encryption behavior)
4. Mass File Modification (rename/delete patterns)
5. Ransom Note Drop (content scan on new .txt/.html files)

WHAT THIS DOESN'T DO:
- Network packet inspection (not our domain)
- Kernel-level hooks (unrealistic for production)
- Memory scanning (different tool)
- Perfect detection (we detect SIGNALS)

OUTPUT:
Behavior events that feed into Module 4 (Campaign Correlator)
"""

import os
import json
import time
import logging
import ctypes
import win32security
import win32api
import win32con
import win32file
import pywintypes
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from threading import Thread, Event
import psutil

# Define FILE_LIST_DIRECTORY constant (missing in some pywin32 versions)
FILE_LIST_DIRECTORY = 0x0001

# ============================================================================
# BEHAVIOR EVENT STRUCTURE
# ============================================================================

@dataclass
class BehaviorEvent:
    """
    Temporal behavior event - things observed over time.
    
    These events flow into Module 4 (Campaign Correlator) just like
    process events from Module 2.
    """
    timestamp: str
    source: str  # Which observer detected this
    behavior: str  # What was observed
    confidence: str  # low, medium, high
    score: int  # Numeric severity (0-100)
    evidence: List[str]  # Supporting facts
    metadata: Dict  # Context-specific data
    username: Optional[str] = None
    process_name: Optional[str] = None
    
    def to_json_line(self) -> str:
        """Serialize to JSONL."""
        return json.dumps(asdict(self))


# ============================================================================
# OBSERVER 1: PRIVILEGE ESCALATION TRACKER
# ============================================================================

class PrivilegeEscalationObserver:
    """
    Detects privilege escalation attempts.
    
    REALISTIC SIGNALS (User-mode observable):
    - Process started as medium → spawns high integrity child
    - Sudden SYSTEM-level process from user context
    - Use of escalation tools (schtasks, sc create, runas)
    - Token manipulation indicators
    
    NO FANTASY:
    - No kernel hooks
    - No memory scanning
    - Just Windows integrity level checks + process parent tracking
    """

    # Legitimate Windows processes that are allowed to parent SYSTEM-level children.
    # Built once at class definition — not recreated on every observe_process() call.
    KNOWN_SYSTEM_PARENTS = frozenset([
        "services.exe", "svchost.exe", "lsass.exe",
        "wininit.exe", "winlogon.exe", "smss.exe", "csrss.exe",
        "searchindexer.exe",    # spawns searchprotocolhost.exe, searchfilterhost.exe
        "msiexec.exe",          # installer spawns SYSTEM processes during setup
        "trustedinstaller.exe", # Windows Update
        "tiworker.exe",         # Windows Update worker
        "wmiprvse.exe",         # WMI provider host
        "spoolsv.exe",          # Print spooler
        "taskhost.exe",         # Scheduled task host
        "taskhostw.exe",
        "dllhost.exe",
        "wuauclt.exe",          # Windows Update client
        "audiodg.exe",
        "fontdrvhost.exe",
        "",                     # parent_name can be empty string for kernel processes
    ])
    
    def __init__(self):
        self.logger = logging.getLogger("PrivEscObserver")
        self.process_integrity_map: Dict[int, str] = {}  # PID → integrity level
        self.escalation_attempts: deque = deque(maxlen=1000)
        
        # Tools commonly used for privilege escalation
        self.escalation_tools = frozenset([
            "schtasks.exe",  # Create scheduled task as SYSTEM
            "sc.exe",        # Create service
            "runas.exe",     # Run as different user
            "psexec.exe",    # Remote execution (often local too)
            "at.exe",        # Legacy task scheduler
        ])
        
        # Commands that indicate privilege attempts
        self.escalation_commands = frozenset([
            "schtasks /create",
            "sc create",
            "runas /user:",
            "net localgroup administrators",
            "/savecred",  # runas with saved credentials
        ])
    
    def get_process_integrity_level(self, pid: int) -> Optional[str]:
        """
        Get process integrity level (Low, Medium, High, System).
        
        This is user-mode accessible via process handle.
        """
        try:
            # Open process handle
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            # Get process token
            token = win32security.OpenProcessToken(
                handle,
                win32security.TOKEN_QUERY
            )
            
            # Get integrity level SID
            integrity_sid = win32security.GetTokenInformation(
                token,
                win32security.TokenIntegrityLevel
            )
            
            # Map SID to integrity level name
            sid_string = win32security.ConvertSidToStringSid(integrity_sid[0])
            
            # Standard Windows integrity levels
            if "S-1-16-16384" in sid_string:  # SECURITY_MANDATORY_SYSTEM_RID
                return "SYSTEM"
            elif "S-1-16-12288" in sid_string:  # SECURITY_MANDATORY_HIGH_RID
                return "HIGH"
            elif "S-1-16-8192" in sid_string:  # SECURITY_MANDATORY_MEDIUM_RID
                return "MEDIUM"
            elif "S-1-16-4096" in sid_string:  # SECURITY_MANDATORY_LOW_RID
                return "LOW"
            else:
                return "UNKNOWN"
                
        except Exception as e:
            self.logger.debug(f"Failed to get integrity level for PID {pid}: {e}")
            return None
    
    def observe_process(self, process_event: Dict) -> Optional[BehaviorEvent]:
        """
        Observe a process creation event for privilege escalation.
        
        Args:
            process_event: Process creation event from Module 1
            
        Returns:
            BehaviorEvent if escalation detected, None otherwise
        """
        proc_name = process_event.get("process_name", "").lower()
        pid = process_event.get("pid")
        parent_pid = process_event.get("parent_pid")
        cmdline = process_event.get("command_line", "").lower()
        username = process_event.get("username")
        
        if not pid:
            return None
        
        # Get current process integrity
        current_integrity = self.get_process_integrity_level(pid)
        if not current_integrity:
            return None
        
        # Track this process
        self.process_integrity_map[pid] = current_integrity
        
        # Check for escalation signals
        evidence = []
        score = 0
        
        # Signal 1: Parent was medium, child is high/system
        if parent_pid and parent_pid in self.process_integrity_map:
            parent_integrity = self.process_integrity_map[parent_pid]
            
            if parent_integrity == "MEDIUM" and current_integrity in ["HIGH", "SYSTEM"]:
                evidence.append(f"Integrity escalation: {parent_integrity} → {current_integrity}")
                score += 50
            
            if parent_integrity in ["LOW", "MEDIUM"] and current_integrity == "SYSTEM":
                evidence.append(f"User process spawned SYSTEM process")
                score += 70
        
        # Signal 2: Escalation tool usage
        if proc_name in self.escalation_tools:
            evidence.append(f"Escalation tool: {proc_name}")
            score += 30
        
        # Signal 3: Escalation command patterns
        if any(pattern in cmdline for pattern in self.escalation_commands):
            evidence.append(f"Escalation command detected")
            score += 40
        
        # Signal 4: SYSTEM process from non-system parent
        # BUG 5 FIX: see KNOWN_SYSTEM_PARENTS class constant above.
        if current_integrity == "SYSTEM" and parent_pid:
            parent_name = process_event.get("parent_process_name", "").lower()
            if parent_name not in self.KNOWN_SYSTEM_PARENTS:
                evidence.append(f"SYSTEM process from unusual parent: {parent_name}")
                score += 60
        
        # Generate event if we have evidence
        if evidence:
            confidence = "low"
            if score >= 50:
                confidence = "medium"
            if score >= 80:
                confidence = "high"
            
            return BehaviorEvent(
                timestamp=datetime.now().isoformat(),
                source="privilege_escalation_observer",
                behavior="privilege_escalation_attempt",
                confidence=confidence,
                score=min(score, 100),
                evidence=evidence,
                metadata={
                    "current_integrity": current_integrity,
                    "parent_integrity": self.process_integrity_map.get(parent_pid),
                    "tool_used": proc_name if proc_name in self.escalation_tools else None
                },
                username=username,
                process_name=proc_name
            )
        
        return None


# ============================================================================
# OBSERVER 2: LATERAL MOVEMENT DETECTOR (Host-Side Only)
# ============================================================================

class LateralMovementObserver:
    """
    Detects lateral movement attempts - HOST OBSERVABLE ONLY.
    
    NO NETWORK IDS FANTASY:
    - We don't inspect packets
    - We don't monitor SMB traffic
    - We don't analyze Kerberos tickets
    
    WHAT WE DO DETECT:
    - psexec.exe usage (local or remote)
    - wmic /node: usage (remote WMI)
    - winrm / powershell remoting
    - schtasks /S (remote scheduled tasks)
    - Remote service creation
    - Repeated remote access attempts
    
    This fits the threat model: ransomware spreading across network.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("LateralMovObserver")
        
        # Track remote execution attempts per user
        self.remote_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.remote_targets: Dict[str, Set[str]] = defaultdict(set)
        
        # Lateral movement tools
        self.lateral_tools = frozenset([
            "psexec.exe",
            "psexec64.exe",
            "wmic.exe",
            "winrs.exe",
            "powershell.exe",
            "pwsh.exe",
        ])
        
        # Lateral movement command patterns
        self.lateral_patterns = frozenset([
            "/node:",          # wmic /node:target
            "\\\\",            # UNC path (\\server\share)
            "/s ",             # schtasks /S target
            "invoke-command",  # PowerShell remoting
            "enter-pssession", # PowerShell remoting
            "-computername",   # PowerShell remote parameter
            "new-pssession",   # PowerShell session
        ])
    
    def observe_process(self, process_event: Dict) -> Optional[BehaviorEvent]:
        """
        Observe process for lateral movement indicators.
        
        Args:
            process_event: Process creation event
            
        Returns:
            BehaviorEvent if lateral movement detected
        """
        proc_name = process_event.get("process_name", "").lower()
        cmdline = process_event.get("command_line", "").lower()
        username = process_event.get("username", "UNKNOWN")
        
        evidence = []
        score = 0
        
        # Signal 1: Lateral movement tool
        if proc_name in self.lateral_tools:
            evidence.append(f"Lateral movement tool: {proc_name}")
            score += 20
        
        # Signal 2: Remote execution patterns
        remote_targets = []
        for pattern in self.lateral_patterns:
            if pattern in cmdline:
                evidence.append(f"Remote execution pattern: {pattern}")
                score += 30
                
                # Try to extract target hostname
                if "/node:" in cmdline:
                    try:
                        target = cmdline.split("/node:")[1].split()[0]
                        remote_targets.append(target)
                    except:
                        pass
                elif "\\\\" in cmdline:
                    try:
                        target = cmdline.split("\\\\")[1].split("\\")[0]
                        remote_targets.append(target)
                    except:
                        pass
        
        # Signal 3: Track remote attempts per user
        if remote_targets:
            for target in remote_targets:
                self.remote_targets[username].add(target)
            
            self.remote_attempts[username].append({
                "timestamp": time.time(),
                "target": remote_targets[0] if remote_targets else "unknown",
                "tool": proc_name
            })
            
            # Multiple targets = higher score
            unique_targets = len(self.remote_targets[username])
            if unique_targets >= 3:
                evidence.append(f"Multiple remote targets: {unique_targets}")
                score += 40
            
            # Rapid attempts = higher score
            recent_attempts = [
                a for a in self.remote_attempts[username]
                if time.time() - a["timestamp"] < 300  # Last 5 minutes
            ]
            if len(recent_attempts) >= 3:
                evidence.append(f"Rapid remote attempts: {len(recent_attempts)} in 5 min")
                score += 30
        
        # Generate event only if we have REMOTE EVIDENCE, not just tool presence.
        # BUG 4 FIX: Previously, having powershell.exe in lateral_tools (score=20)
        # was sufficient to emit a lateral_movement_attempt with confidence=low.
        # This produced a false positive for every interactive PowerShell session.
        # Rule: tool presence alone is NOT sufficient — we require at least one
        # remote execution pattern in the command line before emitting any event.
        has_remote_pattern = any(
            pattern in cmdline for pattern in self.lateral_patterns
        )

        if not has_remote_pattern:
            return None  # Tool present but no remote execution evidence — ignore

        if evidence:
            confidence = "low"
            if score >= 40:
                confidence = "medium"
            if score >= 70:
                confidence = "high"

            return BehaviorEvent(
                timestamp=datetime.now().isoformat(),
                source="lateral_movement_observer",
                behavior="lateral_movement_attempt",
                confidence=confidence,
                score=min(score, 100),
                evidence=evidence,
                metadata={
                    "tool": proc_name,
                    "targets": list(self.remote_targets[username])[-5:],
                    "attempt_count": len(self.remote_attempts[username]),
                    "unique_targets": len(self.remote_targets[username])
                },
                username=username,
                process_name=proc_name
            )

        return None


# ============================================================================
# OBSERVER 3: FILE I/O MONITOR (Pre-Encryption Detection) - FIXED
# ============================================================================

class FileIOObserver:
    """
    Detects mass file I/O patterns indicative of ransomware.
    
    FIXED: Corrected win32file constant names
    
    CRITICAL: This detects ENCRYPTION PREPARATION, not perfect encryption.
    
    NO KERNEL DRIVERS NEEDED:
    - Uses ReadDirectoryChangesW (user-mode API)
    - Tracks file access counts + write volumes
    - Time-windowed pattern detection
    
    WHAT WE DETECT:
    - Sustained high file I/O
    - Many distinct files accessed in short time
    - High write volume
    - Uniform file extension changes
    
    REALISTIC CONSTRAINTS:
    - Can't monitor ALL drives (performance)
    - Monitor user directories only (C:/Users/, D:/Data/)
    - Time-boxed windows (detect BURSTS not steady state)
    """
    
    def __init__(self, watch_paths: List[str] = None):
        self.logger = logging.getLogger("FileIOObserver")
        
        # BUG 1 FIX: Was hardcoded to C:\Users\DELL — silently produced an empty
        # watch_paths list on any other machine, so FileIOObserver never started.
        # Now resolves dynamically from %USERPROFILE% at runtime.
        if watch_paths is None:
            user_profile = os.environ.get("USERPROFILE", "")
            candidates = [
                os.path.join(user_profile, "Documents"),
                os.path.join(user_profile, "Downloads"),
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "OneDrive", "Documents"),
                os.path.join(user_profile, "OneDrive", "Desktop"),
                r"C:\temp",        # catches manual test paths
                r"C:\Users",       # broad fallback: subtree covers all user folders
            ]
            watch_paths = [c for c in candidates if c and Path(c).exists()]

        self.watch_paths = [Path(p) for p in watch_paths if Path(p).exists()]
        
        # Tracking windows (5-minute buckets)
        self.window_duration = 300  # 5 minutes in seconds
        self.file_events: deque = deque(maxlen=10000)

        # BUG 3 FIX: Per-user deque was maxlen=1000. A ransomware simulation
        # creating 500 files + 500 renames = 1000 events fills the deque exactly,
        # then any additional file reads evict the earliest events. If analyze_patterns()
        # runs after eviction, counts drop below threshold and no alert fires.
        # Raised to 5000 to safely cover realistic burst scenarios.
        self.user_file_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))

        # Thresholds — lowered to be realistic for manual testing
        # BUG 4 FIX: HIGH_IO_THRESHOLD=100 was never reached in the 5-min window
        # during testing because analyze_patterns() only ran once per 60s interval
        # (Bug 2) AND the deque evicted events (Bug 3). With those fixed, 100 is
        # still appropriate. However MASS_MODIFY_THRESHOLD=50 is too high for the
        # rename detection — ransomware typically renames every file once.
        # Rename threshold in analyze_patterns is already 20, which is correct.
        self.HIGH_IO_THRESHOLD = 100    # file events in window
        self.MASS_MODIFY_THRESHOLD = 50  # write events in window
        
        self.running = False
        self.monitor_threads: List[Thread] = []
        self.ransom_note_scanner: Optional['RansomNoteScanner'] = None  # Set by coordinator
        
        if not self.watch_paths:
            self.logger.warning("No directories could be monitored — FileIOObserver inactive")
    
    def _monitor_directory(self, path: Path):
        """
        Monitor a directory for file changes using ReadDirectoryChangesW.
        
        FIXED: Uses correct constant names from win32con module.
        """
        try:
            # Open directory handle
            handle = win32file.CreateFile(
                str(path),
                FILE_LIST_DIRECTORY,  # FIXED: Properly defined constant
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            # Directory already logged in start() before thread spawn
            while self.running:
                try:
                    # Watch for changes
                    # FIXED: Use constants from win32con module
                    results = win32file.ReadDirectoryChangesW(
                        handle,
                        8192,  # Buffer size
                        True,  # Watch subtree
                        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                        win32con.FILE_NOTIFY_CHANGE_SIZE,
                        None,
                        None
                    )
                    
                    for action, file_name in results:
                        self._process_file_change(path, file_name, action)
                
                except pywintypes.error as e:
                    if e.winerror == 1:  # ERROR_INVALID_FUNCTION
                        self.logger.error(f"Cannot monitor {path} - unsupported file system")
                        break
                    else:
                        self.logger.error(f"Error monitoring {path}: {e}")
                        time.sleep(1)
                
                except Exception as e:
                    self.logger.error(f"Unexpected error monitoring {path}: {e}")
                    time.sleep(1)
        
        except Exception as e:
            self.logger.error(f"Failed to open directory {path}: {e}")
    
    def _process_file_change(self, base_path: Path, file_name: str, action: int):
        """Process a file change event."""
        action_names = {
            1: "CREATED",
            2: "DELETED",
            3: "MODIFIED",
            4: "RENAMED_OLD",
            5: "RENAMED_NEW"
        }
        
        action_name = action_names.get(action, "UNKNOWN")
        
        # Record event
        event = {
            "timestamp": time.time(),
            "path": str(base_path / file_name),
            "action": action_name,
            "file_name": file_name
        }
        
        self.file_events.append(event)
        
        # Try to determine which user (crude - from path)
        try:
            if "\\Users\\" in str(base_path):
                username = str(base_path).split("\\Users\\")[1].split("\\")[0]
            else:
                username = "SYSTEM"
        except:
            username = "UNKNOWN"
        
        self.user_file_counts[username].append(event)

        # Ransom note content scanning on text file events
        if self.ransom_note_scanner and action_name in ("CREATED", "MODIFIED"):
            self.ransom_note_scanner.on_file_event(
                str(base_path / file_name), action_name, username
            )
    
    def analyze_patterns(self) -> List[BehaviorEvent]:
        """
        Analyze file I/O patterns for suspicious behavior.
        
        Returns:
            List of BehaviorEvents if suspicious patterns detected
        """
        events = []
        current_time = time.time()
        window_start = current_time - self.window_duration
        
        # Analyze per user
        for username, user_events in self.user_file_counts.items():
            # Get events in current window
            recent_events = [
                e for e in user_events
                if e["timestamp"] >= window_start
            ]
            
            if not recent_events:
                continue
            
            # Count events by type
            event_counts = defaultdict(int)
            for event in recent_events:
                event_counts[event["action"]] += 1
            
            total_events = len(recent_events)
            evidence = []
            score = 0
            
            # Pattern 1: High volume of file access
            if total_events >= self.HIGH_IO_THRESHOLD:
                evidence.append(f"High file I/O: {total_events} files in 5 min")
                score += 40
            
            # Pattern 2: Mass modifications
            if event_counts["MODIFIED"] >= self.MASS_MODIFY_THRESHOLD:
                evidence.append(f"Mass modifications: {event_counts['MODIFIED']} files")
                score += 50
            
            # Pattern 3: Mass renames (common in ransomware)
            rename_count = event_counts["RENAMED_OLD"] + event_counts["RENAMED_NEW"]
            if rename_count >= 20:
                evidence.append(f"Mass renames: {rename_count} files")
                score += 60
            
            # Pattern 4: Mass deletes (shadow copies, backups)
            if event_counts["DELETED"] >= 30:
                evidence.append(f"Mass deletions: {event_counts['DELETED']} files")
                score += 40
            
            # Generate event if suspicious
            if evidence:
                confidence = "low"
                if score >= 50:
                    confidence = "medium"
                if score >= 80:
                    confidence = "high"
                
                events.append(BehaviorEvent(
                    timestamp=datetime.now().isoformat(),
                    source="file_io_observer",
                    behavior="mass_file_access",
                    confidence=confidence,
                    score=min(score, 100),
                    evidence=evidence,
                    metadata={
                        "total_events": total_events,
                        "modified_count": event_counts["MODIFIED"],
                        "renamed_count": rename_count,
                        "deleted_count": event_counts["DELETED"],
                        "window_minutes": self.window_duration / 60
                    },
                    username=username,
                    process_name=None  # Can't reliably determine from file events
                ))
        
        return events
    
    def start(self):
        """Start monitoring file I/O."""
        if not self.watch_paths:
            self.logger.warning("No paths to monitor - FileIOObserver will not start")
            return
            
        self.running = True
        
        # Log each path BEFORE spawning threads so order is deterministic
        for watch_path in self.watch_paths:
            self.logger.info(f"Monitoring directory: {watch_path}")
        
        # Now spawn threads (directory logging already done above)
        for watch_path in self.watch_paths:
            thread = Thread(
                target=self._monitor_directory,
                args=(watch_path,),
                daemon=True,
                name=f"FileIO-{watch_path.name}"
            )
            thread.start()
            self.monitor_threads.append(thread)
        
        # Summary always last
        self.logger.info(f"File I/O monitoring started on {len(self.watch_paths)} paths")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        for thread in self.monitor_threads:
            thread.join(timeout=2)



# ============================================================================
# OBSERVER 4: RANSOM NOTE SCANNER (File Content Detection)
# ============================================================================

class RansomNoteScanner:
    """
    Detects ransom notes by scanning newly created/modified text files.

    WHY THIS EXISTS:
    - YARA only scans executables on process creation
    - A .txt/.html ransom note dropped to disk is NEVER scanned by Module 1
    - This observer fills that gap: watches file events from FileIOObserver
      and scans the content of small text files for ransom note keywords

    WHAT WE SCAN:
    - Files created or modified in watched directories
    - Extensions: .txt, .html, .htm, .hta, .rtf, .md
    - Size cap: 512 KB (ransom notes are always small)
    - Content matched against tiered keyword sets

    SCORING:
    - Tier 1 (ransom-specific): "decrypt", "bitcoin", "ransom" etc.  +30 each
    - Tier 2 (family-specific): "ryuk", "conti", "lockbit" etc.      +50 each
    - Tier 3 (contact IOCs):    ".onion", "@", "hacked.com" etc.     +20 each
    - Score >= 60 -> medium confidence
    - Score >= 90 -> high confidence
    """

    SCANNABLE_EXTENSIONS = frozenset([
        ".txt", ".html", ".htm", ".hta", ".rtf", ".md", ".log"
    ])

    MAX_FILE_SIZE = 512 * 1024  # 512 KB — notes are always tiny

    # Tier 1: Generic ransom language
    TIER1_KEYWORDS = frozenset([
        "your files have been encrypted",
        "all your files",
        "files are encrypted",
        "pay a ransom",
        "pay the ransom",
        "ransom payment",
        "bitcoin",
        "btc wallet",
        "decryption key",
        "decryption password",
        "to decrypt",
        "for decryption",
        "restore your files",
        "recovery key",
        "contact us",
        "do not rename",
        "do not delete",
        "encrypted with rsa",
        "encrypted with aes",
        "unique id",
        "pay within",
    ])

    # Tier 2: Known family identifiers
    TIER2_KEYWORDS = frozenset([
        "ryuk",
        "conti",
        "lockbit",
        "revil",
        "sodinokibi",
        "blackcat",
        "alphv",
        "maze",
        "egregor",
        "cuba ransomware",
        "akira",
        "play ransomware",
        "darkside",
        "hive ransomware",
    ])

    # Tier 3: Contact/IOC indicators
    TIER3_KEYWORDS = frozenset([
        ".onion",
        "tox:",
        "jabber:",
        "telegram:",
        "@protonmail",
        "@tutanota",
        "@cock.li",
        "hacked.com",
        "@hacked",
        "session id",
        "negotiation",
    ])

    def __init__(self, emit_callback):
        """
        Args:
            emit_callback: Callable(BehaviorEvent) to emit detections
        """
        self.logger = logging.getLogger("RansomNoteScanner")
        self.emit = emit_callback
        self._scanned_paths: Set[str] = set()  # Avoid re-scanning same file

    def on_file_event(self, file_path: str, action: str, username: str):
        """
        Called by FileIOObserver for each file change.
        Scans eligible files for ransom note content.
        """
        if action not in ("CREATED", "MODIFIED"):
            return

        path = Path(file_path)

        if path.suffix.lower() not in self.SCANNABLE_EXTENSIONS:
            return

        # Avoid rescanning the same file repeatedly within a session
        cache_key = f"{file_path}:{path.stat().st_mtime if path.exists() else 0}"
        if cache_key in self._scanned_paths:
            return
        self._scanned_paths.add(cache_key)

        self._scan_file(path, username)

    def _scan_file(self, path: Path, username: str):
        """Scan a single file for ransom note keywords."""
        try:
            if not path.exists() or not path.is_file():
                return

            file_size = path.stat().st_size
            if file_size == 0 or file_size > self.MAX_FILE_SIZE:
                return

            # Read with error tolerance
            try:
                content = path.read_text(encoding="utf-8", errors="ignore").lower()
            except Exception:
                try:
                    content = path.read_text(encoding="latin-1", errors="ignore").lower()
                except Exception:
                    return

            if len(content.strip()) < 20:
                return  # Too short to be meaningful

            evidence = []
            score = 0
            matched_tier2 = []

            # Tier 1: Generic ransom language
            tier1_hits = [kw for kw in self.TIER1_KEYWORDS if kw in content]
            if tier1_hits:
                score += len(tier1_hits) * 30
                evidence.append(f"Ransom language ({len(tier1_hits)} matches): {', '.join(tier1_hits[:3])}")

            # Tier 2: Family-specific identifiers (high weight)
            tier2_hits = [kw for kw in self.TIER2_KEYWORDS if kw in content]
            if tier2_hits:
                score += len(tier2_hits) * 50
                matched_tier2 = tier2_hits
                evidence.append(f"Ransomware family identified: {', '.join(tier2_hits).upper()}")

            # Tier 3: Contact / IOC indicators
            tier3_hits = [kw for kw in self.TIER3_KEYWORDS if kw in content]
            if tier3_hits:
                score += len(tier3_hits) * 20
                evidence.append(f"Contact/IOC indicators: {', '.join(tier3_hits[:3])}")

            if not evidence:
                return  # Nothing suspicious

            score = min(score, 100)
            confidence = "low"
            if score >= 60:
                confidence = "medium"
            if score >= 90:
                confidence = "high"

            families = ", ".join(matched_tier2).upper() if matched_tier2 else "unknown"

            self.logger.warning(
                f"[RANSOM NOTE DETECTED] {path.name} | "
                f"Confidence: {confidence.upper()} | Score: {score} | "
                f"Families: {families} | User: {username}"
            )

            event = BehaviorEvent(
                timestamp=datetime.now().isoformat(),
                source="ransom_note_scanner",
                behavior="ransom_note_detected",
                confidence=confidence,
                score=score,
                evidence=evidence,
                metadata={
                    "file_path": str(path),
                    "file_name": path.name,
                    "file_size_bytes": path.stat().st_size,
                    "families_identified": matched_tier2,
                    "tier1_hits": tier1_hits,
                    "tier2_hits": tier2_hits,
                    "tier3_hits": tier3_hits,
                },
                username=username,
                process_name=None,
            )
            self.emit(event)

        except Exception as e:
            self.logger.debug(f"Error scanning {path}: {e}")

# ============================================================================
# TEMPORAL BEHAVIOR COORDINATOR
# ============================================================================

class TemporalBehaviorCoordinator:
    """
    Coordinates all temporal observers and emits behavior events.
    
    ARCHITECTURE:
    - Receives process events from Module 1
    - Each observer analyzes patterns
    - Emits BehaviorEvents to output file
    - These events flow into Module 4 (Campaign Correlator)
    """
    
    def __init__(self,
                 output_file: str = "temporal_behaviors.jsonl",
                 analysis_interval: int = 60,
                 watch_paths: List[str] = None):
        # BUG 6 FIX: watch_paths was not exposed on the coordinator at all.
        # integrated_detection_system.py instantiated this with no way to pass
        # additional directories to monitor. Now threads watch_paths through
        # to FileIOObserver so callers can inject paths (e.g. C:\temp for tests).
        
        self.output_file = Path(output_file)
        self.analysis_interval = analysis_interval
        
        self._setup_logging()
        
        # Initialize observers — pass watch_paths to FileIOObserver
        self.priv_esc_observer = PrivilegeEscalationObserver()
        self.lateral_mov_observer = LateralMovementObserver()
        self.file_io_observer = FileIOObserver(watch_paths=watch_paths)

        # Wire ransom note scanner into file I/O observer
        self.ransom_note_scanner = RansomNoteScanner(emit_callback=self._emit_event)
        self.file_io_observer.ransom_note_scanner = self.ransom_note_scanner
        
        self.running = False
        self.analysis_thread: Optional[Thread] = None
        
        self.events_emitted = 0
    
    def _setup_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("TemporalCoordinator")
    
    def observe_process_event(self, process_event: Dict):
        """
        Observe a process creation event.
        
        Args:
            process_event: Process event from Module 1
        """
        # Pass to each observer
        events = []
        
        # Privilege escalation check
        priv_event = self.priv_esc_observer.observe_process(process_event)
        if priv_event:
            events.append(priv_event)
        
        # Lateral movement check
        lateral_event = self.lateral_mov_observer.observe_process(process_event)
        if lateral_event:
            events.append(lateral_event)
        
        # Emit events
        for event in events:
            self._emit_event(event)
    
    def _emit_event(self, event: BehaviorEvent):
        """Write behavior event to output file."""
        try:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(event.to_json_line() + '\n')
            
            self.events_emitted += 1
            
            if event.confidence in ["medium", "high"]:
                self.logger.warning(
                    f"[{event.confidence.upper()}] {event.behavior} - "
                    f"User: {event.username}, Score: {event.score}"
                )
            else:
                self.logger.info(f"Behavior detected: {event.behavior}")
        
        except Exception as e:
            self.logger.error(f"Failed to emit event: {e}")
    
    def _periodic_analysis(self):
        """
        Periodic analysis of time-windowed patterns.

        BUG 2 FIX: Previously called time.sleep() BEFORE analyze_patterns(),
        so the first analysis never ran until after one full interval (60s by
        default). Events collected in the first minute were never evaluated.
        Now runs analysis immediately on start, then sleeps between cycles.
        """
        while self.running:
            try:
                # Analyze file I/O patterns — run FIRST, sleep after
                file_events = self.file_io_observer.analyze_patterns()
                for event in file_events:
                    self._emit_event(event)

            except Exception as e:
                self.logger.error(f"Periodic analysis error: {e}")

            # Sleep AFTER analysis so first run is immediate
            time.sleep(self.analysis_interval)
    
    def start(self):
        """Start temporal observation."""
        self.running = True
        
        # Start file I/O monitoring
        self.file_io_observer.start()
        
        # Start periodic analysis thread
        self.analysis_thread = Thread(
            target=self._periodic_analysis,
            daemon=True
        )
        self.analysis_thread.start()
        
        self.logger.info("Temporal observers active:")
        self.logger.info(f"  Output:            {self.output_file}")
        self.logger.info(f"  Analysis interval: {self.analysis_interval}s")
        # Show exactly which paths are being watched — previously silent on failure
        watched = self.file_io_observer.watch_paths
        if watched:
            self.logger.info(f"  File I/O watching: {len(watched)} path(s):")
            for p in watched:
                self.logger.info(f"    {p}")
        else:
            self.logger.warning("  File I/O watching: NO PATHS — FileIOObserver is inactive!")
        self.logger.info("="*70)
    
    def stop(self):
        """Stop all observers."""
        self.running = False
        
        # Stop file I/O observer
        self.file_io_observer.stop()
        
        # Stop analysis thread
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
    
    def get_stats(self) -> Dict:
        """Get statistics."""
        return {
            "events_emitted": self.events_emitted,
            "running": self.running
        }


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Standalone mode for testing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Module 3: Temporal Behavior Observers (FIXED)"
    )
    parser.add_argument('--output', default='temporal_behaviors.jsonl',
                        help='Output file for behavior events')
    parser.add_argument('--interval', type=int, default=60,
                        help='Analysis interval in seconds (default: 60)')
    parser.add_argument('--watch-paths', nargs='+',
                        help='Additional paths to monitor for file I/O')
    
    args = parser.parse_args()
    
    print("="*70)
    print("Module 3: Temporal Behavior Observers (FIXED)")
    print("="*70)
    print("This module detects behaviors that emerge over time:")
    print("  - Privilege escalation")
    print("  - Lateral movement")
    print("  - Mass file I/O")
    print("  - Pre-encryption patterns")
    print()
    print("Behavior events will be written to:", args.output)
    print("Press Ctrl+C to stop")
    print("="*70)
    print()
    
    coordinator = TemporalBehaviorCoordinator(
        output_file=args.output,
        analysis_interval=args.interval
    )
    
    try:
        coordinator.start()
        
        # Keep running
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nShutdown requested")
    finally:
        coordinator.stop()


if __name__ == "__main__":
    main()

"""
Process Monitor Module - Windows Host Based Process Creation Detection
Captures real-time process creation events with full context.
Supports Windows 10/11 and Windows Server.
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
import logging
import ctypes
from datetime import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict
import wmi
import time

try:
    from signature_scanner import SignatureScanner
    SIGNATURE_SCANNER_AVAILABLE = True
except ImportError:
    SIGNATURE_SCANNER_AVAILABLE = False


def is_admin() -> bool:
    """Checking if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


@dataclass
class ProcessEvent:
    timestamp: str
    process_name: str
    pid: Optional[int]
    parent_pid: Optional[int]
    command_line: str
    username: Optional[str] = None
    executable_path: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_command_line: Optional[str] = None
    risk_hint: Optional[str] = None
    event_type: str = "process_create"
    signature_hits: Optional[list[str]] = None
    
    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(asdict(self))


class ProcessMonitor:
    def __init__(self, log_file: str = "process_events.jsonl", auto_reconnect: bool = True):
        self.log_file = Path(log_file)
        self.auto_reconnect = auto_reconnect
        self.running = False
        self._setup_logging()
        
        # Initialize signature scanner if available
        self.signature_scanner = None
        if SIGNATURE_SCANNER_AVAILABLE:
            try:
                self.signature_scanner = SignatureScanner(rules_dir="rules/")
            except Exception as e:
                self.logger.warning(f"Signature scanner unavailable: {e}")
                self.logger.warning("Continuing without signature scanning")
        else:
            self.logger.warning("signature_scanner module not found - YARA scanning disabled")
        try:
            self.wmi_connection = wmi.WMI()
        except Exception as e:
            self.logger.error(f"Failed to initialize WMI connection: {e}")
            raise RuntimeError("WMI initialization failed. Ensure you have administrator privileges.")
    
    def _setup_logging(self):
        """Configure logging for the monitor."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("ProcessMonitor")
        
    def _log_event(self, event: ProcessEvent):
        """Log process event to file in JSON Lines format."""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(event.to_json() + '\n')
            self.logger.info(
                f"Logged process: {event.process_name} "
                f"(PID: {event.pid}, User: {event.username})"
            )
        except Exception as e:
            self.logger.error(f"Failed to log event: {e}")
    
    def _get_process_owner(self, process) -> Optional[str]:
        """Safely get the process owner username."""
        try:
            owner_info = process.GetOwner()
            if owner_info and len(owner_info) >= 3:
                domain, _, user = owner_info[:3]
                if domain and user:
                    return f"{domain}\\{user}"
                elif user:
                    return user
        except Exception as e:
            self.logger.debug(f"Could not get owner for PID {process.ProcessId}: {e}")
        return None
    
    def _get_parent_process_info(self, parent_pid: int) -> tuple[Optional[str], Optional[str]]:
        """Get parent process name and command line."""
        try:
            if parent_pid > 0:
                parent_processes = self.wmi_connection.Win32_Process(ProcessId=parent_pid)
                if parent_processes:
                    parent = parent_processes[0]
                    return (parent.Name, parent.CommandLine)
        except Exception as e:
            self.logger.debug(f"Could not get parent info for PPID {parent_pid}: {e}")
        return (None, None)
    
    def _create_event(self, process) -> Optional[ProcessEvent]:
        """
        Create ProcessEvent from WMI process object.
        """
        event = None  # Initialize to prevent NameError in exception handler
        try:
            # Create base event object
            parent_pid = int(process.ParentProcessId) if process.ParentProcessId else None
            parent_name, parent_cmdline = self._get_parent_process_info(parent_pid)
            
            event = ProcessEvent(
                timestamp=datetime.now().isoformat(),
                process_name=process.Name,
                pid=int(process.ProcessId),
                parent_pid=parent_pid,
                command_line=process.CommandLine or "",
                username=self._get_process_owner(process),
                executable_path=process.ExecutablePath,
                parent_process_name=parent_name,
                parent_command_line=parent_cmdline,
            )

            # Optional signature scanning (separate try-catch to isolate failures)
            if self.signature_scanner and event.executable_path:
                # Skip common benign paths to reduce I/O
                skip_prefixes = [
                    r"C:\Windows\System32", 
                    r"C:\Windows\SysWOW64", 
                    r"C:\Program Files"
                ]
                
                should_scan = not any(
                    event.executable_path.lower().startswith(prefix.lower()) 
                    for prefix in skip_prefixes
                )
                
                if should_scan:
                    try:
                        signature_hits = self.signature_scanner.scan(event.executable_path)
                        if signature_hits:
                            event.signature_hits = signature_hits
                            event.risk_hint = f"Signature match: {', '.join(signature_hits)}"
                            self.logger.warning(
                                f"[!ALERT!] Signature hit detected: {event.process_name} "
                                f"(PID {event.pid}) -> {signature_hits}"
                            )
                    except Exception as scan_err:
                        self.logger.debug(f"Signature scan failed for {event.executable_path}: {scan_err}")
                        # Don't fail event creation if scan fails
                else:
                    self.logger.debug(f"Skipping scan for benign path: {event.executable_path}")
            
            return event
            
        except Exception as e:
            self.logger.debug(f"Failed to create event from process: {e}")
            return None
    
    def start(self):
        """Start monitoring process creation events.
        
        Blocking call — runs until Ctrl+C or stop() is called.
        Uses WMI event notifications for real-time detection.
        """
        self.running = True
        retry_delay = 5
        
        while self.running:
            try:
                if not self.wmi_connection:
                    if self.auto_reconnect:
                        self.logger.warning("Attempting to reconnect to WMI...")
                        self.wmi_connection = wmi.WMI()
                        time.sleep(retry_delay)
                        continue
                    else:
                        self.logger.error("WMI connection lost and auto-reconnect disabled")
                        break
                
                process_watcher = self.wmi_connection.Win32_Process.watch_for("creation")
                while self.running:
                    try:
                        new_process = process_watcher(timeout_ms=100)
                        if new_process:
                            event = self._create_event(new_process)
                            if event:
                                self._log_event(event)
                            else:
                                self.logger.debug("Event creation returned None (likely benign failure)")
                                
                    except wmi.x_wmi_timed_out:
                        continue
                    except wmi.x_wmi as e:
                        self.logger.error(f"WMI error: {e}")
                        if self.auto_reconnect:
                            self.logger.warning(f"WMI connection lost. Reconnecting in {retry_delay}s...")
                            self.wmi_connection = None
                            time.sleep(retry_delay)
                            break
                        else:
                            raise
                    except Exception as e:
                        self.logger.error(f"Error processing event: {e}")
                        
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal (Ctrl+C)")
                break
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
                if self.auto_reconnect:
                    self.logger.warning(f"Attempting recovery in {retry_delay}s...")
                    self.wmi_connection = None
                    time.sleep(retry_delay)
                else:
                    raise
                    
        self.stop()
    
    def stop(self):
        """Stop the process monitor."""
        self.running = False


def main():
    """Main entry point for standalone execution."""
    import argparse
    import sys
    
    admin_status = is_admin()
    
    parser = argparse.ArgumentParser(
        description="Windows Process Creation Monitor (FIXED VERSION)",
        epilog="Administrator privileges recommended for full functionality."
    )
    parser.add_argument('--log-file', default='process_events.jsonl',
                        help='Output file for process events (default: process_events.jsonl)')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose debug logging')
    parser.add_argument('--no-auto-reconnect', action='store_true',
                        help='Disable automatic WMI reconnection on failure')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger("ProcessMonitor").setLevel(logging.DEBUG)
    
    print("=" * 70)
    print("Windows Process Monitor (FIXED VERSION)")
    print("=" * 70)
    
    if admin_status:
        print("[OK] Running with ADMINISTRATOR privileges -> Full telemetry available")
    else:
        print("[FAIL] Running WITHOUT administrator privileges -> Limited telemetry")
        print("  Recommendation: Run as Administrator")
    
    print("=" * 70)
    print(f"Log file: {args.log_file}")
    print(f"Auto-reconnect: {'Enabled' if not args.no_auto_reconnect else 'Disabled'}")
    
    if SIGNATURE_SCANNER_AVAILABLE:
        print(f"Signature scanning: ENABLED (YARA)")
    else:
        print(f"Signature scanning: DISABLED (install yara-python to enable)")
    
    try:
        monitor = ProcessMonitor(
            args.log_file,
            auto_reconnect=not args.no_auto_reconnect
        )
        monitor.start()
    except RuntimeError as e:
        print(f"\n[FAIL] Error: {e}", file=sys.stderr)
        print("\nTroubleshooting:")
        print("- Run this script as Administrator")
        print("- Ensure WMI service is running: net start winmgmt")
        return 1
    except Exception as e:
        print(f"\n[FAIL] Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

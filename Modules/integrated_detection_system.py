"""
Integrated Detection System - Modules 1 + 2 + 3
Combines process monitoring, behavioral tagging, and temporal observation.

ARCHITECTURE:
┌──────────────────────────────────────────────────────────────┐
│                    Windows Process Events                    │
└────────────────────┬─────────────────────────────────────────┘
                     ↓
┌──────────────────────────────────────────────────────────────┐
│ Module 1: Process Monitor (process_monitor.py)               │
│ - Captures process creation via WMI                          │
│ - Adds YARA signature hits                                   │
│ - Writes to: process_events.jsonl                            │
└────────────────────┬─────────────────────────────────────────┘
                     ↓
         ┌───────────┴───────────┐
         ↓                       ↓
┌──────────────────┐    ┌──────────────────────────────────────┐
│ Module 2:        │    │ Module 3: Temporal Observers         │
│ Behavior Tagger  │    │ - Privilege escalation tracking      │
│ - Pattern tags   │    │ - Lateral movement detection         │
│ - Confidence     │    │ - File I/O monitoring                │
│ → enriched_      │    │ → temporal_behaviors.jsonl           │
│   events.jsonl   │    └──────────────────────────────────────┘
└──────────────────┘
         │
         ↓
┌──────────────────────────────────────────────────────────────┐
│ Module 4: Campaign Correlator (Coming Next)                  │
│ - Consumes: enriched_events.jsonl + temporal_behaviors.jsonl │
│ - Correlates behaviors across time                           │
│ - Campaign scoring                                           │
│ → campaign_alerts.jsonl                                      │
└──────────────────────────────────────────────────────────────┘
"""

import sys
import time
import signal
import logging
import json
from pathlib import Path
from typing import Optional
from threading import Thread, Lock
import psutil

# Import modules
try:
    from process_monitor import ProcessMonitor
    from behavior_tagger import ThreadedTagger, TaggedEvent
    from temporal_observers import TemporalBehaviorCoordinator
    from decision_engine import DecisionEngine
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Ensure all module files are in the same directory:")
    print("  - process_monitor.py")
    print("  - behavior_tagger.py")
    print("  - temporal_observers.py")
    print("  - decision_engine.py")
    sys.exit(1)


class IntegratedDetectionSystem:
    """
    Orchestrates all detection modules.
    
    FLOW:
    1. Module 1 captures process events → process_events.jsonl
    2. Module 2 tags events → enriched_events.jsonl  
    3. Module 3 observes temporal patterns → temporal_behaviors.jsonl
    4. All events feed into Module 4 (Campaign Correlator - next step)
    """
    
    def __init__(self,
                 process_log: str = "process_events.jsonl",
                 enriched_log: str = "enriched_events.jsonl",
                 temporal_log: str = "temporal_behaviors.jsonl",
                 alert_log: str = "alerts.jsonl"):
        
        self.process_log = process_log
        self.enriched_log = enriched_log
        self.temporal_log = temporal_log
        self.alert_log = alert_log
        
        self.process_monitor: Optional[ProcessMonitor] = None
        self.behavior_tagger: Optional[ThreadedTagger] = None
        self.temporal_coordinator: Optional[TemporalBehaviorCoordinator] = None
        self.decision_engine = DecisionEngine(rules_dir="rules/")
        
        self.running = False
        self.stopping = False
        self.stop_lock = Lock()
        
        self.monitor_thread: Optional[Thread] = None
        self.event_bridge_thread: Optional[Thread] = None
        
        self._setup_logging()
        self._setup_signal_handlers()
    
    def _setup_logging(self):
        """Configure logging - cleaner output."""
        # Create file handler (detailed logs)
        file_handler = logging.FileHandler('integrated_detection.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        # Create console handler (important messages only)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        # Configure root logger
        logging.basicConfig(
            level=logging.DEBUG,
            handlers=[file_handler, console_handler]
        )
        
        self.logger = logging.getLogger("IntegratedDetection")
    
    def _setup_signal_handlers(self):
        """Handle shutdown signals gracefully."""
        def signal_handler(signum, frame):
            """Handle Ctrl+C and other signals."""
            if not self.stopping:
                self.logger.info("Shutdown requested (Ctrl+C)")
                self.stop()
            # If already stopping, ignore additional signals
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _bridge_events_to_temporal(self):
        """
        Bridge process events to Module 3 (temporal observers).
        
        This thread tail-follows process_events.jsonl and feeds events
        to the temporal coordinator for temporal pattern detection.
        """
        self.logger.debug("Event bridge to temporal observers started")
        
        file_path = Path(self.process_log)
        file_position = 0
        
        # Seek to end of file initially
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                f.seek(0, 2)
                file_position = f.tell()
        
        while self.running and not self.stopping:
            try:
                if not file_path.exists():
                    time.sleep(1)
                    continue
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.seek(file_position)
                    
                    for line in f:
                        if line.strip():
                            try:
                                event = json.loads(line)
                                # Feed to temporal coordinator
                                self.temporal_coordinator.observe_process_event(event)
                            except json.JSONDecodeError:
                                pass  # Skip malformed JSON silently
                    
                    file_position = f.tell()
                
                time.sleep(0.1)  # Poll interval
                
            except Exception as e:
                self.logger.error(f"Event bridge error: {e}")
                time.sleep(1)
    
    def _alert_callback(self, event: TaggedEvent):
        """
        Callback invoked by Module 2 for every tagged event.
        Passes the event through Module 3 (DecisionEngine) which:
          - Computes a proper weighted score from BEHAVIOR_TAGS
          - Maps score → LOW / MEDIUM / HIGH / CRITICAL via RISK_THRESHOLDS
          - Triggers YARA only when score >= MEDIUM threshold
          - Returns a DecisionResult consumed by Module 5
        """
        result = self.decision_engine.evaluate(
            event,
            executable_path=event.executable_path
        )

        # Write every decision to the alert log (Module 5 reads this)
        try:
            with open(self.alert_log, 'a', encoding='utf-8') as f:
                f.write(result.to_json_line() + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write decision result: {e}")

        # Console alert only for MEDIUM and above
        if result.level in ("medium", "high", "critical"):
            yara_note = ""
            if result.yara_hits:
                yara_note = f" | YARA: {', '.join(result.yara_hits)}"
            elif result.yara_triggered:
                yara_note = " | YARA: no match"

            self.logger.warning(
                f"[{result.level.upper():8s}] score={result.total_score:3d} | "
                f"{result.process_name} (PID {result.pid}){yara_note}"
            )
            self.logger.warning(f"           Action : {result.recommended_action}")
    
    def _monitor_resources(self):
        """
        Monitor system resource usage - quieter logging.
        
        Only logs when thresholds are exceeded.
        """
        process = psutil.Process()
        startup_grace_period = 10  # Ignore first 10 seconds (startup spike)
        start_time = time.time()
        
        while self.running and not self.stopping:
            try:
                # Skip startup period
                if time.time() - start_time < startup_grace_period:
                    time.sleep(5)
                    continue
                
                cpu_percent = process.cpu_percent(interval=1)
                mem_mb = process.memory_info().rss / 1024 / 1024
                
                # Adjusted thresholds (less noisy)
                if cpu_percent > 10:  # Increased from 5%
                    self.logger.warning(f"High CPU usage: {cpu_percent:.1f}%")
                
                if mem_mb > 250:  # Increased from 200MB
                    self.logger.warning(f"High memory usage: {mem_mb:.1f}MB")
                
                # Check system load (only log if critical)
                system_cpu = psutil.cpu_percent(interval=1)
                if system_cpu > 95:
                    self.logger.warning(
                        f"System under heavy load ({system_cpu}%), "
                        "detection may be throttled"
                    )
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.debug(f"Resource monitoring error: {e}")
    
    def start(self):
        """Start the detection system."""
        self.running = True
        self.stopping = False
        
        self.logger.info("="*70)
        self.logger.info("Starting Anti-Ransomware Detection System")
        self.logger.info("="*70)
        self.logger.info("Modules Active:")
        self.logger.info("  [1] Process Monitor      — WMI telemetry capture")
        self.logger.info("  [2] Behavior Tagger      — Pattern detection & scoring")
        self.logger.info("  [3] Decision Engine      — Threshold gating & YARA trigger")
        self.logger.info("  [4] Temporal Observers   — Time-window behavior tracking")
        self.logger.info("="*70)
        
        # Start resource monitoring (quiet)
        self.monitor_thread = Thread(
            target=self._monitor_resources,
            daemon=True,
            name="ResourceMonitor"
        )
        self.monitor_thread.start()
        self.temporal_coordinator = TemporalBehaviorCoordinator(
            output_file=self.temporal_log,
            analysis_interval=60
        )
        self.temporal_coordinator.start()
        
        # Start event bridge (process_events → temporal observers)
        self.event_bridge_thread = Thread(
            target=self._bridge_events_to_temporal,
            daemon=True,
            name="EventBridge"
        )
        self.event_bridge_thread.start()
        
        # Start Module 2: Behavior Tagger
        self.behavior_tagger = ThreadedTagger(
            self.process_log,
            self.enriched_log
        )
        self.behavior_tagger.processor.callback = self._alert_callback
        self.behavior_tagger.start()
        
        # Start Module 1: Process Monitor
        try:
            self.process_monitor = ProcessMonitor(
                log_file=self.process_log,
                auto_reconnect=True
            )
            
            self.logger.info("="*70)
            self.logger.info("All modules active!")
            self.logger.info(f"  Processed   Events: {self.process_log}")
            self.logger.info(f"  Enriched    Events: {self.enriched_log}")
            self.logger.info(f"  Temporal Behaviors: {self.temporal_log}")
            self.logger.info(f"  Alerts            : {self.alert_log}")
            self.logger.info("="*70)
            self.logger.info("Monitor active. Press Ctrl+C to stop...")
            self.logger.info("="*70)
            # Blocking call - runs until stopped
            self.process_monitor.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start process monitor: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop all components gracefully - SINGLE EXECUTION ONLY."""
        with self.stop_lock:
            if self.stopping:
                return  # Already stopping, prevent duplicate
            
            self.stopping = True
            self.running = False
        
        self.logger.info("Stopping integrated detection system...")
        
        # Stop Module 1 (Process Monitor)
        if self.process_monitor:
            try:
                self.process_monitor.stop()
            except Exception as e:
                self.logger.debug(f"Error stopping process monitor: {e}")
        
        # Stop Module 2 (Behavior Tagger)
        if self.behavior_tagger:
            try:
                self.behavior_tagger.stop()
            except Exception as e:
                self.logger.debug(f"Error stopping behavior tagger: {e}")
        
        # Stop Module 3 (Temporal Coordinator)
        if self.temporal_coordinator:
            try:
                self.temporal_coordinator.stop()
            except Exception as e:
                self.logger.debug(f"Error stopping temporal coordinator: {e}")
        
        # Stop event bridge thread
        if self.event_bridge_thread and self.event_bridge_thread.is_alive():
            self.event_bridge_thread.join(timeout=2)
        
        self.logger.info("All modules stopped cleanly")
    
    def get_status(self) -> dict:
        """Get system status."""
        status = {
            "running": self.running,
            "stopping": self.stopping,
            "module_1_active": self.process_monitor is not None,
            "module_2_active": self.behavior_tagger is not None,
            "module_3_active": True,  # DecisionEngine is always instantiated
            "module_4_active": self.temporal_coordinator is not None,
        }

        if self.behavior_tagger:
            try:
                status["module_2_stats"] = self.behavior_tagger.get_stats()
            except Exception:
                pass

        status["module_3_stats"] = self.decision_engine.get_stats()

        if self.temporal_coordinator:
            try:
                status["module_4_stats"] = self.temporal_coordinator.get_stats()
            except Exception:
                pass

        return status


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Integrated Anti-Ransomware Detection System (Modules 1+2+3)",
        epilog="Run with Administrator privileges for full functionality"
    )
    parser.add_argument('--process-log', default='process_events.jsonl',
                        help='Process event log file')
    parser.add_argument('--enriched-log', default='enriched_events.jsonl',
                        help='Enriched event log file')
    parser.add_argument('--temporal-log', default='temporal_behaviors.jsonl',
                        help='Temporal behavior log file')
    parser.add_argument('--alert-log', default='alerts.jsonl',
                        help='Alert log file')
    
    args = parser.parse_args()
    
    # Check admin privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False
    
    if not is_admin:
        print("="*70)
        print("WARNING: Running without Administrator privileges")
        print("="*70)
        print("Reduced capabilities:")
        print("  - Limited process telemetry")
        print("  - Cannot check integrity levels (Module 3)")
        print("  - File monitoring may be restricted (Module 3)")
        print()
        print("Recommendation: Run as Administrator for full detection")
        print("="*70)
        print()
    
    # Start detection system
    system = IntegratedDetectionSystem(
        process_log=args.process_log,
        enriched_log=args.enriched_log,
        temporal_log=args.temporal_log,
        alert_log=args.alert_log
    )
    
    try:
        system.start()
    except KeyboardInterrupt:
        print("\n")  # Clean line after Ctrl+C
    except Exception as e:
        print(f"Fatal error: {e}")
        return 1
    finally:
        # Ensure clean shutdown
        if not system.stopping:
            system.stop()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

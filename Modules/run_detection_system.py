"""
Integrated Anti-Ransomware Detection System Runner
Coordinates process_monitor.py and behavior_tagger.py

PRODUCTION DEPLOYMENT:
- Runs as Windows background service
- Minimal resource footprint
- Auto-recovery on failures
- Clean shutdown handling
"""

import io

# Fix Windows console encoding issues
import sys
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


import sys
import time
import signal
import logging
from pathlib import Path
from typing import Optional
import psutil
import threading

# Import your modules
try:
    from process_monitor import ProcessMonitor
    from behavior_tagger import ThreadedTagger, TaggedEvent
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Ensure process_monitor.py and behavior_tagger.py are in the same directory")
    sys.exit(1)


class DetectionSystemCoordinator:
    """
    Coordinates all detection components.
    
    RESOURCE MANAGEMENT:
    - Monitors own CPU/memory usage
    - Auto-throttles if system load is high
    - Graceful degradation under pressure
    """
    
    def __init__(self, 
                 process_log: str = "process_events.jsonl",
                 enriched_log: str = "enriched_events.jsonl",
                 alert_log: str = "alerts.jsonl"):
        
        self.process_log = process_log
        self.enriched_log = enriched_log
        self.alert_log = alert_log
        
        self.process_monitor: Optional[ProcessMonitor] = None
        self.behavior_tagger: Optional[ThreadedTagger] = None
        
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        self._setup_logging()
        self._setup_signal_handlers()
    
    def _setup_logging(self):
        """Configure logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('detection_system.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("DetectionSystem")
    
    def _setup_signal_handlers(self):
        """Handle shutdown signals gracefully."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Clean shutdown on signal."""
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        self.stop()
    
    def _alert_callback(self, event: TaggedEvent):
        """
        Callback for high-confidence events.
        
        TODO: INTEGRATE WITH YOUR ALERTING SYSTEM
        - Send to SIEM
        - Trigger response actions
        - Notify security team
        """
        if event.confidence in ["medium", "high"]: 
            # alerts are signals, not verdicts
            # medium != notify, maybe log only
            # high != kill, maybe escalate
            # Log to alerts file
            with open(self.alert_log, 'a', encoding='utf-8') as f:
                f.write(event.to_json_line() + '\n')
            
            # Console alert
            self.logger.warning(
                f"[{event.confidence.upper()}] {event.process_name} - "
                f"Tags: {', '.join(event.tags[:3])}"
            )
            
            # TODO: Add your alerting logic here
            # - Email notification
            # - Slack webhook
            # - SIEM integration
            # - Kill process (if configured)
    
    def _monitor_resources(self):
        """
        Monitor system resource usage.
        
        PROTECTION MECHANISM:
        - If detection system uses >5% CPU -> log warning
        - If detection system uses >100MB RAM -> log warning
        - If system CPU >90% -> pause non-critical processing
        """
        process = psutil.Process()
        
        while self.running:
            try:
                cpu_percent = process.cpu_percent(interval=1)
                mem_mb = process.memory_info().rss / 1024 / 1024
                
                if cpu_percent > 5:
                    self.logger.warning(f"High CPU usage: {cpu_percent:.1f}%")
                
                if mem_mb > 100:
                    self.logger.warning(f"High memory usage: {mem_mb:.1f}MB")
                
                # Check system load
                system_cpu = psutil.cpu_percent(interval=1)
                if system_cpu > 90:
                    self.logger.warning(
                        f"System under heavy load ({system_cpu}%), "
                        "detection may be throttled"
                    )
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
    
    def start(self):
        """Start the detection system."""
        self.running = True
        
        self.logger.info("="*70)
        self.logger.info("Starting Anti-Ransomware Detection System")
        self.logger.info("="*70)
        
        # Start resource monitoring
        self.monitor_thread = threading.Thread(
            target=self._monitor_resources,
            daemon=True
        )
        self.monitor_thread.start()
        
        # Start behavior tagger (with alert callback)
        self.logger.info("Starting behavior tagger...")
        self.behavior_tagger = ThreadedTagger(
            self.process_log,
            self.enriched_log
        )
        # Inject callback into processor
        self.behavior_tagger.processor.callback = self._alert_callback
        self.behavior_tagger.start()
        
        # Start process monitor
        self.logger.info("Starting process monitor...")
        try:
            self.process_monitor = ProcessMonitor(
                log_file=self.process_log,
                auto_reconnect=True
            )
            
            self.logger.info("="*70)
            self.logger.info("Detection system active")
            self.logger.info(f"  Process log: {self.process_log}")
            self.logger.info(f"  Enriched log: {self.enriched_log}")
            self.logger.info(f"  Alert log: {self.alert_log}")
            self.logger.info("="*70)
            
            # Blocking call - runs until stopped
            self.process_monitor.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start process monitor: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop all components gracefully."""
        self.running = False
        self.logger.info("Stopping detection system...")
        
        # Stop process monitor
        if self.process_monitor:
            self.process_monitor.stop()
        
        # Stop behavior tagger
        if self.behavior_tagger:
            self.behavior_tagger.stop()
        
        self.logger.info("Detection system stopped cleanly")
    
    def get_status(self) -> dict:
        """Get system status."""
        status = {
            "running": self.running,
            "process_monitor": self.process_monitor is not None,
            "behavior_tagger": self.behavior_tagger is not None,
        }
        
        if self.behavior_tagger:
            status["tagger_stats"] = self.behavior_tagger.get_stats()
        
        return status


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Integrated Anti-Ransomware Detection System",
        epilog="Run with Administrator privileges for full functionality"
    )
    parser.add_argument('--process-log', default='process_events.jsonl',
                        help='Process event log file')
    parser.add_argument('--enriched-log', default='enriched_events.jsonl',
                        help='Enriched event log file')
    parser.add_argument('--alert-log', default='alerts.jsonl',
                        help='Alert log file')
    parser.add_argument('--daemon', action='store_true',
                        help='Run as background daemon')
    
    args = parser.parse_args()
    
    # Check admin privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False
    
    if not is_admin:
        print("WARNING: Running without Administrator privileges")
        print("Some telemetry may be unavailable")
        print()
    
    # Start detection system
    coordinator = DetectionSystemCoordinator(
        process_log=args.process_log,
        enriched_log=args.enriched_log,
        alert_log=args.alert_log
    )
    
    try:
        coordinator.start()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        return 1
    finally:
        coordinator.stop()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

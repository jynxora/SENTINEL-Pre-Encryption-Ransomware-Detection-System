"""
Dashboard Server — Real-time Web UI Backend
=============================================
Serves the React dashboard and streams live events via WebSocket.
Reads from the .jsonl log files written by the detection system.

DESIGN:
- Flask + Flask-SocketIO (WebSocket)
- File tail-following for live event streaming
- REST endpoints for historical data + stats
- Integrates ML scorer for per-event augmentation
- Runs on localhost:5000 alongside the terminal

INSTALL:
    pip install flask flask-socketio flask-cors

RUN:
    python dashboard_server.py
    # Open http://localhost:5000 in your browser

NOTE: This is a companion process — run alongside integrated_detection_system.py
"""

import json
import os
import sys
import time
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from collections import deque, defaultdict

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

# Try WebSocket support
try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    print("[WARNING] flask-socketio not installed — WebSocket disabled (pip install flask-socketio)")

# Try ML scorer
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from ml_scorer import MLScorer, MLScore
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILES = {
    "process_events": "process_events.jsonl",
    "enriched_events": "enriched_events.jsonl",
    "alerts": "alerts.jsonl",
    "temporal": "temporal_behaviors.jsonl",
}

MAX_BUFFER = 500          # Max events to keep in memory
TAIL_INTERVAL = 0.3       # Seconds between file polls
STATS_INTERVAL = 5.0      # Seconds between stats broadcasts

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="dashboard_ui/dist", static_url_path="")
CORS(app)

if SOCKETIO_AVAILABLE:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
else:
    socketio = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("DashboardServer")

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

class DashboardState:
    """Thread-safe in-memory state for the dashboard."""

    def __init__(self):
        self.lock = threading.Lock()
        
        # Event buffers
        self.alerts: deque = deque(maxlen=MAX_BUFFER)
        self.process_events: deque = deque(maxlen=MAX_BUFFER)
        self.temporal_events: deque = deque(maxlen=MAX_BUFFER)
        
        # Stats
        self.total_events = 0
        self.severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        self.process_freq: Dict[str, int] = defaultdict(int)
        self.user_freq: Dict[str, int] = defaultdict(int)
        self.hourly_counts: Dict[int, int] = defaultdict(int)
        self.yara_hits = 0
        self.ml_detections = 0
        self.start_time = datetime.now()
        
        # Timeline (last 60 minutes, per minute)
        self.timeline: deque = deque(maxlen=60)
        self._last_minute = -1
        
        # File positions
        self.file_positions: Dict[str, int] = {k: 0 for k in LOG_FILES}
        
        # Recent activity rate
        self.events_per_minute: deque = deque(maxlen=60)
        self._minute_count = 0
        self._minute_start = time.time()

    def add_alert(self, event: dict):
        with self.lock:
            self.alerts.appendleft(event)
            self.total_events += 1
            
            level = event.get("level", "low")
            self.severity_counts[level] = self.severity_counts.get(level, 0) + 1
            
            proc = event.get("process_name", "unknown")
            self.process_freq[proc] += 1
            
            user = event.get("username", "unknown") or "unknown"
            self.user_freq[user] += 1
            
            if event.get("yara_hits"):
                self.yara_hits += 1
            
            if event.get("ml_score") and event["ml_score"] > 0.5:
                self.ml_detections += 1
            
            # Timeline
            minute = int(time.time() / 60)
            if minute != self._last_minute:
                self.timeline.append({"minute": minute, "count": 0, "high": 0})
                self._last_minute = minute
            if self.timeline:
                self.timeline[-1]["count"] += 1
                if level in ("high", "critical"):
                    self.timeline[-1]["high"] += 1
            
            # Rate tracking
            self._minute_count += 1
            now = time.time()
            if now - self._minute_start >= 60:
                self.events_per_minute.append(self._minute_count)
                self._minute_count = 0
                self._minute_start = now

    def add_process_event(self, event: dict):
        """
        BUG 2 FIX: Previously on_process_event() only appended to
        state.process_events and never called add_alert(), so process_freq,
        user_freq, total_events, and the timeline were never updated for
        normal user activity — making the stats dashboard look empty during
        benign operation.

        Now we update all the shared counters here so normal user activity
        is visible in every stats widget, while still keeping the separate
        process_events buffer for the /api/events/process endpoint.
        """
        with self.lock:
            self.process_events.appendleft(event)

            # Update shared counters so normal activity shows in stats
            proc = event.get("process_name", "unknown")
            self.process_freq[proc] += 1

            user = event.get("username", "unknown") or "unknown"
            self.user_freq[user] += 1

            self.total_events += 1

            # Count as "low" severity in the timeline so normal activity
            # contributes to the activity chart without raising false alarms
            level = event.get("level", "low")
            self.severity_counts[level] = self.severity_counts.get(level, 0) + 1

            minute = int(time.time() / 60)
            if minute != self._last_minute:
                self.timeline.append({"minute": minute, "count": 0, "high": 0})
                self._last_minute = minute
            if self.timeline:
                self.timeline[-1]["count"] += 1

            self._minute_count += 1
            now = time.time()
            if now - self._minute_start >= 60:
                self.events_per_minute.append(self._minute_count)
                self._minute_count = 0
                self._minute_start = now

    def get_stats(self) -> dict:
        with self.lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            rate = self._minute_count / max(1, (time.time() - self._minute_start) / 60)
            return {
                "total_events": self.total_events,
                "severity_counts": dict(self.severity_counts),
                "top_processes": sorted(self.process_freq.items(), key=lambda x: x[1], reverse=True)[:10],
                "top_users": sorted(self.user_freq.items(), key=lambda x: x[1], reverse=True)[:10],
                "yara_hits": self.yara_hits,
                "ml_detections": self.ml_detections,
                "uptime_seconds": int(uptime),
                "events_per_minute": round(rate, 1),
                "timeline": list(self.timeline),
                "alert_count": len(self.alerts),
            }

    def get_alerts(self, limit: int = 50, level_filter: Optional[str] = None) -> List[dict]:
        with self.lock:
            alerts = list(self.alerts)
            if level_filter:
                alerts = [a for a in alerts if a.get("level") == level_filter]
            return alerts[:limit]


state = DashboardState()

# ML scorer (initialize once)
ml_scorer = None
if ML_AVAILABLE:
    try:
        ml_scorer = MLScorer()
        logger.info("ML scorer initialized")
    except Exception as e:
        logger.warning(f"ML scorer init failed: {e}")


# ---------------------------------------------------------------------------
# File tailer
# ---------------------------------------------------------------------------

class FileTailer:
    """Tails a JSONL file and calls callback for each new line.

    Args:
        backfill: Number of *existing* lines to replay on startup (0 = skip
                  to EOF as before).  Set >0 so the dashboard shows recent
                  history when it restarts while the detection system is
                  already running.
    """

    def __init__(self, filepath: str, callback, label: str = "", backfill: int = 0):
        self.filepath = Path(filepath)
        self.callback = callback
        self.label = label
        self.backfill = backfill   # BUG 3 FIX: replays last N lines on start
        self.position = 0
        self.running = False

    def start(self):
        self.running = True

        if self.filepath.exists():
            if self.backfill > 0:
                # BUG 3 FIX: replay the last `backfill` lines so the dashboard
                # is not blank after a restart.  Previously we always seeked to
                # EOF and silently dropped all historical data.
                self._replay_tail_lines(self.backfill)
            else:
                # Skip to end — intentionally ignore all existing content
                self.position = self.filepath.stat().st_size

        thread = threading.Thread(target=self._run, daemon=True, name=f"Tailer-{self.label}")
        thread.start()

    def _replay_tail_lines(self, n: int):
        """Read the last *n* lines of the file and feed them to callback."""
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                # Efficient tail: collect last n lines without reading whole file
                lines = deque(f, maxlen=n)
                for line in lines:
                    stripped = line.strip()
                    if stripped:
                        try:
                            self.callback(json.loads(stripped))
                        except (json.JSONDecodeError, Exception):
                            pass
                self.position = f.tell()
        except Exception as e:
            logger.debug(f"Backfill error ({self.label}): {e}")
            if self.filepath.exists():
                self.position = self.filepath.stat().st_size

    def _run(self):
        while self.running:
            try:
                if not self.filepath.exists():
                    time.sleep(TAIL_INTERVAL)
                    continue

                current_size = self.filepath.stat().st_size
                if current_size < self.position:
                    # File was truncated/rotated
                    self.position = 0

                if current_size > self.position:
                    with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(self.position)
                        for line in f:
                            stripped = line.strip()
                            if stripped:
                                try:
                                    event = json.loads(stripped)
                                    self.callback(event)
                                except json.JSONDecodeError:
                                    pass
                        self.position = f.tell()

            except Exception as e:
                logger.debug(f"Tailer error ({self.label}): {e}")

            time.sleep(TAIL_INTERVAL)

    def stop(self):
        self.running = False


def on_alert_event(event: dict):
    """Called when a new alert arrives from alerts.jsonl."""
    # Augment with ML score
    if ml_scorer and ml_scorer.is_available():
        try:
            ml_result = ml_scorer.score(event, event.get("level", "low"))
            if ml_result:
                event["ml_score"] = ml_result.ml_score
                event["ml_score_pct"] = ml_result.ml_score_pct
                event["ml_confidence"] = ml_result.ml_confidence
                event["ml_top_features"] = ml_result.top_features
                event["augmented_level"] = ml_result.augmented_level
        except Exception as e:
            logger.debug(f"ML augmentation error: {e}")

    state.add_alert(event)

    # Push via WebSocket
    if socketio and SOCKETIO_AVAILABLE:
        try:
            socketio.emit("new_alert", event)
        except Exception:
            pass


def on_process_event(event: dict):
    """Called when a new process event arrives from process_events.jsonl.

    BUG 2 FIX: Previously this only appended to state.process_events and
    never updated any stats counters, so normal user activity was completely
    invisible in the dashboard's stats, timelines and frequency tables.
    Now delegates to state.add_process_event() which updates all counters.
    """
    state.add_process_event(event)   # updates process_freq, user_freq, timeline, etc.

    if socketio and SOCKETIO_AVAILABLE:
        try:
            socketio.emit("new_process", event)
        except Exception:
            pass


def on_temporal_event(event: dict):
    """Called when a new temporal behavior event arrives."""
    with state.lock:
        state.temporal_events.appendleft(event)

    if socketio and SOCKETIO_AVAILABLE:
        try:
            socketio.emit("new_temporal", event)
        except Exception:
            pass


# Tailers are created inside start_tailers() so they pick up the final
# LOG_FILES paths AFTER main() has applied --log-dir.  Declaring them here
# as None just keeps the module-level name available for stop logic.
alert_tailer = None
process_tailer = None
temporal_tailer = None
enriched_tailer = None   # Bug 4 fix: was never started


def start_tailers():
    # BUG 1 FIX: Create tailers HERE, after main() has updated LOG_FILES.
    # Previously tailers were created at module level and captured the
    # default paths, so --log-dir had zero effect on what files were watched.
    global alert_tailer, process_tailer, temporal_tailer, enriched_tailer

    alert_tailer    = FileTailer(LOG_FILES["alerts"],         on_alert_event,    "alerts",   backfill=200)
    process_tailer  = FileTailer(LOG_FILES["process_events"], on_process_event,  "process",  backfill=200)
    temporal_tailer = FileTailer(LOG_FILES["temporal"],       on_temporal_event, "temporal", backfill=50)
    enriched_tailer = FileTailer(LOG_FILES["enriched_events"],on_alert_event,    "enriched", backfill=0)

    alert_tailer.start()
    process_tailer.start()
    temporal_tailer.start()
    enriched_tailer.start()   # Bug 4 fix: was never started
    logger.info("File tailers started (watching: %s)", {k: v for k, v in LOG_FILES.items()})


# Stats broadcaster
def stats_broadcaster():
    while True:
        time.sleep(STATS_INTERVAL)
        if socketio and SOCKETIO_AVAILABLE:
            try:
                socketio.emit("stats_update", state.get_stats())
            except Exception:
                pass


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.route("/api/alerts")
def get_alerts():
    limit = int(request.args.get("limit", 50))
    level = request.args.get("level")
    return jsonify(state.get_alerts(limit=limit, level_filter=level))


@app.route("/api/stats")
def get_stats():
    return jsonify(state.get_stats())


@app.route("/api/events/process")
def get_process_events():
    limit = int(request.args.get("limit", 50))
    with state.lock:
        return jsonify(list(state.process_events)[:limit])


@app.route("/api/events/temporal")
def get_temporal_events():
    limit = int(request.args.get("limit", 50))
    with state.lock:
        return jsonify(list(state.temporal_events)[:limit])


@app.route("/api/ml/status")
def ml_status():
    if ml_scorer:
        return jsonify({"available": ml_scorer.is_available(), **ml_scorer.get_stats()})
    return jsonify({"available": False, "reason": "ML module not loaded"})


@app.route("/api/ml/score", methods=["POST"])
def ml_score_event():
    """Score an arbitrary event via ML."""
    if not ml_scorer or not ml_scorer.is_available():
        return jsonify({"error": "ML not available"}), 503
    event = request.json or {}
    result = ml_scorer.score(event, event.get("level", "low"))
    if result:
        return jsonify(result.to_dict())
    return jsonify({"error": "Scoring failed"}), 500


@app.route("/api/health")
def health():
    return jsonify({
        "status": "running",
        "uptime": int((datetime.now() - state.start_time).total_seconds()),
        "ml_available": bool(ml_scorer and ml_scorer.is_available()),
        "websocket_available": SOCKETIO_AVAILABLE,
        "watching_files": {k: Path(v).exists() for k, v in LOG_FILES.items()},
    })


# ---------------------------------------------------------------------------
# Serve dashboard frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    # Try to serve built React app, fall back to inline HTML
    dist = Path(__file__).parent / "dashboard_ui" / "dist" / "index.html"
    if dist.exists():
        return send_from_directory(str(dist.parent), "index.html")
    # Return embedded dashboard
    return serve_inline_dashboard()


def serve_inline_dashboard():
    """Serve the standalone dashboard HTML if no build exists."""
    html_path = Path(__file__).parent / "dashboard.html"
    if html_path.exists():
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard not found. Run: cp dashboard.html to working dir</h1>", 404


# ---------------------------------------------------------------------------
# WebSocket events
# ---------------------------------------------------------------------------

if SOCKETIO_AVAILABLE:
    @socketio.on("connect")
    def on_connect():
        logger.info(f"Dashboard client connected")
        # Send initial state
        emit("stats_update", state.get_stats())
        emit("initial_alerts", state.get_alerts(limit=50))

    @socketio.on("disconnect")
    def on_disconnect():
        logger.info("Dashboard client disconnected")

    @socketio.on("request_stats")
    def on_request_stats():
        emit("stats_update", state.get_stats())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Anti-Ransomware Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--log-dir", default=".", help="Directory containing .jsonl log files")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Update log file paths if log_dir specified
    if args.log_dir != ".":
        log_dir = Path(args.log_dir)
        for k, v in LOG_FILES.items():
            LOG_FILES[k] = str(log_dir / v)

    print("=" * 60)
    print("Anti-Ransomware Detection Dashboard")
    print("=" * 60)
    print(f"Dashboard:   http://{args.host}:{args.port}")
    print(f"API:         http://{args.host}:{args.port}/api/alerts")
    print(f"ML:          {'enabled' if (ml_scorer and ml_scorer.is_available()) else 'disabled (pip install scikit-learn)'}")
    print(f"WebSocket:   {'enabled' if SOCKETIO_AVAILABLE else 'disabled (pip install flask-socketio)'}")
    print("=" * 60)

    # Start background threads
    start_tailers()
    stats_thread = threading.Thread(target=stats_broadcaster, daemon=True, name="StatsBroadcaster")
    stats_thread.start()

    # Run server
    if SOCKETIO_AVAILABLE:
        socketio.run(app, host=args.host, port=args.port, debug=args.debug)
    else:
        app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()

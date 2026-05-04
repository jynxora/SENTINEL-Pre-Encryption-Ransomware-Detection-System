"""
Module 5: Evidence & Output Layer
===================================
Produces defensible, structured output from DecisionResult objects.
Generates:
  - alerts.jsonl        — machine-readable alert log
  - alert_report.html   — human-readable HTML report
  - summary.json        — campaign summary for analyst
  - STDOUT alerts       — colored console output

PHILOSOPHY:
  Every alert includes:
    1. What was detected (process + command)
    2. Why it's suspicious (tags + score breakdown)
    3. How confident we are (score + level)
    4. Whether YARA corroborated (with rule names)
    5. Whether ML augmented the decision
    6. What to do (recommended action)
    7. MITRE ATT&CK technique references

  This module is pure output — no detection logic.

USAGE:
    from output_layer import OutputLayer
    layer = OutputLayer(alert_log="alerts.jsonl")
    layer.emit(decision_result, ml_score=ml_result)
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
from collections import defaultdict

logger = logging.getLogger("OutputLayer")

# ANSI colors for terminal
try:
    import colorama
    colorama.init(autoreset=True)
    USE_COLOR = True
    R  = colorama.Fore.RED
    Y  = colorama.Fore.YELLOW
    G  = colorama.Fore.GREEN
    C  = colorama.Fore.CYAN
    M  = colorama.Fore.MAGENTA
    W  = colorama.Fore.WHITE
    DIM = colorama.Style.DIM
    BOLD = colorama.Style.BRIGHT
    RST = colorama.Style.RESET_ALL
except ImportError:
    USE_COLOR = False
    R = Y = G = C = M = W = DIM = BOLD = RST = ""

LEVEL_COLORS = {
    "low":      G,
    "medium":   Y,
    "high":     R,
    "critical": M,
}

LEVEL_ICONS = {
    "low":      "[LOW]     ",
    "medium":   "[MEDIUM]  ",
    "high":     "[HIGH]    ",
    "critical": "[CRITICAL]",
}

MITRE_MAP = {
    "shadow_copy_deletion":      "T1490 - Inhibit System Recovery",
    "boot_manipulation":         "T1490 - Inhibit System Recovery",
    "backup_deletion":           "T1490 - Inhibit System Recovery",
    "encryption_activity":       "T1486 - Data Encrypted for Impact",
    "credential_access_attempt": "T1003 - OS Credential Dumping",
    "lateral_movement":          "T1021 - Remote Services",
    "service_manipulation":      "T1489 - Service Stop",
    "network_share_discovery":   "T1135 - Network Share Discovery",
    "obfuscated_execution":      "T1027 - Obfuscated Files/Information",
    "persistence_attempt":       "T1547 - Boot/Logon Autostart Execution",
    "living_off_the_land":       "T1218 - System Binary Proxy Execution",
}


class OutputLayer:
    """
    Emits structured output for each DecisionResult.
    Thread-safe — can be called from multiple threads.
    """

    def __init__(
        self,
        alert_log: str = "alerts.jsonl",
        min_console_level: str = "medium",
        min_file_level: str = "low",
    ):
        self.alert_log = Path(alert_log)
        self.min_console_level = min_console_level
        self.min_file_level = min_file_level

        self._level_order = ["low", "medium", "high", "critical"]

        # In-memory stats
        self.total_emitted = 0
        self.level_counts = defaultdict(int)
        self.yara_hits_total = 0
        self.ml_elevations = 0

        import threading
        self._lock = threading.Lock()

    def emit(self, result, ml_score=None) -> dict:
        """
        Main emission method.
        
        Args:
            result:   DecisionResult from decision_engine.py
            ml_score: Optional MLScore from ml_scorer.py
        
        Returns:
            Enriched event dict written to disk and shown on console.
        """
        # Build enriched event dict
        event = self._build_event(result, ml_score)

        # Write to file (always, unless below file threshold)
        if self._level_gte(event["level"], self.min_file_level):
            self._write_to_file(event)

        # Print to console if above threshold
        if self._level_gte(event["level"], self.min_console_level):
            self._print_alert(event)

        # Stats
        with self._lock:
            self.total_emitted += 1
            self.level_counts[event["level"]] += 1
            if event.get("yara_hits"):
                self.yara_hits_total += 1
            if event.get("ml_elevated"):
                self.ml_elevations += 1

        return event

    def _build_event(self, result, ml_score) -> dict:
        """Merge DecisionResult + ML score into one output dict."""
        event = {
            # Identity
            "timestamp":        result.timestamp,
            "process_name":     result.process_name,
            "pid":              result.pid,
            "username":         result.username,
            "executable_path":  result.executable_path,
            "command_line":     result.command_line,

            # Detection
            "total_score":          result.total_score,
            "level":                result.level,
            "tags":                 result.tags,
            "ransomware_indicators": result.ransomware_indicators,
            "score_breakdown":      result.score_breakdown,

            # YARA
            "yara_triggered":     result.yara_triggered,
            "yara_trigger_reason": result.yara_trigger_reason,
            "yara_hits":          result.yara_hits,

            # Verdict
            "verdict":            result.verdict,
            "recommended_action": result.recommended_action,

            # MITRE techniques
            "mitre_techniques": list({
                MITRE_MAP[tag]
                for tag in (result.tags or [])
                if tag in MITRE_MAP
            }),
        }

        # Augment with ML if available
        if ml_score:
            event.update({
                "ml_score":        ml_score.ml_score,
                "ml_score_pct":    ml_score.ml_score_pct,
                "ml_confidence":   ml_score.ml_confidence,
                "ml_top_features": ml_score.top_features,
                "model_used":      ml_score.model_used,
                "augmented_level": ml_score.augmented_level,
                "ml_elevated":     ml_score.augmented_level != result.level,
            })
            # Use augmented level if elevated
            if ml_score.augmented_level and self._level_gte(ml_score.augmented_level, result.level):
                event["level"] = ml_score.augmented_level

        return event

    def _write_to_file(self, event: dict):
        """Append event as JSON line to alert log."""
        try:
            with self._lock:
                with open(self.alert_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write alert: {e}")

    def _print_alert(self, event: dict):
        """Print colored alert to console."""
        level = event["level"]
        color = LEVEL_COLORS.get(level, W)
        icon = LEVEL_ICONS.get(level, "[UNKNOWN] ")
        sep = "─" * 70

        lines = [
            f"\n{color}{BOLD}{sep}",
            f"{icon} {event['process_name']}  (PID {event['pid']})",
            f"{sep}{RST}",
            f"  {DIM}Time   :{RST} {event['timestamp']}",
            f"  {DIM}User   :{RST} {event['username'] or 'unknown'}",
            f"  {DIM}Cmd    :{RST} {C}{event['command_line'][:120]}{RST}",
            f"  {DIM}Score  :{RST} {color}{BOLD}{event['total_score']}{RST}  →  {color}{BOLD}{level.upper()}{RST}",
        ]

        # Score breakdown (top 3)
        if event.get("score_breakdown"):
            top = sorted(event["score_breakdown"], key=lambda x: x.get("weight",0), reverse=True)[:3]
            lines.append(f"  {DIM}Signals:{RST} " + "  ".join(
                f"{Y}+{b['weight']}{RST} {b['tag']}" for b in top
            ))

        # YARA
        if event.get("yara_hits"):
            lines.append(f"  {DIM}YARA   :{RST} {M}HIT → {', '.join(event['yara_hits'])}{RST}")

        # ML
        if event.get("ml_score_pct") is not None:
            ml_color = R if event["ml_score_pct"] > 70 else (Y if event["ml_score_pct"] > 40 else G)
            ml_str = f"{C}ML: {ml_color}{event['ml_score_pct']}%{RST} ({event.get('ml_confidence','?')})"
            if event.get("ml_elevated"):
                ml_str += f"  {Y}↑ ELEVATED to {event['level'].upper()}{RST}"
            lines.append(f"  {DIM}ML     :{RST} {ml_str}")

        # MITRE
        if event.get("mitre_techniques"):
            lines.append(f"  {DIM}MITRE  :{RST} {', '.join(event['mitre_techniques'])}")

        # Action
        lines.append(f"  {DIM}Action :{RST} {color}{BOLD}{event['recommended_action']}{RST}")
        lines.append(f"{color}{sep}{RST}")

        print("\n".join(lines), flush=True)

    def _level_gte(self, a: str, b: str) -> bool:
        try:
            return self._level_order.index(a) >= self._level_order.index(b)
        except ValueError:
            return False

    def get_stats(self) -> dict:
        return {
            "total_emitted":  self.total_emitted,
            "level_counts":   dict(self.level_counts),
            "yara_hits":      self.yara_hits_total,
            "ml_elevations":  self.ml_elevations,
        }

    def generate_summary(self, output_path: str = "alert_summary.json"):
        """Generate a JSON summary for analyst handoff."""
        summary = {
            "generated_at": datetime.now().isoformat(),
            "alert_log": str(self.alert_log),
            "statistics": self.get_stats(),
            "note": (
                "This summary was generated by SENTINEL — "
                "Human-Operated Ransomware Detection System. "
                "See alerts.jsonl for full event detail."
            ),
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Summary written to {output_path}")
        return summary


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from decision_engine import DecisionResult

    layer = OutputLayer(alert_log="test_alerts.jsonl", min_console_level="low")

    # Synthetic test result
    result = DecisionResult(
        timestamp=datetime.now().isoformat(),
        process_name="vssadmin.exe",
        pid=4321,
        username="CORP\\attacker",
        executable_path=r"C:\Windows\System32\vssadmin.exe",
        command_line="vssadmin delete shadows /all /quiet",
        total_score=66,
        level="critical",
        score_breakdown=[
            {"tag": "shadow_copy_deletion", "weight": 20, "rationale": "MITRE T1490"},
            {"tag": "backup_deletion",      "weight": 18, "rationale": "MITRE T1490"},
            {"tag": "boot_manipulation",    "weight": 20, "rationale": "MITRE T1490"},
        ],
        tags=["shadow_copy_deletion", "backup_deletion", "boot_manipulation", "ransomware_tool"],
        ransomware_indicators=["shadow_copy_deletion", "backup_deletion"],
        yara_triggered=True,
        yara_trigger_reason="Triggered: level=critical",
        yara_hits=["Ransomware_Generic", "LockBit_Shadow"],
        verdict="CRITICAL: Definitive ransomware indicators detected.",
        recommended_action="IMMEDIATE RESPONSE — isolate system and begin incident response.",
    )

    print("Output Layer — Demo")
    layer.emit(result)
    print("\nStats:", layer.get_stats())

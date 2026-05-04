"""
Module 3: Decision Engine
=========================
Receives tagged events from Module 2, applies weighted scoring against
RISK_THRESHOLDS, decides severity level, and — only when threshold is
crossed — triggers YARA for corroboration.

RESPONSIBILITIES:
  1. Compute a proper weighted score from tag weights (BEHAVIOR_TAGS)
  2. Map score → LOW / MEDIUM / HIGH / CRITICAL via RISK_THRESHOLDS
  3. Gate YARA: trigger only when score >= MEDIUM threshold
  4. Emit a structured DecisionResult (feeds Module 5)

WHAT THIS MODULE DOES NOT DO:
  - No tagging / pattern matching  (that is Module 2)
  - No telemetry capture           (that is Module 1)
  - No output formatting           (that is Module 5)
  - No deep temporal correlation   (future Module 6)

WIRING NOTE:
  YARA must be removed from process_monitor.py and called only here.
  See _trigger_yara() and the note at the bottom of this file.
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
import json

from behavior_tags import BEHAVIOR_TAGS, RISK_THRESHOLDS
from behavior_tagger import TaggedEvent

try:
    from signature_scanner import SignatureScanner
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Decision levels — mirrors RISK_THRESHOLDS keys for explicit mapping
# ---------------------------------------------------------------------------

LEVEL_LOW      = "low"
LEVEL_MEDIUM   = "medium"
LEVEL_HIGH     = "high"
LEVEL_CRITICAL = "critical"

# Minimum level at which YARA is triggered
YARA_TRIGGER_LEVEL = LEVEL_MEDIUM


# ---------------------------------------------------------------------------
# Output structure
# ---------------------------------------------------------------------------

@dataclass
class ScoreBreakdown:
    """Per-tag contribution to the total score."""
    tag: str
    weight: int
    rationale: str


@dataclass
class DecisionResult:
    """
    Structured output of the Decision Engine.
    Consumed by Module 5 (Evidence & Output Layer).
    """
    # Identity
    timestamp: str
    process_name: str
    pid: int
    username: Optional[str]
    executable_path: Optional[str]
    command_line: str

    # Scoring
    total_score: int
    level: str                              # low / medium / high / critical
    score_breakdown: list                   # List[ScoreBreakdown] as dicts

    # Tags from Module 2
    tags: list
    ransomware_indicators: list

    # YARA
    yara_triggered: bool
    yara_trigger_reason: str               # Why YARA was (or wasn't) called
    yara_hits: list                        # Rule names that matched

    # Verdict
    verdict: str                           # Human-readable single sentence
    recommended_action: str

    def to_json_line(self) -> str:
        return json.dumps(asdict(self))


# ---------------------------------------------------------------------------
# Verdict templates per level
# ---------------------------------------------------------------------------

_VERDICTS = {
    LEVEL_LOW: (
        "No significant ransomware indicators detected.",
        "Log and continue monitoring."
    ),
    LEVEL_MEDIUM: (
        "Suspicious activity detected — multiple weak signals present.",
        "Flag for analyst review within 24 hours."
    ),
    LEVEL_HIGH: (
        "Strong ransomware indicators detected — likely malicious activity.",
        "Priority investigation required within 4 hours."
    ),
    LEVEL_CRITICAL: (
        "CRITICAL: Definitive ransomware indicators detected.",
        "IMMEDIATE RESPONSE — isolate system and begin incident response."
    ),
}


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class DecisionEngine:
    """
    The single decision point in the pipeline.

    Usage:
        engine = DecisionEngine(rules_dir="rules/")
        result = engine.evaluate(tagged_event, executable_path="C:\\...")
    """

    def __init__(self, rules_dir: str = "rules/", yara_timeout: int = 30):
        self.logger = logging.getLogger("DecisionEngine")

        # YARA scanner — instantiated once, reused for every triggered scan
        self._scanner: Optional[SignatureScanner] = None
        if YARA_AVAILABLE:
            try:
                self._scanner = SignatureScanner(
                    rules_dir=rules_dir,
                    timeout=yara_timeout
                )
                self.logger.info("YARA scanner ready")
            except Exception as exc:
                self.logger.warning(f"YARA scanner failed to initialise: {exc}")
        else:
            self.logger.warning(
                "signature_scanner not importable — YARA corroboration disabled"
            )

        # Stats
        self._evaluated = 0
        self._yara_triggered = 0
        self._yara_hits = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        event: TaggedEvent,
        executable_path: Optional[str] = None
    ) -> DecisionResult:
        """
        Core evaluation method.

        Args:
            event:           TaggedEvent from Module 2 (behavior_tagger)
            executable_path: Path to the process executable for YARA scanning.
                             Comes from ProcessEvent.executable_path — pass it
                             through from Module 1 via the coordinator.

        Returns:
            DecisionResult ready for Module 5.
        """
        self._evaluated += 1

        # Step 1: Compute weighted score from tags
        total_score, breakdown = self._compute_score(event.tags)

        # Step 2: Map score → level
        level = self._score_to_level(total_score)

        # Step 3: Gate YARA on level
        yara_hits, yara_triggered, yara_reason = self._trigger_yara(
            level, executable_path, event.process_name
        )

        # Step 4: Elevate level if YARA found a match
        if yara_hits:
            level = self._elevate_on_yara(level)

        # Step 5: Build verdict
        verdict, action = _VERDICTS[level]

        self.logger.info(
            f"[{level.upper():8s}] score={total_score:3d} | "
            f"yara={'HIT' if yara_hits else ('scan' if yara_triggered else 'skip'):4s} | "
            f"{event.process_name} (PID {event.pid})"
        )

        return DecisionResult(
            timestamp=event.timestamp,
            process_name=event.process_name,
            pid=event.pid,
            username=event.username,
            executable_path=executable_path,
            command_line=event.command_line,
            total_score=total_score,
            level=level,
            score_breakdown=[asdict(b) for b in breakdown],
            tags=event.tags,
            ransomware_indicators=event.ransomware_indicators,
            yara_triggered=yara_triggered,
            yara_trigger_reason=yara_reason,
            yara_hits=yara_hits,
            verdict=verdict,
            recommended_action=action,
        )

    def get_stats(self) -> dict:
        return {
            "evaluated": self._evaluated,
            "yara_triggered": self._yara_triggered,
            "yara_hits": self._yara_hits,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_score(
        self, tags: list
    ) -> tuple[int, list]:
        """
        Walk the event's tags and sum weights from BEHAVIOR_TAGS.

        Tags that have no entry in BEHAVIOR_TAGS contribute 0 (they are
        classification labels, not scored signals).

        Returns (total_score, breakdown_list).
        """
        total = 0
        breakdown = []

        for tag in tags:
            tag_def = BEHAVIOR_TAGS.get(tag)
            if tag_def is None:
                continue  # classification label — no score contribution

            weight = tag_def.get("weight", 0)
            rationale = tag_def.get("rationale", "")
            total += weight
            breakdown.append(ScoreBreakdown(
                tag=tag,
                weight=weight,
                rationale=rationale
            ))

        # Sort breakdown highest-weight first — makes the evidence report readable
        breakdown.sort(key=lambda b: b.weight, reverse=True)
        return total, breakdown

    def _score_to_level(self, score: int) -> str:
        """
        Map numeric score to level string using RISK_THRESHOLDS.
        Thresholds are lower bounds:
            critical >= 40
            high     >= 25
            medium   >= 15
            low      <  15
        """
        if score >= RISK_THRESHOLDS[LEVEL_CRITICAL]:
            return LEVEL_CRITICAL
        if score >= RISK_THRESHOLDS[LEVEL_HIGH]:
            return LEVEL_HIGH
        if score >= RISK_THRESHOLDS[LEVEL_MEDIUM]:
            return LEVEL_MEDIUM
        return LEVEL_LOW

    def _trigger_yara(
        self,
        level: str,
        executable_path: Optional[str],
        process_name: str,
    ) -> tuple[list, bool, str]:
        """
        Decide whether to run YARA and run it if so.

        YARA is triggered when:
          - Level is MEDIUM or above (behaviour has already crossed a threshold)
          - An executable path is available
          - The scanner is initialised

        Returns (hits, was_triggered, reason_string).
        """
        level_order = [LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL]

        def _level_gte(a: str, b: str) -> bool:
            return level_order.index(a) >= level_order.index(b)

        # --- Guard: level too low ---
        if not _level_gte(level, YARA_TRIGGER_LEVEL):
            return [], False, f"Score below YARA threshold (level={level})"

        # --- Guard: no path ---
        if not executable_path:
            return [], False, "No executable path available for scanning"

        # --- Guard: scanner unavailable ---
        if self._scanner is None:
            return [], False, "YARA scanner not available (yara-python not installed)"

        # --- Scan ---
        self._yara_triggered += 1
        reason = f"Triggered: level={level}, path={executable_path}"
        try:
            hits = self._scanner.scan(executable_path)
            if hits:
                self._yara_hits += 1
                self.logger.warning(
                    f"[YARA HIT] {process_name} → {hits}"
                )
            return hits, True, reason
        except Exception as exc:
            self.logger.error(f"YARA scan error for {executable_path}: {exc}")
            return [], True, f"{reason} — scan error: {exc}"

    @staticmethod
    def _elevate_on_yara(level: str) -> str:
        """
        If YARA found a match, elevate level by one step.
        CRITICAL stays CRITICAL.
        """
        promotion = {
            LEVEL_LOW:      LEVEL_MEDIUM,
            LEVEL_MEDIUM:   LEVEL_HIGH,
            LEVEL_HIGH:     LEVEL_CRITICAL,
            LEVEL_CRITICAL: LEVEL_CRITICAL,
        }
        return promotion.get(level, level)


# ---------------------------------------------------------------------------
# WIRING NOTE — remove YARA from process_monitor.py
# ---------------------------------------------------------------------------
#
# In process_monitor.py, delete:
#
#   from signature_scanner import SignatureScanner          # line ~14
#   self.signature_scanner = SignatureScanner(...)          # line ~60
#   if self.signature_scanner and event.executable_path:   # line ~120
#       ... (the entire YARA block inside _create_event)
#
# The executable_path is already captured in ProcessEvent and passed through
# to the coordinator, which hands it to DecisionEngine.evaluate().
# YARA now runs only after Module 2 has scored the event.
#
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from datetime import datetime

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    engine = DecisionEngine(rules_dir="rules/")

    # Three test cases from the validation samples in behavior_tags.py
    TEST_CASES = [
        {
            # shadow_copy_deletion(20) + backup_deletion(18) + boot_manipulation(20)
            # + service_manipulation(8) = 66 → CRITICAL
            "name": "Full ransomware prep chain (critical)",
            "event": TaggedEvent(
                timestamp=datetime.now().isoformat(),
                process_name="vssadmin.exe",
                pid=1001,
                command_line="vssadmin delete shadows /all /quiet",
                username="CORP\\attacker",
                parent_process_name="cmd.exe",
                tags=["system_utility", "backup_manipulation", "ransomware_tool",
                      "shadow_copy_deletion", "backup_deletion",
                      "boot_manipulation", "service_manipulation"],
                confidence="high",
                ransomware_indicators=["ransomware_tool:vssadmin.exe",
                                       "shadow_copy_deletion", "backup_deletion",
                                       "boot_manipulation"],
                ransomware_score=60,
            ),
            "exe": None,
            "expected_level": "critical",   # score=66
        },
        {
            # shadow_copy_deletion(20) + backup_deletion(18) = 38 → HIGH
            "name": "LockBit shadow copy + backup deletion (high)",
            "event": TaggedEvent(
                timestamp=datetime.now().isoformat(),
                process_name="vssadmin.exe",
                pid=1002,
                command_line="vssadmin delete shadows /all /quiet",
                username="CORP\\attacker",
                parent_process_name="cmd.exe",
                tags=["system_utility", "backup_manipulation", "ransomware_tool",
                      "shadow_copy_deletion", "backup_deletion"],
                confidence="high",
                ransomware_indicators=["ransomware_tool:vssadmin.exe",
                                       "shadow_copy_deletion", "backup_deletion"],
                ransomware_score=38,
            ),
            "exe": None,
            "expected_level": "high",       # score=38
        },
        {
            # boot_manipulation(20) = 20 → MEDIUM
            "name": "Ryuk boot manipulation alone (medium)",
            "event": TaggedEvent(
                timestamp=datetime.now().isoformat(),
                process_name="bcdedit.exe",
                pid=1003,
                command_line="bcdedit /set {default} recoveryenabled no",
                username="CORP\\attacker",
                parent_process_name="cmd.exe",
                tags=["system_utility", "boot_configuration",
                      "ransomware_tool", "boot_manipulation"],
                confidence="high",
                ransomware_indicators=["ransomware_tool:bcdedit.exe", "boot_manipulation"],
                ransomware_score=20,
            ),
            "exe": None,
            "expected_level": "medium",     # score=20
        },
        {
            # obfuscated_execution(4) + credential_access_attempt(10)
            # + interactive_shell(1) = 15 → MEDIUM
            "name": "Encoded PowerShell + credential access (medium)",
            "event": TaggedEvent(
                timestamp=datetime.now().isoformat(),
                process_name="powershell.exe",
                pid=1004,
                command_line="powershell.exe -enc VGVzdA==",
                username="CORP\\user1",
                parent_process_name="winword.exe",
                tags=["interactive_shell", "script_engine", "living_off_the_land",
                      "obfuscated_execution", "credential_access_attempt",
                      "document_spawned_process", "suspicious_parent_child"],
                confidence="high",
                ransomware_indicators=[],
                ransomware_score=0,
            ),
            "exe": None,
            "expected_level": "medium",     # score=15
        },
        {
            # interactive_shell(1) only = 1 → LOW
            "name": "Normal PowerShell (low)",
            "event": TaggedEvent(
                timestamp=datetime.now().isoformat(),
                process_name="powershell.exe",
                pid=1005,
                command_line="powershell.exe Get-Process",
                username="CORP\\user2",
                parent_process_name="explorer.exe",
                tags=["interactive_shell", "script_engine"],
                confidence="low",
                ransomware_indicators=[],
                ransomware_score=0,
            ),
            "exe": None,
            "expected_level": "low",        # score=1
        },
    ]

    print("=" * 70)
    print("Decision Engine — Self Test")
    print("=" * 70)

    passed = 0
    for tc in TEST_CASES:
        result = engine.evaluate(tc["event"], executable_path=tc["exe"])
        ok = result.level == tc["expected_level"]
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1

        print(f"\n[{status}] {tc['name']}")
        print(f"       Score : {result.total_score}")
        print(f"       Level : {result.level}  (expected: {tc['expected_level']})")
        print(f"       YARA  : triggered={result.yara_triggered} | {result.yara_trigger_reason}")
        print(f"       Top signals:")
        for b in result.score_breakdown[:3]:
            print(f"         +{b['weight']:2d}  {b['tag']}")
        print(f"       Verdict: {result.verdict}")
        print(f"       Action : {result.recommended_action}")

    print(f"\n{'='*70}")
    print(f"Results: {passed}/{len(TEST_CASES)} passed")
    print(f"Engine stats: {engine.get_stats()}")
    print("=" * 70)

    sys.exit(0 if passed == len(TEST_CASES) else 1)

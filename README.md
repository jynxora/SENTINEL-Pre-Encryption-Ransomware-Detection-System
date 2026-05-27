# SENTINEL
**Pre-Encryption Human-Operated Ransomware (HoR) Detection System**

SENTINEL monitors Windows hosts for attacker behavior *before* the encryption payload executes — catching the reconnaissance, staging, and anti-recovery commands that operators run in the minutes to hours preceding file encryption. It combines real-time process telemetry, weighted behavioral tagging, temporal pattern correlation, YARA signature scanning, ML anomaly scoring, and a live browser dashboard into a single deployable Python system.

> **Philosophy:** Ransomware operators are human. Humans leave command-line footprints. SENTINEL detects the footprints.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Detection Pipeline](#detection-pipeline)
  - [Module 1 — Process Monitor](#module-1--process-monitor)
  - [Module 2 — Behavior Tagger](#module-2--behavior-tagger)
  - [Module 3 — Temporal Observers](#module-3--temporal-observers)
  - [Module 4 — Decision Engine](#module-4--decision-engine)
  - [Module 5 — ML Anomaly Scorer](#module-5--ml-anomaly-scorer)
  - [Module 6 — Evidence & Output Layer](#module-6--evidence--output-layer)
- [YARA Signatures](#yara-signatures)
- [Scoring & Risk Thresholds](#scoring--risk-thresholds)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Running SENTINEL](#running-sentinel)
- [Dashboard](#dashboard)
- [Output Files](#output-files)
- [Tuning & Calibration](#tuning--calibration)
- [Visual POC](#visual-poc)
- [Limitations](#limitations)
- [Ransomware Families Covered](#ransomware-families-covered)
- [Contributing](#contributing)

---

## Overview

Human-Operated Ransomware (HoR) attacks — LockBit, BlackCat/ALPHV, Conti, REvil, Ryuk — share a consistent pre-encryption playbook:

| Stage | Typical Commands | MITRE |
|---|---|---|
| Discovery | `net view`, `net share`, `ipconfig /all`, `whoami /all` | T1135, T1033 |
| Credential Access | `mimikatz`, `procdump lsass`, `reg save HKLM\SAM` | T1003 |
| Anti-Recovery | `vssadmin delete shadows /all /quiet` | T1490 |
| Boot Sabotage | `bcdedit /set {default} bootstatuspolicy ignoreallfailures` | T1490 |
| Backup Deletion | `wbadmin delete catalog -quiet` | T1490 |
| Lateral Movement | `psexec \\target`, `wmic /node: process call create` | T1021 |
| Persistence | Registry Run keys, scheduled tasks | T1547 |

SENTINEL intercepts every process creation on the Windows host, scores the command line in real time, and raises structured alerts before a single file is encrypted. At `CRITICAL` level, the system recommends immediate isolation.

---

## Features

- **6-layer detection pipeline** — telemetry → tagging → temporal correlation → decision engine → ML scoring → output
- **Weighted behavioral scoring** — 40+ behavior tags with per-tag weights, scoped to `event` or `session`
- **Temporal pattern detection** — privilege escalation, lateral movement, mass file I/O, and ransom note drops tracked over sliding time windows
- **YARA corroboration** — triggered only after rule-engine crosses `MEDIUM` threshold; 8 rule files covering 9 ransomware families
- **ML augmentation** — `IsolationForest` + `GradientBoostingClassifier` ensemble; <5ms per event; <20MB footprint
- **4 alert levels** — `LOW / MEDIUM / HIGH / CRITICAL` with defined response SLAs
- **MITRE ATT&CK mapping** — every tag resolves to a technique ID
- **Live browser dashboard** — Flask + WebSocket; real-time event stream, stats, ML scores
- **Machine-readable output** — `alerts.jsonl` + `alert_summary.json` for SIEM/SOAR integration
- **Zero kernel-mode code** — pure Python, WMI, and Win32 APIs; deployable without driver signing
- **Exclusion rules** — known-good patterns whitelist to suppress Windows Update, scheduled tasks, and admin tooling

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Windows Host                                  │
│                   Process Creation Events                           │
└────────────────────────┬────────────────────────────────────────────┘
                         │ WMI Win32_Process.watch_for("creation")
┌────────────────────────▼────────────────────────────────────────────┐
│  Module 1: Process Monitor   (process_monitor.py)                   │
│  - Captures: name, PID, PPID, command line, user, executable path   │
│  - Resolves: parent process name + command line                     │
│  - Auto-reconnects on WMI failure                                   │
│  → process_events.jsonl                                             │
└──────────────┬─────────────────────────────┬───────────────────────┘
               │                             │
┌──────────────▼──────────────┐  ┌───────────▼───────────────────────┐
│  Module 2: Behavior Tagger  │  │  Module 3: Temporal Observers      │
│  (behavior_tagger.py)       │  │  (temporal_observers.py)           │
│                             │  │                                    │
│  Per-event:                 │  │  Over sliding time windows:        │
│  - Tool classification      │  │  - PrivilegeEscalationObserver     │
│  - Command pattern matching │  │  - LateralMovementObserver         │
│  - Parent-child analysis    │  │  - FileIOObserver (ReadDirChanges) │
│  - Session accumulation     │  │  - RansomNoteScanner               │
│  - Exclusion filtering      │  │                                    │
│  → enriched_events.jsonl    │  │  → temporal_behaviors.jsonl        │
└──────────────┬──────────────┘  └───────────┬───────────────────────┘
               │                             │
               └──────────────┬──────────────┘
┌─────────────────────────────▼───────────────────────────────────────┐
│  Module 4: Decision Engine   (decision_engine.py)                   │
│                                                                     │
│  1. Weighted score  = Σ(tag_weight × tag_present)                   │
│  2. score → level  : low(5) / medium(15) / high(25) / critical(40) │
│  3. YARA gate       : triggered iff level ≥ MEDIUM                  │
│  4. YARA elevation  : matching rule can push level to HIGH/CRITICAL  │
│  → DecisionResult (structured dataclass)                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│  Module 5: ML Anomaly Scorer  (ml_scorer.py)                        │
│                                                                     │
│  IsolationForest  +  GradientBoostingClassifier                     │
│  Feature vector: process risk score, tag count, session depth,      │
│  command entropy, suspicious keyword count, parent risk, …          │
│  → MLScore (ml_score 0–100, ml_confidence, top_features)           │
│  → Can elevate level if ML score diverges from rule score           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│  Module 6: Evidence & Output Layer  (output_layer.py)               │
│                                                                     │
│  - Colored console alerts (ANSI)                                    │
│  - alerts.jsonl  (machine-readable, SIEM-ready)                     │
│  - alert_summary.json  (analyst handoff)                            │
│  - MITRE ATT&CK technique cross-reference                           │
│  - Recommended action per severity level                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────┐
│  Dashboard Server  (dashboard_server.py  +  dashboard.html)         │
│  Flask + WebSocket — http://localhost:5000                          │
│  Live event stream, ML scores, severity distribution, stats panel  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detection Pipeline

### Module 1 — Process Monitor

`process_monitor.py` subscribes to WMI `Win32_Process` creation events using a polling watcher (`timeout_ms=100`). For every new process it resolves:

- Process name, PID, command line, executable path
- Owner (domain\username) via `GetOwner()`
- Parent process name and command line (for parent-child analysis)

The module is **pure telemetry** — no detection logic. Events are appended to `process_events.jsonl` as JSON Lines for downstream consumption. Administrator privileges are required for full telemetry; the module degrades gracefully without them.

**Resilience:** Automatic WMI reconnection with configurable retry delay. The watcher loop restarts transparently after transient WMI service failures.

---

### Module 2 — Behavior Tagger

`behavior_tagger.py` processes the event stream from Module 1 and attaches a list of behavior tags to each event. Tagging operates in three layers:

**Tool classification** — O(1) lookup against a static dictionary of 30+ known executables. Each tool carries one or more class labels (`interactive_shell`, `script_engine`, `ransomware_tool`, `download_capable`, etc.).

**Command pattern matching** — Regex and substring matching against the full command line for ransomware-specific patterns:

| Pattern Category | Example Patterns Detected |
|---|---|
| Shadow copy deletion | `vssadmin delete shadows`, `wmic shadowcopy delete` |
| Boot manipulation | `bcdedit /set`, `bootstatuspolicy ignoreallfailures`, `recoveryenabled no` |
| Backup deletion | `wbadmin delete catalog`, `wbadmin delete backup` |
| Credential access | `mimikatz`, `procdump.*lsass`, `reg save HKLM\SAM` |
| Obfuscation | Base64 `-EncodedCommand`, `-Enc `, `FromBase64String` |
| Network discovery | `net view`, `net share`, `arp -a` |
| Lateral movement | `psexec`, `wmic /node:`, `winrm`, `Enter-PSSession` |
| Persistence | Registry Run key writes, `schtasks /create` |
| Service manipulation | `sc stop`, `net stop`, `taskkill` targeting AV/backup services |

**Session accumulation** — A per-user session state tracks the count of shells, LOLBins, ransomware-tool uses, and shadow copy operations in the current session window. Accumulated counts trigger session-scoped tags (`multiple_ransomware_indicators`, `multiple_ransomware_tools`, `repeated_shell_activity`).

**Exclusion filtering** — Known-good patterns (Windows Update, System32 scheduled maintenance, whitelisted admin scripts) are stripped before scoring to reduce false positives.

Output: `TaggedEvent` (original process fields + `tags: List[str]` + `confidence` + `ransomware_indicators` subset).

---

### Module 3 — Temporal Observers

`temporal_observers.py` runs four concurrent observers that detect behaviors visible only *over time*, not in a single process creation event.

**PrivilegeEscalationObserver** — Reads the Windows integrity level token of every process via `win32security`. Flags transitions from Medium → High/System integrity that aren't explainable by known-system parent processes (e.g., WerFault, TiWorker). The known-system-parent whitelist prevents alerting on legitimate OS-elevated child processes.

**LateralMovementObserver** — Monitors for PsExec execution, `wmic /node:` remote process creation, WinRM (`winrs`, `Enter-PSSession`), and SMB admin share access patterns (`\\target\C$`, `\\target\ADMIN$`). A sliding 5-minute window counts lateral tool executions; exceeding the threshold fires a `HIGH` behavior event.

**FileIOObserver** — Uses `ReadDirectoryChangesW` on user-writeable paths to count file creation, modification, rename, and deletion events. Mass-rename patterns (e.g., thousands of files gaining a new extension within seconds) and mass-deletion are flagged as pre-encryption staging behavior.

**RansomNoteScanner** — Scans newly created `.txt` and `.html` files for ransom note content markers (`decrypt`, `bitcoin`, `YOUR FILES ARE ENCRYPTED`, BTC address patterns, `.onion` URLs). A match fires an immediate `CRITICAL` behavior event — if a note has been dropped, encryption may already be underway.

All four observers emit `BehaviorEvent` objects to `temporal_behaviors.jsonl` for Campaign Correlator consumption.

---

### Module 4 — Decision Engine

`decision_engine.py` is the scoring and verdict layer. It receives `TaggedEvent` objects and produces a `DecisionResult`.

**Scoring formula:**

```
total_score = Σ BEHAVIOR_TAGS[tag]["weight"]  for each tag in event.tags
```

Tag weights range from 1 (weak signal, e.g. `interactive_shell`) to 20 (definitive indicator, e.g. `shadow_copy_deletion`).

**Level mapping:**

| Score | Level | SLA |
|---|---|---|
| ≥ 5 | `LOW` | Log and accumulate |
| ≥ 15 | `MEDIUM` | Analyst review within 24 hours |
| ≥ 25 | `HIGH` | Priority investigation within 4 hours |
| ≥ 40 | `CRITICAL` | Immediate response — isolate system |

**YARA gate** — YARA scanning is *not* run on every process. It is triggered only when `score ≥ MEDIUM threshold`. This keeps the hot path free of file I/O overhead for benign events. When YARA fires, matching rule names are attached to the `DecisionResult` and can elevate the alert level by one step.

**Critical fast-path** — Any single event bearing `shadow_copy_deletion`, `boot_manipulation`, or `backup_deletion` immediately satisfies the CRITICAL threshold regardless of accumulated score.

---

### Module 5 — ML Anomaly Scorer

`ml_scorer.py` augments the rule-based decision with an ML layer. It runs after the Decision Engine and can *elevate* (but never suppress) the rule-based level.

**Models:**
- `IsolationForest` — unsupervised anomaly detector; identifies process vectors that are statistically unusual relative to the training baseline
- `GradientBoostingClassifier` — supervised binary classifier trained on labeled benign/malicious examples

**Feature vector (extracted from `TaggedEvent` + process telemetry):**

| Feature Group | Examples |
|---|---|
| Process identity | Per-process risk score (vssadmin=90, bcdedit=85, powershell=30) |
| Behavioral | Tag count, ransomware indicator count, session depth |
| Command line | Entropy, length, suspicious keyword hits, base64 presence |
| Lineage | Parent process risk score |
| Temporal | Events in last 60s, 300s |

Output: `MLScore` (ml_score 0–100, ml_score_pct, ml_confidence, top contributing features, model used, augmented_level). The model is persisted to `ml_model.pkl` and loaded at startup.

**Design constraints:** <5ms per event latency; <20MB memory footprint; no network calls; pure Python.

---

### Module 6 — Evidence & Output Layer

`output_layer.py` is pure output — no detection logic. It consumes `DecisionResult + MLScore` and produces:

**Colored console alerts** — ANSI-colored terminal output with score breakdown (top 3 contributing tags), YARA hit names, ML score percentage, MITRE technique IDs, and recommended action. Minimum console level is configurable (default: `MEDIUM`).

**`alerts.jsonl`** — One JSON object per alert. Fields include all process telemetry, full tag list, score breakdown, YARA hits, ML features, MITRE techniques, and recommended action. Structured for direct ingestion into Splunk, Elastic SIEM, or any JSONL-capable pipeline.

**`alert_summary.json`** — Session-level summary: total events, level distribution, YARA hit count, ML elevation count. Written on graceful shutdown.

**MITRE mapping** — Tags resolve to technique IDs automatically:

| Tag | MITRE Technique |
|---|---|
| `shadow_copy_deletion` | T1490 — Inhibit System Recovery |
| `encryption_activity` | T1486 — Data Encrypted for Impact |
| `credential_access_attempt` | T1003 — OS Credential Dumping |
| `lateral_movement` | T1021 — Remote Services |
| `service_manipulation` | T1489 — Service Stop |
| `network_share_discovery` | T1135 — Network Share Discovery |
| `obfuscated_execution` | T1027 — Obfuscated Files/Information |
| `persistence_attempt` | T1547 — Boot/Logon Autostart Execution |
| `living_off_the_land` | T1218 — System Binary Proxy Execution |

---

## YARA Signatures

Rules are stored in `rules/` and compiled once at startup. The scanner runs against the process executable path when the Decision Engine gates it.

| File | Family | Key Indicators |
|---|---|---|
| `lockbit.yar` | LockBit 3.0 / 4.0 | PE code patterns, `LockBit` strings, `.lockbit` extension, `UNIQUE_ID_DO_NOT_REMOVE` mutex |
| `blackcat.yar` | BlackCat / ALPHV | Rust artifact `/rust/`, `ALPHV` strings, `enable_esxi_vm_kill`, `.alphv` extension |
| `conti.yar` | Conti | MurmurHash2 bytecode, Conti strings, BTC markers |
| `command_abuse.yar` | Generic HoR | Command-line strings: `vssadmin delete shadows`, `bcdedit /set`, `wbadmin delete catalog`, taskkill service stops |
| `additional_ransomware_rules.yar` | REvil, Maze/Egregor, Cuba, Play, Akira | RC4/Salsa20 bytecode, ransom note markers, mutex patterns, config structure markers |

**Updating rules:** Drop new `.yar` files into `rules/` and restart SENTINEL. The `SignatureScanner` compiles all `.yar` files in the directory at init. Recommended quarterly update sources:
- https://github.com/reversinglabs/reversinglabs-yara-rules
- https://github.com/Yara-Rules/rules
- https://malpedia.caad.fkie.fraunhofer.de/
- https://www.ransomware.live/

---

## Scoring & Risk Thresholds

```
LOW      score ≥  5   →  Log only
MEDIUM   score ≥ 15   →  Analyst review / YARA gate opens
HIGH     score ≥ 25   →  Priority investigation
CRITICAL score ≥ 40   →  Immediate isolation recommended
```

**Selected tag weights (full list in `behavior_tags.py`):**

| Tag | Weight | Scope |
|---|---|---|
| `shadow_copy_deletion` | 20 | event |
| `boot_manipulation` | 20 | event |
| `backup_deletion` | 18 | event |
| `encryption_activity` | 16 | event |
| `credential_access_attempt` | 14 | event |
| `lateral_movement` | 12 | event |
| `obfuscated_execution` | 4 | event |
| `multiple_ransomware_indicators` | 10 | session |
| `living_off_the_land` / `lolbin_abuse` | 3 | event |
| `interactive_shell` | 1 | session |

A single `vssadmin delete shadows /all /quiet` command yields:
`shadow_copy_deletion (20) + backup_deletion (18) + boot_manipulation (20) + ransomware_tool (8) = 66 → CRITICAL`

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection Method |
|---|---|---|
| Inhibit System Recovery | T1490 | Tag: `shadow_copy_deletion`, `boot_manipulation`, `backup_deletion`; YARA: `command_abuse.yar` |
| Data Encrypted for Impact | T1486 | Tag: `encryption_activity`; YARA: family rules |
| OS Credential Dumping | T1003 | Tag: `credential_access_attempt`; command pattern matching |
| Remote Services | T1021 | Tag: `lateral_movement`; Temporal: `LateralMovementObserver` |
| Service Stop | T1489 | Tag: `service_manipulation`; `sc stop` / `net stop` patterns |
| Network Share Discovery | T1135 | Tag: `network_share_discovery`; `net view` / `net share` patterns |
| Obfuscated Files/Information | T1027 | Tag: `obfuscated_execution`; Base64 / encoded command detection |
| Boot/Logon Autostart | T1547 | Tag: `persistence_attempt`; Registry run key / schtasks patterns |
| System Binary Proxy Execution | T1218 | Tag: `living_off_the_land`; LOLBin classification |
| Access Token Manipulation | T1134 | Temporal: `PrivilegeEscalationObserver` |

---

## Project Structure

```
sentinel/
│
├── integrated_detection_system.py  Main orchestrator — wires all modules together
├── process_monitor.py              Module 1: WMI process capture
├── behavior_tagger.py              Module 2: Per-event behavioral tagging + session state
├── temporal_observers.py           Module 3: Time-window behavior detection (4 observers)
├── decision_engine.py              Module 4: Weighted scoring, YARA gating, verdict
├── ml_scorer.py                    Module 5: IsolationForest + GradientBoosting ML layer
├── output_layer.py                 Module 6: Console + JSONL + summary output
├── behavior_tags.py                Tag taxonomy, weights, thresholds, exclusion rules
├── signature_scanner.py            YARA wrapper (compiles rules/, scans executables)
├── dashboard_server.py             Flask + WebSocket live dashboard backend
├── dashboard.html                  Single-page browser dashboard
├── generate_test_data.py           Synthetic event generator for testing/tuning
│
├── rules/
│   ├── lockbit.yar                 LockBit 3.0 / 4.0 signatures
│   ├── blackcat.yar                BlackCat / ALPHV signatures
│   ├── conti.yar                   Conti signatures
│   ├── command_abuse.yar           Generic HoR command-line patterns
│   └── additional_ransomware_rules.yar  REvil, Maze, Cuba, Play, Akira
│
├── ml_model.pkl                    Serialized ML models (auto-generated on first run)
├── process_events.jsonl            Raw process telemetry (Module 1 output)
├── enriched_events.jsonl           Tagged events (Module 2 output)
├── temporal_behaviors.jsonl        Temporal behavior events (Module 3 output)
├── alerts.jsonl                    Final alerts (Module 6 output) — SIEM ingest target
├── alert_summary.json              Session-level analyst summary
└── integrated_detection.log        System debug log
```

---

## Installation

### Prerequisites

- Windows 10 / 11 or Windows Server 2019 / 2022
- Python **3.10 or later** (3.12 recommended)
- **Administrator privileges** (required for WMI process telemetry and integrity level reads)
- WMI service running: `net start winmgmt`

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/jynxora/sentinel.git
cd sentinel
```

```bash
# 2. Install Python dependencies
pip install -r requirements.txt
```

**`requirements.txt`:**
```
wmi
pywin32
psutil
yara-python
scikit-learn
joblib
flask
flask-cors
flask-socketio
colorama
```

```bash
# 3. Verify YARA rule compilation (optional sanity check)
python -c "from signature_scanner import SignatureScanner; s = SignatureScanner('rules/'); print('YARA OK')"
```

```bash
# 4. (Optional) Pre-train the ML model
python ml_scorer.py
# Model saved to ml_model.pkl — this step is skipped on subsequent runs
```

> **Note:** `temporal_observers.py` requires `win32security`, `win32api`, `win32file` from the `pywin32` package. On some systems `pywin32` post-install scripts must be run manually:
> `python Scripts/pywin32_postinstall.py -install`

---

## Running SENTINEL

### Full integrated system (recommended)

```bash
# Run as Administrator
python integrated_detection_system.py
```

This starts all modules in coordinated threads:
- Module 1 WMI watcher
- Module 2 tagger (queue-based, non-blocking)
- Module 3 temporal observers (background threads)
- Module 4+5+6 on every enriched event

Stop with `Ctrl+C` — graceful shutdown writes `alert_summary.json`.

### Dashboard (companion process)

```bash
# In a second terminal (also as Administrator)
python dashboard_server.py
# Open http://localhost:5000
```

The dashboard server tails `enriched_events.jsonl` and `alerts.jsonl` in real time and streams events to the browser via WebSocket.

### Standalone module testing

```bash
# Test the Decision Engine on a synthetic event
python decision_engine.py

# Test the Output Layer with a mock CRITICAL result
python output_layer.py

# Generate synthetic test events for tuning
python generate_test_data.py
```

---

## Dashboard

The browser dashboard (`dashboard.html` served by `dashboard_server.py`) provides:

- **Live event feed** — real-time process events with tags, scores, and severity badges
- **Alert severity panel** — `LOW / MEDIUM / HIGH / CRITICAL` counts updated per event
- **ML score overlay** — per-event ML anomaly score and confidence
- **Stats bar** — total events, alert rate, YARA hit count, ML elevation count
- **WebSocket streaming** — sub-second latency via `flask-socketio`
- **REST endpoints** — `/api/events`, `/api/stats`, `/api/alerts` for programmatic access

Access at `http://localhost:5000` while `dashboard_server.py` is running.

---

## Output Files

### `alerts.jsonl`

One JSON object per alert (MEDIUM and above by default). Key fields:

```jsonc
{
  "timestamp": "2026-01-30T14:22:10.441Z",
  "process_name": "vssadmin.exe",
  "pid": 4321,
  "username": "CORP\\attacker",
  "command_line": "vssadmin delete shadows /all /quiet",
  "total_score": 66,
  "level": "critical",
  "tags": ["shadow_copy_deletion", "backup_deletion", "boot_manipulation", "ransomware_tool"],
  "ransomware_indicators": ["shadow_copy_deletion", "backup_deletion"],
  "score_breakdown": [
    {"tag": "shadow_copy_deletion", "weight": 20, "rationale": "MITRE T1490"},
    {"tag": "backup_deletion",      "weight": 18, "rationale": "MITRE T1490"},
    {"tag": "boot_manipulation",    "weight": 20, "rationale": "MITRE T1490"}
  ],
  "yara_triggered": true,
  "yara_hits": ["Ransomware_Generic", "LockBit_Shadow"],
  "ml_score": 0.94,
  "ml_score_pct": 94,
  "ml_confidence": "high",
  "ml_top_features": ["process_risk_score", "ransomware_indicator_count"],
  "mitre_techniques": ["T1490 - Inhibit System Recovery"],
  "verdict": "CRITICAL: Definitive ransomware indicators detected.",
  "recommended_action": "IMMEDIATE RESPONSE — isolate system and begin incident response."
}
```

### `alert_summary.json`

```jsonc
{
  "generated_at": "2026-01-30T15:00:00",
  "alert_log": "alerts.jsonl",
  "statistics": {
    "total_emitted": 142,
    "level_counts": {"low": 89, "medium": 31, "high": 14, "critical": 8},
    "yara_hits": 6,
    "ml_elevations": 4
  }
}
```

---

## Tuning & Calibration

SENTINEL ships with default thresholds tuned for a moderate-security enterprise environment. **Before production deployment, calibrate against your baseline:**

1. Run SENTINEL on 7–14 days of **known-good activity** with all alerts logged at `LOW` level
2. Analyze `enriched_events.jsonl` for false positive patterns
3. Add known-good process signatures to `ExclusionRules` in `behavior_tags.py`
4. Adjust `ThresholdConfig` values in `behavior_tags.py` for your environment:
   - `REPEATED_SHELL_THRESHOLD` — how many shells before `repeated_shell_activity` fires
   - `LOLBIN_THRESHOLD` — how many LOLBins before `multiple_lolbin_usage` fires
   - `FILE_IO_MASS_READ_THRESHOLD` — file reads/minute before FileIOObserver alerts
5. Adjust `RISK_THRESHOLDS` (LOW=5 / MEDIUM=15 / HIGH=25 / CRITICAL=40) to reduce noise
6. Re-validate quarterly as the environment evolves

**Target false positive rates:**

| Level | Acceptable FP Rate |
|---|---|
| LOW | 20–30% (monitoring only) |
| MEDIUM | 5–10% (requires analyst review) |
| HIGH | < 2% (priority queue) |
| CRITICAL | < 0.5% (immediate response triggered) |

---

## Visual POC

> The screenshots below show SENTINEL detecting a simulated LockBit pre-encryption sequence against synthetic test data generated by `generate_test_data.py`.

### Terminal Alert Output — CRITICAL Detection

```
──────────────────────────────────────────────────────────────────────────
[CRITICAL] vssadmin.exe  (PID 4321)
──────────────────────────────────────────────────────────────────────────
  Time   : 2026-01-30T14:22:10.441123
  User   : CORP\attacker
  Cmd    : vssadmin delete shadows /all /quiet
  Score  : 66  →  CRITICAL
  Signals: +20 shadow_copy_deletion  +20 boot_manipulation  +18 backup_deletion
  YARA   : HIT → Ransomware_Command_Abuse, Win32_Ransomware_LockBit
  ML     : ML: 94%  (high) ↑ ELEVATED to CRITICAL
  MITRE  : T1490 - Inhibit System Recovery
  Action : IMMEDIATE RESPONSE — isolate system and begin incident response.
──────────────────────────────────────────────────────────────────────────
```

### Multi-Stage Attack Sequence (Simulated LockBit Run)

The following sequence illustrates how SENTINEL escalates across a 4-minute operator session:

```
T+00s  [LOW]      whoami /all                          score: 2  → discovery
T+18s  [LOW]      ipconfig /all                        score: 3  → discovery
T+45s  [MEDIUM]   net view /domain                     score: 17 → YARA gate opens
T+72s  [HIGH]     psexec \\DC01 cmd.exe               score: 28 → lateral movement
T+95s  [HIGH]     wmic shadowcopy delete               score: 31 → backup interference
T+110s [CRITICAL] vssadmin delete shadows /all /quiet  score: 66 → ISOLATE NOW
T+118s [CRITICAL] bcdedit /set recoveryenabled no      score: 58 → boot sabotage
```

### Dashboard — Live Alert Stream

```
┌─────────────────────────────────────────────────────────────────────┐
│  SENTINEL  ●  Live  │  Events: 247  │  Alerts: 8  │  YARA Hits: 3   │
├────────────────────┬──────────────┬──────────────┬──────────────────┤
│  LOW  89           │  MEDIUM  31  │  HIGH  14    │  CRITICAL  8     │
├────────────────────┴──────────────┴──────────────┴──────────────────┤
│  14:22:10  vssadmin.exe    CORP\attacker    [CRITICAL]  score:66     │
│            ↳ shadow_copy_deletion  boot_manipulation  backup_deletion│
│            ↳ YARA: Ransomware_Command_Abuse  ML: 94%                │
│  14:21:50  psexec.exe      CORP\attacker    [HIGH]      score:28     │
│  14:21:27  wmic.exe        CORP\attacker    [MEDIUM]    score:17     │
│  14:20:30  cmd.exe         CORP\attacker    [LOW]       score: 3     │
└─────────────────────────────────────────────────────────────────────┘
```

> **Note:** Replace the text POC panels above with actual screenshots of your deployment. Capture: (1) terminal during `generate_test_data.py` replay, (2) the dashboard in browser, (3) a `alerts.jsonl` extract in a JSON viewer. Store images in `docs/screenshots/` and update the image paths below:

```markdown
![Terminal Alert](docs/screenshots/terminal_critical.png)
![Dashboard Live](docs/screenshots/dashboard_live.png)
![alerts.jsonl](docs/screenshots/alerts_jsonl.png)
```

---

## Limitations

**Windows-only.** SENTINEL relies on WMI, Win32 APIs, and `pywin32`. It does not run on Linux or macOS. Process telemetry on Linux equivalents (eBPF, auditd) would require a separate implementation.

**No kernel-mode visibility.** SENTINEL operates entirely in user mode. A sophisticated attacker who disables WMI (`net stop winmgmt`), kills the SENTINEL process before executing ransomware commands, or uses direct syscalls to avoid Win32 API telemetry will not be detected. Kernel-mode EDR or a SIEM with Windows Event Log (Event ID 4688) as a secondary telemetry source is recommended for defense-in-depth.

**Pre-encryption only.** SENTINEL detects *operator commands* — it does not scan files for encryption in progress or detect fileless ransomware payloads executing in memory. If the operator skips the shadow copy deletion step (rare but possible), the CRITICAL fast-path will not trigger. Behavioral scoring still accumulates from other signals.

**WMI polling latency.** The `watch_for()` watcher polls at `timeout_ms=100`. In a worst case, a short-lived process (sub-100ms execution) may be missed. This is an inherent WMI limitation. Sysmon with Event ID 1 (`ProcessCreate`) is a more reliable telemetry source and can be parsed as an alternative input to Module 1.

**YARA scans the executable on disk.** The `SignatureScanner` scans the `executable_path` of the process. If the binary is packed, polymorphic, or the path is unavailable (e.g., a reflectively loaded DLL), YARA will not match. Command-line string rules in `command_abuse.yar` scan the command line string directly and are not affected by this limitation.

**ML model is environment-specific.** The shipped `ml_model.pkl` is trained on synthetic data. In production, retrain on 7–14 days of your environment's baseline before relying on ML elevation decisions. Use `generate_test_data.py` combined with real benign telemetry for training.

**No network traffic inspection.** Lateral movement detected by `LateralMovementObserver` is inferred from process creation (PsExec execution, `wmic /node:` command lines). Actual network connection establishment is not monitored. A network-level IDS or firewall log integration is complementary.

**SSD / TRIM / drive encryption false positives.** `cipher.exe` triggered legitimately (e.g., encrypted folder operations) will score as `encryption_activity`. Calibrate the exclusion rules for your environment's legitimate cipher usage.

**High-privilege requirement.** Without Administrator privileges, `GetOwner()` and integrity level reads will fail silently. SENTINEL degrades to process-name-and-command-line-only telemetry, reducing detection fidelity for privilege escalation and credential access events.

---

## Ransomware Families Covered

| Family | Detection Method | Rules / Tags |
|---|---|---|
| LockBit 3.0 / 4.0 | YARA + behavioral | `lockbit.yar`, `shadow_copy_deletion`, `boot_manipulation` |
| BlackCat / ALPHV | YARA + behavioral | `blackcat.yar`, ESXi kill commands |
| Conti | YARA + behavioral | `conti.yar`, MurmurHash2 bytecode |
| REvil / Sodinokibi | YARA + behavioral | `additional_ransomware_rules.yar`, RC4/Salsa20 patterns |
| Ryuk | Behavioral | `vssadmin resize shadowstorage /maxsize=401mb` (Ryuk-specific) |
| Maze / Egregor | YARA | `additional_ransomware_rules.yar` |
| Cuba | YARA | `additional_ransomware_rules.yar` |
| Play | YARA | `additional_ransomware_rules.yar` |
| Akira | YARA | `additional_ransomware_rules.yar` |
| Generic HoR | YARA + behavioral | `command_abuse.yar`, all behavioral tags |

---

## Contributing

Pull requests are welcome. Before opening one:

1. Run the test data generator against your changes: `python generate_test_data.py`
2. Verify no regressions in CRITICAL detection for the `vssadmin delete shadows` and `bcdedit` test cases
3. New YARA rules must include `meta.author`, `meta.date`, `meta.mitre_technique`, and `meta.false_positive_risk`
4. New behavior tags must be added to both `BEHAVIOR_TAGS` (with `weight`, `scope`, `rationale`) and `TAG_DESCRIPTIONS` in `behavior_tags.py`
5. Threshold changes require updated documentation in this README

**To report a false positive or missed detection, open an issue with:**
- The exact command line that triggered (or failed to trigger) an alert
- The process name and parent process name
- The level SENTINEL produced vs. the level you expected
- Whether the event was on a domain-joined host and the user privilege level

**Rule update sources (quarterly recommended):**
- https://github.com/reversinglabs/reversinglabs-yara-rules
- https://github.com/advanced-threat-research/Yara-Rules
- https://github.com/Yara-Rules/rules
- https://malpedia.caad.fkie.fraunhofer.de/
- https://www.cisa.gov/ransomware

---

*SENTINEL — detect the operator, not just the payload.*

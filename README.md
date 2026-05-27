# SENTINEL
**Pre-Encryption Human-Operated Ransomware Detection System**

SENTINEL monitors Windows hosts for attacker behavior *before* the encryption payload executes — catching the reconnaissance, staging, and anti-recovery commands that operators run in the minutes to hours preceding file encryption. It combines real-time process telemetry, weighted behavioral tagging, temporal pattern correlation, YARA signature scanning, ML anomaly scoring, and a live browser dashboard into a single deployable Python system.

> **Philosophy:** Ransomware operators are human. Humans leave command-line footprints. SENTINEL detects the footprints.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Pipeline](#detection-pipeline)
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

Human-Operated Ransomware (HoR) attacks — LockBit, BlackCat/ALPHV, Conti, REvil, Ryuk — share a consistent pre-encryption playbook. Before a single file is touched, an operator works through discovery (`net view`, `whoami /all`), credential access (`mimikatz`, `procdump lsass`), anti-recovery (`vssadmin delete shadows /all /quiet`), boot sabotage (`bcdedit /set {default} bootstatuspolicy ignoreallfailures`), backup deletion (`wbadmin delete catalog -quiet`), lateral movement (`psexec \\target`, `wmic /node:`), and persistence via Registry Run keys or scheduled tasks.

SENTINEL intercepts every process creation on the Windows host, scores the command line in real time, and raises structured alerts before a single file is encrypted. At `CRITICAL` level the system recommends immediate isolation.

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

`process_monitor.py` subscribes to WMI `Win32_Process` creation events using a polling watcher at `timeout_ms=100`. For every new process it captures the name, PID, command line, and executable path, resolves the owner via `GetOwner()`, and pulls the parent process name and command line for downstream parent-child analysis. The module is pure telemetry with no detection logic — events are appended to `process_events.jsonl` for everything downstream to consume. If the WMI service drops, the watcher reconnects automatically. Running without Administrator privileges degrades telemetry silently rather than crashing.

---

### Module 2 — Behavior Tagger

`behavior_tagger.py` takes the raw event stream and attaches a list of behavior tags to each event across three passes.

**Tool classification** hits an O(1) dictionary of 30+ known executables. Each tool carries one or more class labels — `interactive_shell`, `script_engine`, `ransomware_tool`, `download_capable`, and so on — so the downstream scorer immediately knows the process category before reading a single character of the command line.

**Command pattern matching** then runs regex and substring checks against the full command line for ransomware-specific strings. Shadow copy deletion is caught via `vssadmin delete shadows` and `wmic shadowcopy delete`. Boot manipulation via `bcdedit /set`, `bootstatuspolicy ignoreallfailures`, and `recoveryenabled no`. Backup deletion via `wbadmin delete catalog` and `wbadmin delete backup`. Credential access via `mimikatz`, `procdump.*lsass`, and `reg save HKLM\SAM`. Obfuscation via Base64 `-EncodedCommand` and `FromBase64String`. Network discovery via `net view`, `net share`, and `arp -a`. Lateral movement via `psexec`, `wmic /node:`, `winrm`, and `Enter-PSSession`. Persistence via Registry Run key writes and `schtasks /create`. Service manipulation via `sc stop`, `net stop`, and `taskkill` calls targeting AV and backup services.

**Session accumulation** runs in parallel, maintaining a per-user state that counts shells opened, LOLBins executed, ransomware-tool invocations, and shadow copy operations within the current session window. Once those counts cross configured thresholds, session-scoped tags fire — `multiple_ransomware_indicators`, `multiple_ransomware_tools`, `repeated_shell_activity` — giving the scorer a view of the operator's session arc, not just the individual command.

Known-good patterns (Windows Update, System32 scheduled maintenance, whitelisted admin scripts) are stripped by an exclusion filter before any tags are attached. Output is a `TaggedEvent` carrying the original process fields alongside `tags`, `confidence`, and the `ransomware_indicators` subset.

---

### Module 3 — Temporal Observers

`temporal_observers.py` runs four concurrent observers that catch behaviors that only become visible over time — things that a single process creation event can never tell you.

**PrivilegeEscalationObserver** reads the Windows integrity level token of every process via `win32security`. It flags transitions from Medium to High or System integrity that can't be explained by known system parent processes like WerFault or TiWorker. The whitelist prevents the observer from alerting every time the OS legitimately elevates a child process.

**LateralMovementObserver** watches for PsExec execution, `wmic /node:` remote process creation, WinRM invocations, and SMB admin share access patterns. A sliding 5-minute window counts lateral tool uses; exceeding the threshold fires a `HIGH` behavior event to `temporal_behaviors.jsonl`. During testing this observer fired on `CORP\jsmith` running `net.exe` with remote targets, exactly as expected — those events are visible in `temporal_behaviors.jsonl`.

**FileIOObserver** uses `ReadDirectoryChangesW` on user-writeable paths to track file creation, modification, rename, and deletion rates. Mass-rename patterns — thousands of files gaining a new extension within seconds — and mass-deletion are flagged as pre-encryption staging. This is the closest SENTINEL gets to catching encryption in motion without a kernel driver.

**RansomNoteScanner** scans newly created `.txt` and `.html` files for ransom note content markers: `decrypt`, `bitcoin`, `YOUR FILES ARE ENCRYPTED`, BTC address patterns, `.onion` URLs. A match is an immediate `CRITICAL` — if a note has been dropped, encryption is likely already underway. All four observers write `BehaviorEvent` objects to `temporal_behaviors.jsonl`.

---

### Module 4 — Decision Engine

`decision_engine.py` receives `TaggedEvent` objects and produces a structured `DecisionResult`. The score is a simple weighted sum — for each tag present, look up its weight in `BEHAVIOR_TAGS` and add it to the total. Tag weights run from 1 (`interactive_shell`, a near-meaningless signal on its own) up to 20 (`shadow_copy_deletion`, nearly always malicious).

That score then maps to a level. Anything below 5 is ignored. Score 5–14 is `LOW` — log it, accumulate context. Score 15–24 is `MEDIUM` — analyst review within 24 hours, and the YARA gate opens. Score 25–39 is `HIGH` — priority investigation within 4 hours. Score 40 and above is `CRITICAL` — immediate isolation recommended.

YARA is deliberately not run on every event. It is gated behind the MEDIUM threshold so that the hot path for benign processes stays free of file I/O overhead. When YARA does fire, matching rule names attach to the `DecisionResult` and can push the level one step higher. There is also a CRITICAL fast-path: any single event bearing `shadow_copy_deletion`, `boot_manipulation`, or `backup_deletion` satisfies the CRITICAL threshold immediately, regardless of accumulated score.

---

### Module 5 — ML Anomaly Scorer

`ml_scorer.py` runs after the Decision Engine and can elevate, but never suppress, the rule-based level. Two models work together: an `IsolationForest` that flags process vectors statistically unusual against the training baseline, and a `GradientBoostingClassifier` trained on labeled benign and malicious examples.

The feature vector is extracted entirely from process telemetry — no file I/O, no network calls. It includes a per-process risk score (vssadmin=90, bcdedit=85, powershell=30), behavioral counts like tag count and ransomware indicator count, command line entropy and length, suspicious keyword hits, base64 presence, parent process risk, and event velocity in the last 60 and 300 seconds. Output is an `MLScore` with a 0–100 score, confidence label, and the top contributing features. The model is serialized to `ml_model.pkl` at first training and loaded at startup on subsequent runs. Latency is under 5ms per event with under 20MB memory footprint.

---

### Module 6 — Evidence & Output Layer

`output_layer.py` is pure output — no detection logic of its own. It takes a `DecisionResult` and optional `MLScore` and produces three things.

The **console alert** is ANSI-colored terminal output showing the process, score, top 3 contributing tags with their weights, YARA hit names if any, ML score percentage, MITRE technique IDs, and the recommended action string. The minimum console level defaults to `MEDIUM` and is configurable.

**`alerts.jsonl`** receives one JSON object per alert carrying every field: process telemetry, the full tag list, score breakdown, YARA hits, ML features, MITRE techniques, verdict string, and recommended action. It is structured for direct ingestion into Splunk, Elastic SIEM, or any JSONL-capable pipeline.

**`alert_summary.json`** is written on graceful shutdown and contains session-level totals: events emitted, counts per level, YARA hit count, and ML elevation count — intended as a quick analyst handoff document.

Every tag in the output resolves to a MITRE ATT&CK technique automatically. `shadow_copy_deletion` → T1490, `encryption_activity` → T1486, `credential_access_attempt` → T1003, `lateral_movement` → T1021, `service_manipulation` → T1489, `network_share_discovery` → T1135, `obfuscated_execution` → T1027, `persistence_attempt` → T1547, `living_off_the_land` → T1218.

---

## YARA Signatures

Rules live in `rules/` and are compiled once at startup by `SignatureScanner`. The scanner runs against the process executable path whenever the Decision Engine gates it at MEDIUM or above.

`lockbit.yar` covers LockBit 3.0 and 4.0 via PE code patterns, the `LockBit` string family, `.lockbit` extension markers, and the `UNIQUE_ID_DO_NOT_REMOVE` mutex. `blackcat.yar` targets BlackCat/ALPHV using the Rust artifact path `/rust/`, `ALPHV` strings, `enable_esxi_vm_kill`, and the `.alphv` extension. `conti.yar` uses the leaked MurmurHash2 bytecode signature alongside Conti-specific strings. `command_abuse.yar` is the generic HoR rule — it scans the command line string directly for `vssadmin delete shadows`, `bcdedit /set`, `wbadmin delete catalog`, and service kill patterns, so it works regardless of whether the binary is packed. `additional_ransomware_rules.yar` adds coverage for REvil/Sodinokibi (RC4 and Salsa20 bytecode, campaign config markers), Maze/Egregor, Cuba, Play, and Akira.

To add emerging threat coverage, drop a `.yar` file into `rules/` and restart SENTINEL. Good quarterly sources are the ReversingLabs YARA rules repository, Yara-Rules/rules, Malpedia, and ransomware.live.

---

## Scoring & Risk Thresholds

```
LOW      score ≥  5   →  Log only
MEDIUM   score ≥ 15   →  Analyst review / YARA gate opens
HIGH     score ≥ 25   →  Priority investigation
CRITICAL score ≥ 40   →  Immediate isolation recommended
```

The heaviest weights are on the three definitive ransomware indicators: `shadow_copy_deletion` (20), `boot_manipulation` (20), and `backup_deletion` (18). Encryption activity carries 16, credential access 14, lateral movement 12. Obfuscation alone is only 4, and an interactive shell opening is 1 — almost noise by itself, but it accumulates. The session tag `multiple_ransomware_indicators` adds another 10 when the operator has made multiple incriminating moves in the same session.

The arithmetic is intentional. `vssadmin delete shadows /all /quiet` alone scores `shadow_copy_deletion (20) + backup_deletion (18) + boot_manipulation (20) + ransomware_tool (8) = 66` — well past CRITICAL from a single command. Full weights are documented in `behavior_tags.py`.

---

## MITRE ATT&CK Coverage

SENTINEL maps detection coverage to ten ATT&CK techniques. T1490 (Inhibit System Recovery) is covered by the `shadow_copy_deletion`, `boot_manipulation`, and `backup_deletion` tags plus `command_abuse.yar`. T1486 (Data Encrypted for Impact) by `encryption_activity` and the family YARA rules. T1003 (OS Credential Dumping) by `credential_access_attempt` and command pattern matching. T1021 (Remote Services) by the `lateral_movement` tag and `LateralMovementObserver`. T1489 (Service Stop) by `service_manipulation` and `sc stop` / `net stop` patterns. T1135 (Network Share Discovery) by `network_share_discovery`. T1027 (Obfuscated Files/Information) by `obfuscated_execution` and Base64 command detection. T1547 (Boot/Logon Autostart Execution) by `persistence_attempt`. T1218 (System Binary Proxy Execution) by LOLBin classification. T1134 (Access Token Manipulation) by the `PrivilegeEscalationObserver`.

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
├── process_events.jsonl            Raw process telemetry — every process creation on host
├── enriched_events.jsonl           Tagged events with scores, confidence, ransomware flags
├── temporal_behaviors.jsonl        Time-window behavior events (lateral movement, file I/O)
├── alerts.jsonl                    Final alerts — primary SIEM ingest target
├── alert_summary.json              Session-level analyst summary (written on shutdown)
└── integrated_detection.log        System debug log
```

`process_events.jsonl`, `enriched_events.jsonl`, and `temporal_behaviors.jsonl` are live output files written by the running system, not configuration. The included samples in this repository were captured from a real test run against `generate_test_data.py` and show what actual telemetry looks like in each stage of the pipeline.

---

## Installation

SENTINEL runs on Windows 10/11 or Windows Server 2019/2022. Python 3.10 or later is required (3.12 recommended). Administrator privileges are required — without them, WMI telemetry and integrity level reads are unavailable. Confirm the WMI service is running before starting: `net start winmgmt`.

```bash
# Clone the repository
git clone https://github.com/jynxora/sentinel.git
cd sentinel

# Install dependencies
pip install -r requirements.txt
```

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
# Verify YARA rules compile cleanly (optional sanity check)
python -c "from signature_scanner import SignatureScanner; s = SignatureScanner('rules/'); print('YARA OK')"

# Pre-train the ML model (optional — happens automatically on first run otherwise)
python ml_scorer.py
```

On some systems `pywin32` post-install scripts need to be run manually after `pip install`:

```bash
python Scripts/pywin32_postinstall.py -install
```

---

## Running SENTINEL

Run the main orchestrator as Administrator. This starts all six modules in coordinated threads — the WMI watcher, the queue-based tagger, the four temporal observers in background threads, and the scoring/output pipeline on every enriched event.

```bash
python integrated_detection_system.py
```

Stop with `Ctrl+C`. Graceful shutdown writes `alert_summary.json` before exiting.

The browser dashboard runs as a companion process in a second terminal. It tails `enriched_events.jsonl` and `alerts.jsonl` in real time and pushes events to the browser via WebSocket.

```bash
python dashboard_server.py
# Open http://localhost:5000
```

Individual modules can be run standalone for testing and tuning:

```bash
python decision_engine.py      # Test scoring against a synthetic CRITICAL event
python output_layer.py         # Test console output formatting
python generate_test_data.py   # Replay a simulated attack sequence
```

---

## Dashboard

The dashboard at `http://localhost:5000` streams events live via WebSocket with sub-second latency. It shows a live event feed with tags, scores, and severity badges; a four-level severity panel updated per event; per-event ML anomaly scores and confidence labels; and a stats bar tracking total events, alert rate, YARA hits, and ML elevations. REST endpoints at `/api/events`, `/api/stats`, and `/api/alerts` are available for programmatic access or integration with external tooling.

---

## Output Files

SENTINEL writes four files during a run. The first three are written by the detection modules and exist whether or not any alerts fire. The fourth is the final alert log.

**`process_events.jsonl`** is Module 1's raw output — one JSON object per process creation, capturing every field WMI provides: timestamp, process name, PID, parent PID, command line, username, executable path, and resolved parent process name and command line. This is the ground-truth telemetry log.

**`enriched_events.jsonl`** is Module 2's output — the same events with behavioral tags, confidence, ransomware indicator flags, and session-level counters (`shell_count`, `lolbin_count`, `ransomware_score`) appended. This is the file the Decision Engine reads, and the file the dashboard server tails for live streaming.

**`temporal_behaviors.jsonl`** is Module 3's output — behavior events emitted by the four temporal observers when time-window patterns cross their thresholds. Each event records the observer source, behavior type, confidence, score, evidence list, metadata (tool, targets, attempt count), and the associated username and process name.

**`alerts.jsonl`** is the final output of Module 6 — one JSON object per alert at MEDIUM level or above. A representative CRITICAL alert looks like this:

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
  "yara_hits": ["Ransomware_Command_Abuse", "Win32_Ransomware_LockBit"],
  "ml_score": 0.94,
  "ml_score_pct": 94,
  "ml_confidence": "high",
  "ml_top_features": ["process_risk_score", "ransomware_indicator_count"],
  "mitre_techniques": ["T1490 - Inhibit System Recovery"],
  "verdict": "CRITICAL: Definitive ransomware indicators detected.",
  "recommended_action": "IMMEDIATE RESPONSE — isolate system and begin incident response."
}
```

On graceful shutdown, `alert_summary.json` is written with session totals:

```jsonc
{
  "generated_at": "2026-01-30T15:00:00",
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

The shipped thresholds are calibrated for a moderate-security enterprise environment. Before production deployment, run SENTINEL on 7–14 days of known-good activity with all alerts logged at `LOW`, then analyze `enriched_events.jsonl` for false positive patterns. Add recurring legitimate patterns to `ExclusionRules` in `behavior_tags.py`.

Three values in `ThresholdConfig` (also in `behavior_tags.py`) control session-level sensitivity: `REPEATED_SHELL_THRESHOLD` determines how many shells open before the session tag fires, `LOLBIN_THRESHOLD` how many LOLBins before `multiple_lolbin_usage` fires, and `FILE_IO_MASS_READ_THRESHOLD` how many file reads per minute before `FileIOObserver` alerts. Adjust `RISK_THRESHOLDS` itself only as a last resort — the individual tag weights are a finer-grained instrument.

Target false positive rates by level: LOW can tolerate 20–30% (it's monitoring-only), MEDIUM should stay under 10% (it requires analyst review), HIGH under 2% (it goes to a priority queue), and CRITICAL under 0.5% (it triggers an immediate response workflow). Re-validate quarterly.

---

## Visual POC

The screenshots below show SENTINEL running against synthetic test data generated by `generate_test_data.py`, replaying a simulated LockBit pre-encryption operator session.

Three captures are most useful: the terminal output during a CRITICAL detection, the live dashboard in the browser, and an `alerts.jsonl` extract in a JSON viewer.

```markdown
![Terminal — CRITICAL alert](docs/screenshots/terminal_critical.png)

![Dashboard — live event stream](docs/screenshots/dashboard_live.png)

![alerts.jsonl — CRITICAL entry](docs/screenshots/alerts_jsonl.png)

```

To reproduce the POC sequence yourself:

```bash
# Terminal 1 — start the detection system
python integrated_detection_system.py

# Terminal 2 — start the dashboard
python dashboard_server.py

# Terminal 3 — replay the attack sequence
python generate_test_data.py
```

The sequence escalates across roughly 4 minutes of operator activity:

```
T+00s  [LOW]      whoami /all                          score:  2  → discovery
T+18s  [LOW]      ipconfig /all                        score:  3  → discovery
T+45s  [MEDIUM]   net view /domain                     score: 17  → YARA gate opens
T+72s  [HIGH]     psexec \\DC01 cmd.exe                score: 28  → lateral movement
T+95s  [HIGH]     wmic shadowcopy delete               score: 31  → backup interference
T+110s [CRITICAL] vssadmin delete shadows /all /quiet  score: 66  → ISOLATE NOW
T+118s [CRITICAL] bcdedit /set recoveryenabled no      score: 58  → boot sabotage
```

The corresponding terminal output at the CRITICAL event:

```
──────────────────────────────────────────────────────────────────────
[CRITICAL] vssadmin.exe  (PID 4321)
──────────────────────────────────────────────────────────────────────
  Time   : 2026-01-30T14:22:10.441123
  User   : CORP\attacker
  Cmd    : vssadmin delete shadows /all /quiet
  Score  : 66  →  CRITICAL
  Signals: +20 shadow_copy_deletion  +20 boot_manipulation  +18 backup_deletion
  YARA   : HIT → Ransomware_Command_Abuse, Win32_Ransomware_LockBit
  ML     : 94%  (high)  ↑ ELEVATED to CRITICAL
  MITRE  : T1490 - Inhibit System Recovery
  Action : IMMEDIATE RESPONSE — isolate system and begin incident response.
──────────────────────────────────────────────────────────────────────
```

---

## Limitations

**Windows-only.** SENTINEL depends on WMI, `pywin32`, and Win32 APIs. It does not run on Linux or macOS. Equivalent telemetry on Linux (eBPF, auditd) would require a separate implementation.

**No kernel-mode visibility.** SENTINEL operates entirely in user mode. An attacker who disables WMI (`net stop winmgmt`), kills the SENTINEL process before executing ransomware commands, or uses direct syscalls to avoid Win32 API telemetry will not be detected. A kernel-mode EDR or a SIEM fed by Windows Event Log Event ID 4688 is recommended as a complementary layer.

**Pre-encryption only.** SENTINEL detects operator commands. It does not scan files for encryption in progress or detect fileless ransomware executing in memory. If an operator skips shadow copy deletion (rare but possible), the CRITICAL fast-path will not trigger, though behavioral scoring still accumulates from other signals.

**WMI polling latency.** The `watch_for()` watcher polls at `timeout_ms=100`. A process that completes in under 100ms may be missed. This is an inherent WMI ceiling — Sysmon Event ID 1 (`ProcessCreate`) is a more reliable telemetry source and can be used as an alternative input to Module 1.

**YARA scans the executable on disk.** `SignatureScanner` scans `executable_path`. If the binary is packed, polymorphic, or the path is unavailable (e.g. a reflectively loaded DLL), YARA will not match. Command-line rules in `command_abuse.yar` scan the command string directly and are unaffected by this.

**The shipped ML model is trained on synthetic data.** Retrain on 7–14 days of your environment's real baseline before relying on ML elevation decisions in production. `generate_test_data.py` combined with captured benign telemetry provides the training set.

**No network traffic inspection.** Lateral movement is inferred from process creation — PsExec execution and `wmic /node:` command lines. Actual network connections are not monitored. A network-level IDS or firewall log feed is complementary.

**`cipher.exe` false positives.** Legitimate encrypted folder operations will score as `encryption_activity`. Add your environment's normal cipher usage patterns to `ExclusionRules` in `behavior_tags.py` during calibration.

**Privilege requirement is hard.** Without Administrator, `GetOwner()` and integrity level reads fail silently. SENTINEL degrades to process-name-and-command-line-only telemetry, losing privilege escalation and most credential access detection fidelity.

---

## Ransomware Families Covered

LockBit 3.0 and 4.0 are covered by `lockbit.yar` plus the `shadow_copy_deletion` and `boot_manipulation` behavioral tags. BlackCat/ALPHV by `blackcat.yar` including ESXi kill command detection. Conti by `conti.yar` using the leaked MurmurHash2 bytecode. REvil/Sodinokibi by `additional_ransomware_rules.yar` with RC4/Salsa20 bytecode patterns. Ryuk by the behavioral tag for the Ryuk-specific command `vssadmin resize shadowstorage /maxsize=401mb`. Maze/Egregor, Cuba, Play, and Akira are all in `additional_ransomware_rules.yar`. Generic HoR operators — those not using a named payload — are caught by `command_abuse.yar` and the full behavioral tag set.

---

## Contributing

Before opening a pull request, run `generate_test_data.py` against your changes and verify no regressions in CRITICAL detection for the `vssadmin delete shadows` and `bcdedit` test cases. New YARA rules must include `meta.author`, `meta.date`, `meta.mitre_technique`, and `meta.false_positive_risk`. New behavior tags must appear in both `BEHAVIOR_TAGS` (with `weight`, `scope`, and `rationale`) and `TAG_DESCRIPTIONS` in `behavior_tags.py`. Threshold changes require updated documentation here.

To report a false positive or missed detection, open an issue with the exact command line that triggered or failed to trigger an alert, the process name and parent process name, the level SENTINEL produced versus what you expected, and whether the host was domain-joined and the user's privilege level at the time.

Rule update sources worth checking quarterly: the ReversingLabs YARA rules repository, Yara-Rules/rules, the ATD YARA rules repository, Malpedia, and the CISA ransomware advisory page.

---

*SENTINEL — detect the operator, not just the payload.*

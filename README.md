# RedScan v2 – Network Intelligence Platform

Conference-demo-ready RedScan with a **unified GUI** and a full backend engine.

---

## Features

| Layer | Description |
|---|---|
| 🎯 **Preset Library** | 80+ expert scanning profiles across 9 categories; presets can belong to multiple categories simultaneously |
| 🔧 **Command Factory** | Visual flag canvas builder with real-time conflict resolution and "Save as Preset" |
| 📊 **Scan Dashboard** | Real-time host/port table, XML enrichment for richer version data, session save/load, live log |
| ⚡ **Smart Scan** | Adaptive PID+AIMD rate controller; calibration accepts RST replies as valid RTT samples |
| 🤖 **AI Insights** | Pluggable LLM analysis (OpenAI, Gemini, or built-in Mock); provider config persists across restarts |
| 🌐 **FastAPI service** | REST + NDJSON streaming API with optional X-API-Key auth and per-IP rate limiting |
| 🧠 **Conflict Manager** | Rule-based engine that auto-fixes silent incompatibilities and warns about advisory conflicts before every scan |

---

## Preset Library

### Categories (9)

| Icon | Category | Preset Count |
|---|---|---|
| 🔍 | Host Discovery | 8 |
| 🚪 | Port Scanning | 10 |
| 📋 | Service Enumeration | 8 |
| 🛡 | Vulnerability Scanning | 12 |
| 🌐 | Web Application | 9 |
| 🥷 | Stealth & Evasion | 8 |
| ⚙️ | Service-Specific | 14 |
| 🖧 | Network Infrastructure | 5 |
| 🔑 | Authentication & Credentials | 8 |

Cross-category presets (e.g. `snmp_sweep`, `smb_vuln`) appear in *all* their listed
categories — the browser shows the same preset card under each relevant heading without
duplicating the underlying object.

### Navigation (Lazy Loading)

The Preset Library now uses a two-stage navigation model:

1. **Landing page** — 3-column grid of category tiles, each showing the icon, name, and
   preset count.  No preset data is loaded until a tile is clicked.
2. **Category page** — 2-column card grid for the selected category, with a ← Back button.
3. **Search mode** — typing in the search bar from any page performs a cross-category
   full-text search (name, description, flags, script names).

---

## Dynamic Conflict Manager

`redscan/conflict_manager.py` provides a **rule-based** conflict engine that is
evaluated before every scan.  Rules are data objects — adding a new rule requires
no changes to the dashboard or any other caller.

### Rule types

| Type | Behaviour |
|---|---|
| `auto_fix` | Mutates the command list silently and logs an advisory |
| `warning` | Logs a warning but does not mutate the command |
| `info` | Logs a neutral informational note |

### Built-in rules (12)

| Rule name | Trigger | Action |
|---|---|---|
| `host_discovery_drops_ports` | `-sn` with a non-empty ports field | auto_fix |
| `sn_plus_sv_incompatible` | `-sn` + `-sV` | auto_fix – removes `-sV` |
| `sn_plus_sc_incompatible` | `-sn` + `-sC` | auto_fix – removes `-sC` |
| `frag_with_connect_scan` | `-f`/`--mtu` + `-sT` | auto_fix – removes frag flags |
| `conflicting_scan_types` | `-sS` + `-sT` | auto_fix – removes `-sT` |
| `dns_brute_needs_domain` | `dns-brute` script + IP/localhost target | warning |
| `raw_socket_without_root` | Raw-socket flag without root privileges | warning |
| `udp_allports_very_slow` | `-sU -p-` | warning |
| `stealth_defeated_by_aggressive_timing` | Stealth scan type + `-T5` | warning |
| `os_detect_without_root` | `-O` without root | warning |
| `script_with_host_discovery_only` | `--script` + `-sn` | warning |
| `decoy_with_connect_scan` | `-D` + `-sT` | warning |
| `localhost_vuln_scan` | `vuln` script against localhost | info |
| `aggressive_timing_with_brute` | `-T5` + brute-force script | warning |

### Extending the rule set

```python
from redscan.conflict_manager import ConflictRule, ConflictManager

my_rule = ConflictRule(
    name="no_syn_on_port_443",
    check=lambda cmd, target, ports, root: "-sS" in cmd and "443" in ports,
    severity="warning",
    message=lambda cmd, target, ports, root: "[!] Port 443 SYN scans are often rate-limited.",
)

manager = ConflictManager(rules=[*DEFAULT_RULES, my_rule])
clean_cmd, messages = manager.apply(cmd, target, ports_str)
```

---

## Bug Fixes

| File | Fix |
|---|---|
| `redscan/models.py` | `aimd_beta` validator changed to `lt=1` (paper specifies `0 < β < 1` strictly; `1.0` means zero backoff) |
| `redscan/smart_scan.py` | Calibration RTT now accepted for `"closed"` (RST) replies, not only `"open"`; prevents the rate controller from staying pinned at `initial_rate` when the calibration host resets the connection |
| `redscan/api.py` | Rate-limit env var (`REDSCAN_RATE_LIMIT`) is re-read on every request instead of frozen at import time; `_rate_buckets` dict is now pruned to prevent unbounded memory growth across unique client IPs |
| `redscan/history.py` | `threading.Lock` → `threading.RLock`; `_load_raw` now acquires the lock so concurrent reads cannot race against writes |
| `gui/views/llm_panel.py` | `_load_config()` now calls `_apply_config()` after restoring UI vars so the correct LLM pipeline is activated on startup (previously Mock was always used until the user manually clicked "Apply") |
| `gui/views/llm_panel.py` | `_build_prompt()` now includes the nmap command in both prompt variants so the LLM sees what flags were used |
| `gui/views/dashboard.py` | Added public `start_scan()` method; XML enrichment failure now logs an advisory instead of silently doing nothing |
| `gui/app.py` | `WM_DELETE_WINDOW` handler added to terminate any running nmap process on window close; `_start_scan()` call replaced with public `start_scan()` |

---

## Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
# A desktop display (X11 or Wayland) is required for the GUI
```

### Launch the GUI

```bash
python gui_main.py
```

### Run the API server

```bash
# Optional: enable auth and custom rate limit
REDSCAN_API_KEY=secret REDSCAN_RATE_LIMIT=20 uvicorn app:app --reload
```

API endpoints:

- `GET  /health`
- `POST /scan`              (requires `X-API-Key` header if `REDSCAN_API_KEY` is set)
- `POST /scan/stream`       (NDJSON streaming)
- `GET  /history`           (last 50 scan records)
- `DELETE /history`         (clear all history)

### CLI (legacy)

```bash
python scan.py
```

---

## GUI Overview

```
┌──────────────┬─────────────────────────────────────────────────────┐
│  🛡 RedScan  │                                                     │
│──────────────│         Main Content Area                           │
│ 🎯 Presets   │  (switches between views on sidebar click)          │
│ 🔧 Factory   │                                                     │
│ 📊 Dashboard │                                                     │
│ ⚡ Smart Scan│                                                     │
│ 🤖 AI Insight│                                                     │
└──────────────┴─────────────────────────────────────────────────────┘
```

**Preset Library** – Search/filter 80+ scans across 9 categories by name, description, or flags.
Click a category tile to browse its presets, click *Run* to execute on the Dashboard, or
*To Factory* to inspect the flags on the canvas.

**Command Factory** – Pick flag pieces from the left palette; they snap to
the canvas.  Single-select categories (scan type, timing, port scope) are
automatically enforced – conflicting pieces disappear from the palette as soon
as an incompatible piece is placed.  Hit *Run Command* to execute, or
*Save as Preset* to reuse later.

**Scan Dashboard** – Choose a target, preset (or "(none)" for defaults), and
port range, then click *Run Scan*.  The host/port table populates in real time
from Nmap's stdout.  Select a host to see its full port detail.  Post-scan
XML enrichment provides richer version and OS information when available.
Sessions can be saved to JSON and reloaded at any time.

**Smart Scan** – Configure all PID+AIMD parameters via sliders (α, Kp, Ki, Kd,
β, R_min, R_max, loss window, calibration ratio …).  A live rate-history chart
shows the controller in action.  The calibration probe now treats RST replies
as valid RTT samples so the rate controller converges correctly even when the
calibration endpoint does not complete the TCP handshake.

**AI Insights** – Select a provider (Mock/OpenAI/Gemini), enter an API key if
needed, then click *Apply Configuration*.  The provider setting and API key are
saved to `~/.redscan_config.json` and automatically re-applied on the next
launch.  Click *AI Insights* to receive a risk summary and recommendations
(the nmap command you ran is included in the prompt), or *What's Next?* for
guided follow-up suggestions.

---

## Repository Layout

```
redscan/
  preset_library.py   80+ ScanPreset definitions across 9 categories; cross-category support
  conflict_manager.py Rule-based nmap command conflict engine (auto-fix + warn)
  smart_scan.py       Adaptive rate controller (EWMA + PID + AIMD)
  command_factory.py  Graph-based nmap command assembler (networkx)
  runtime_parser.py   Async incremental output parser
  llm.py              Pluggable LLM abstraction + MockLLMProvider
  orchestrator.py     End-to-end pipeline orchestrator
  api.py              FastAPI endpoints (auth, rate limiting, history)
  history.py          Thread-safe JSON scan history store
  models.py           Pydantic schemas

gui/
  app.py              CTk main window + sidebar navigation
  styles.py           Colour palette, fonts, layout constants
  views/
    preset_browser.py Scrollable preset card library
    command_factory.py Visual flag canvas
    dashboard.py      Real-time scan results table + session I/O
    smart_scan.py     Adaptive scan config panel + rate chart
    llm_panel.py      LLM settings + AI insight display

gui_main.py           GUI entry point
app.py                FastAPI entry point (uvicorn)
scan.py               Legacy CLI
xml_parser.py         Post-scan XML enrichment helper
```

---

## Tests

```bash
python -m pytest -q
```

Tests cover preset library integrity (unique keys, aggressiveness values, cross-category
placement, semantic hints), conflict manager rules (auto-fix mutations, warning triggers,
false-positive checks, command immutability), LLM response parsing, host record
serialization, smart scan discovery, runtime parser events, and API happy-path.


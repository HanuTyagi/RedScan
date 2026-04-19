# RedScan v2 – Network Intelligence Platform

Conference-demo-ready RedScan with a **unified GUI** and a full backend engine.

---

## Features

| Layer | Description |
|---|---|
| 🎯 **Preset Library** | 29 expert scanning profiles across 6 categories with aggressiveness ratings |
| 🔧 **Command Factory** | Visual flag canvas builder with real-time conflict resolution and "Save as Preset" |
| 📊 **Scan Dashboard** | Real-time host/port table, XML enrichment for richer version data, session save/load, live log |
| ⚡ **Smart Scan** | Adaptive PID+AIMD rate controller; calibration accepts RST replies as valid RTT samples |
| 🤖 **AI Insights** | Pluggable LLM analysis (OpenAI, Gemini, or built-in Mock); provider config persists across restarts |
| 🌐 **FastAPI service** | REST + NDJSON streaming API with optional X-API-Key auth and per-IP rate limiting |

---

## Bug Fixes (this release)

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

**Preset Library** – Search/filter 29 scans by name, description, or flags.
Click *Run* to execute on the Dashboard, or *To Factory* to inspect the flags
on the canvas.

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
  preset_library.py   29 ScanPreset definitions with 6 categories
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

Tests cover preset library integrity, command factory conflict logic,
LLM response parsing, host record serialization, smart scan discovery,
runtime parser events, and API happy-path.


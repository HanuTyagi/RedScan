# RedScan v2 – Network Intelligence Platform

Conference-demo-ready RedScan with a **unified GUI** and a full backend engine.

---

## Features

| Layer | Description |
|---|---|
| 🎯 **Preset Library** | 25+ expert scanning profiles across 6 categories with aggressiveness ratings |
| 🔧 **Command Factory** | Drag-and-drop canvas builder with real-time conflict resolution |
| 📊 **Scan Dashboard** | Real-time host/port table, session save/load, live output log |
| ⚡ **Smart Scan** | Adaptive PID+AIMD rate controller, configurable via GUI sliders |
| 🤖 **AI Insights** | Pluggable LLM analysis (OpenAI, Gemini, or built-in Mock) |
| 🌐 **FastAPI service** | REST + NDJSON streaming API for headless / programmatic use |

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
uvicorn app:app --reload
```

API endpoints:

- `GET  /health`
- `POST /scan`
- `POST /scan/stream`  (NDJSON)

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

**Preset Library** – Search/filter 25+ scans by name, description, or flags.
Click *Run* to execute on the Dashboard, or *To Factory* to inspect the flags
on the canvas.

**Command Factory** – Pick flag pieces from the left palette; they snap to
the canvas.  Single-select categories (scan type, timing, port scope) are
automatically enforced – conflicting pieces disappear from the palette as soon
as an incompatible piece is placed.  Hit *Run Command* to execute, or
*Save as Preset* to reuse later.

**Scan Dashboard** – Choose a target, preset (or "(none)" for defaults), and
port range, then click *Run Scan*.  The host/port table populates in real time
from Nmap's stdout.  Select a host to see its full port detail.  Sessions can
be saved to JSON and reloaded at any time.

**Smart Scan** – Configure all PID+AIMD parameters via sliders (α, Kp, Ki, Kd,
β, R_min, R_max, loss window, calibration ratio …).  A live rate-history chart
shows the controller in action.

**AI Insights** – Select a provider (Mock/OpenAI/Gemini), enter an API key if
needed, then click *AI Insights* to receive a risk summary and recommendations,
or *What's Next?* for guided follow-up suggestions.

---

## Repository Layout

```
redscan/
  preset_library.py   25+ ScanPreset definitions with 6 categories
  smart_scan.py       Adaptive rate controller (EWMA + PID + AIMD)
  command_factory.py  Graph-based nmap command assembler (networkx)
  runtime_parser.py   Async incremental output parser
  llm.py              Pluggable LLM abstraction + MockLLMProvider
  orchestrator.py     End-to-end pipeline orchestrator
  api.py              FastAPI endpoints
  models.py           Pydantic schemas

gui/
  app.py              CTk main window + sidebar navigation
  styles.py           Colour palette, fonts, layout constants
  views/
    preset_browser.py Scrollable preset card library
    command_factory.py Drag-and-drop flag canvas
    dashboard.py      Real-time scan results table + session I/O
    smart_scan.py     Adaptive scan config panel + rate chart
    llm_panel.py      LLM settings + AI insight display

gui_main.py           GUI entry point
app.py                FastAPI entry point (uvicorn)
scan.py               Legacy CLI
```

---

## Tests

```bash
python -m pytest -q
```

49 tests covering preset library integrity, command factory conflict logic,
LLM response parsing, host record serialization, smart scan discovery,
runtime parser events, and API happy-path.


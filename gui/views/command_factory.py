"""
Command Factory – a palette-and-canvas Nmap command builder.

The palette (left panel) contains flag "pieces" organised by category.  The
user clicks pieces to place them on the canvas (right panel).  When a piece
is placed:

  • The palette hides any mutually-exclusive alternatives for that category.
  • Hard-conflict rules block incompatible flags immediately (e.g. -sn blocks
    the entire port-scope category and the Ports entry widget).
  • A new piece appears on the canvas with a brief fade-in highlight.
  • The live command preview bar at the bottom updates instantly.
  • The ConflictManager runs and shows a colour-coded warning/error bar.
  • The Ports entry widget is automatically disabled when the active flags
    already supply their own port range (-sn / -p- / -F / --top-ports).

The built command can be sent directly to the dashboard (Run Command) or
saved as a named preset.
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import threading
import tkinter as tk
import tkinter.filedialog as filedialog
from pathlib import Path
from typing import Callable

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, BG_CARD, BG_PRIMARY, BG_SECONDARY, BTN_CORNER,
    CARD_CORNER, FONT_BODY, FONT_H1, FONT_H2, FONT_MONO, FONT_SMALL, PAD,
    PAD_S, TEXT_MUTED, TEXT_PRIMARY,
)
from redscan.conflict_manager import ConflictManager, DEFAULT_RULES
from redscan.preset_library import (
    CATEGORY_ICONS, CATEGORY_ORDER, ScanPreset, get_by_category,
)

# Shared, stateless conflict manager instance
_factory_conflict_manager = ConflictManager()


# ---------------------------------------------------------------------------
# Flag / piece definitions
# ---------------------------------------------------------------------------
#
# Each entry: (flag_tokens, display_label, category, description)
# category controls mutual-exclusion: only ONE flag per category can be placed
# (except categories with multi_select=True — those use "detection" / "output" /
# "misc" / "evasion" where multiple flags are independently useful).
#
# Single-select categories: scan_type, timing, port_scope
# Multi-select categories: detection, evasion, output, misc, nse_scripts, operators
#
_FLAG_DEFS: list[tuple[list[str], str, str, str]] = [
    # ── Scan types (single-select) ───────────────────────────────────────────
    (["-sT"],            "-sT  TCP Connect",      "scan_type",   "Full TCP handshake — no root needed"),
    (["-sS"],            "-sS  SYN Stealth",      "scan_type",   "Half-open SYN; fastest; needs root"),
    (["-sU"],            "-sU  UDP Scan",          "scan_type",   "UDP port scan; slow"),
    (["-sA"],            "-sA  ACK Scan",          "scan_type",   "Firewall ruleset mapping"),
    (["-sW"],            "-sW  Window Scan",       "scan_type",   "TCP window field analysis"),
    (["-sM"],            "-sM  Maimon Scan",       "scan_type",   "FIN/ACK probe"),
    (["-sX"],            "-sX  Xmas Scan",         "scan_type",   "FIN+PSH+URG flags"),
    (["-sF"],            "-sF  FIN Scan",          "scan_type",   "FIN only; evades some filters"),
    (["-sN"],            "-sN  NULL Scan",         "scan_type",   "No TCP flags set"),
    (["-sI"],            "-sI  Idle / Zombie",     "scan_type",   "Blind scan via zombie host"),
    (["-sn"],            "-sn  Ping Only",         "scan_type",   "Host discovery only — no port scan"),
    (["-sO"],            "-sO  IP Protocol",       "scan_type",   "Which IP protocols are supported"),

    # ── Timing templates (single-select) ────────────────────────────────────
    (["-T0"],            "-T0  Paranoid",          "timing",      "IDS evasion; very slow (5 min/probe)"),
    (["-T1"],            "-T1  Sneaky",            "timing",      "Slow; avoids most IDS"),
    (["-T2"],            "-T2  Polite",            "timing",      "Slow to conserve bandwidth"),
    (["-T3"],            "-T3  Normal",            "timing",      "Nmap default"),
    (["-T4"],            "-T4  Aggressive",        "timing",      "Fast on good networks"),
    (["-T5"],            "-T5  Insane",            "timing",      "Fastest; may miss results"),

    # ── Port scope (single-select) ────────────────────────────────────────────
    (["-F"],             "-F   Top 100",           "port_scope",  "Scan top 100 common ports"),
    (["-p-"],            "-p-  All 65535",         "port_scope",  "Scan every port (slow!)"),
    (["-p", "1-1024"],   "-p   1-1024",            "port_scope",  "Well-known port range"),
    (["-p", "80,443,8080,8443"], "-p   Web Ports", "port_scope",  "HTTP/HTTPS ports"),
    (["--top-ports", "1000"], "--top-ports 1000",  "port_scope",  "Top 1000 ports by frequency"),
    (["--top-ports", "200"],  "--top-ports 200",   "port_scope",  "Top 200 ports by frequency"),

    # ── Detection (multi-select) ──────────────────────────────────────────────
    (["-sV"],            "-sV  Version",           "detection",   "Service version detection"),
    (["-O"],             "-O   OS Detect",         "detection",   "OS fingerprinting (root)"),
    (["-A"],             "-A   Aggressive",        "detection",   "sV+O+sC+traceroute"),
    (["-sC"],            "-sC  Default Scripts",   "detection",   "Run default NSE scripts"),
    (["--version-intensity", "9"], "--version-intensity 9", "detection", "Max version probe depth"),
    (["--osscan-guess"], "--osscan-guess",          "detection",   "Aggressive OS guess"),
    (["--traceroute"],   "--traceroute",            "detection",   "Trace hop path to host"),

    # ── Evasion (multi-select) ────────────────────────────────────────────────
    (["-f"],             "-f   Fragment",          "evasion",     "Fragment IP packets (8-byte)"),
    (["-ff"],            "-ff  Fragment ×2",       "evasion",     "Fragment IP packets (16-byte)"),
    (["-D", "RND:10"],   "-D   Decoys RND:10",     "evasion",     "Use 10 random decoy IPs"),
    (["-D", "RND:5"],    "-D   Decoys RND:5",      "evasion",     "Use 5 random decoy IPs"),
    (["--data-length", "20"], "--data-length 20",  "evasion",     "Append 20 bytes random data"),
    (["--data-length", "50"], "--data-length 50",  "evasion",     "Append 50 bytes random data"),
    (["--randomize-hosts"], "--randomize-hosts",   "evasion",     "Randomise scan target order"),
    (["--spoof-mac", "0"], "--spoof-mac random",   "evasion",     "Randomise source MAC (LAN)"),
    (["--badsum"],       "--badsum",               "evasion",     "Send packets with bad checksums"),
    (["--scan-delay", "500ms"], "--scan-delay 500ms", "evasion",  "Inter-probe delay for IDS evasion"),

    # ── Operators / performance (multi-select) ───────────────────────────────
    (["-Pn"],            "-Pn  No Ping",           "operators",   "Skip host discovery"),
    (["-n"],             "-n   No DNS",            "operators",   "Skip DNS resolution"),
    (["-R"],             "-R   Always DNS",        "operators",   "Always resolve DNS"),
    (["--min-rate", "100"],  "--min-rate 100",     "operators",   "Send ≥ 100 pkts/s"),
    (["--min-rate", "500"],  "--min-rate 500",     "operators",   "Send ≥ 500 pkts/s"),
    (["--max-retries", "1"], "--max-retries 1",    "operators",   "Max 1 probe retry"),
    (["--max-retries", "3"], "--max-retries 3",    "operators",   "Max 3 probe retries"),
    (["--host-timeout", "30s"], "--host-timeout 30s", "operators", "Abandon host after 30s"),
    (["--defeat-rst-ratelimit"], "--defeat-rst-ratelimit", "operators", "Ignore RST rate limiting"),

    # ── Output (multi-select) ─────────────────────────────────────────────────
    (["-v"],             "-v   Verbose",           "output",      "Verbose output"),
    (["-vv"],            "-vv  Very Verbose",      "output",      "Very verbose output"),
    (["-d"],             "-d   Debug",             "output",      "Debug-level output"),
    (["--reason"],       "--reason",               "output",      "Show port state reason"),
    (["--open"],         "--open",                 "output",      "Show only open ports"),
    (["--packet-trace"], "--packet-trace",         "output",      "Print every packet sent/received"),
    (["-oN", "/tmp/nmap_out.txt"], "-oN  Normal Out", "output",   "Save normal output to file"),
    (["-oX", "/tmp/nmap_out.xml"], "-oX  XML Out",    "output",   "Save XML output to file"),
    (["-oG", "/tmp/nmap_out.gnmap"], "-oG  Grepable", "output",   "Save grepable output to file"),

    # ── NSE Script categories ─────────────────────────────────────────────────
    (["--script", "vuln"],      "🔴 vuln",         "nse_scripts", "Run all vulnerability NSE scripts"),
    (["--script", "auth"],      "🔑 auth",         "nse_scripts", "Authentication/bypass scripts"),
    (["--script", "brute"],     "🔨 brute",        "nse_scripts", "Brute-force credential scripts"),
    (["--script", "discovery"], "🔭 discovery",    "nse_scripts", "Host/service discovery scripts"),
    (["--script", "safe"],      "✅ safe",         "nse_scripts", "Safe, non-intrusive scripts"),
    (["--script", "exploit"],   "💥 exploit",      "nse_scripts", "Exploitation scripts"),
    (["--script", "intrusive"], "⚡ intrusive",    "nse_scripts", "Scripts that may crash services"),
    (["--script", "malware"],   "🦠 malware",      "nse_scripts", "Malware/backdoor detection"),
    (["--script", "fuzzer"],    "🎲 fuzzer",       "nse_scripts", "Protocol fuzzing scripts"),
    # Popular individual scripts
    (["--script", "http-title,http-headers,http-methods"], "🌐 http-info",
                                                   "nse_scripts", "HTTP title, headers, methods"),
    (["--script", "http-vuln-cve2017-5638,http-shellshock"], "🌐 http-vulns",
                                                   "nse_scripts", "Common HTTP vulnerabilities"),
    (["--script", "smb-vuln-ms17-010,smb-security-mode"], "📁 smb-security",
                                                   "nse_scripts", "SMB security + EternalBlue"),
    (["--script", "ssh-hostkey,ssh2-enum-algos"],   "🔒 ssh-info",
                                                   "nse_scripts", "SSH host key and algorithms"),
    (["--script", "ftp-anon,ftp-bounce,ftp-vuln-cve2010-4221"], "📤 ftp-checks",
                                                   "nse_scripts", "FTP anonymous + vulnerabilities"),
    (["--script", "ssl-cert,ssl-enum-ciphers,tls-ticketbleed"], "🔐 ssl-tls",
                                                   "nse_scripts", "SSL/TLS certificate and ciphers"),
    (["--script", "dns-brute,dns-recursion,dns-zone-transfer"], "🌍 dns-recon",
                                                   "nse_scripts", "DNS brute-force and zone transfer"),
    (["--script", "mysql-info,mysql-empty-password"], "🗃 mysql",
                                                   "nse_scripts", "MySQL info and empty passwords"),
    (["--script", "ms-sql-info,ms-sql-empty-password"], "🗃 mssql",
                                                   "nse_scripts", "MSSQL info and empty passwords"),
    (["--script", "rdp-enum-encryption,rdp-vuln-ms12-020"], "🖥 rdp",
                                                   "nse_scripts", "RDP encryption and MS12-020"),
    (["--script", "snmp-info,snmp-processes,snmp-sysdescr"], "📡 snmp",
                                                   "nse_scripts", "SNMP system info"),
]

# ---------------------------------------------------------------------------
# Hard-conflict table
# ---------------------------------------------------------------------------
#
# Maps "category:token" or plain "category" → set of keys to block.
# Blocking by plain category name disables ALL remaining items in that category.
#
_HARD_CONFLICTS: dict[str, set[str]] = {
    # -sn (ping only): no port scan, no port scope, no version/OS detection,
    #  no script categories that probe services.
    "scan_type:sn": {
        "port_scope",    # no point specifying ports
        "nse_scripts",   # service scripts won't work
    },
    # -p- / -F / --top-ports embed their own port range → port entry disabled
    # (handled by ConflictManager.needs_ports_input(), not by palette hiding)
    # Fragmentation incompatible with -sT
    "evasion:f":    {"scan_type:sT"},
    "scan_type:sT": {"evasion:f"},
    # -A subsumes -sV, -sC, -O → hide them from detection palette
    "detection:A":  {"detection:sV", "detection:sC", "detection:O"},
    # -sO (IP protocol scan) is incompatible with port-scope selectors
    "scan_type:sO": {"port_scope"},
}

# Single-select categories (only one piece per category allowed on canvas).
_SINGLE_SELECT_CATS: frozenset[str] = frozenset({"scan_type", "timing", "port_scope"})


def _check_hard_conflict(placed: list["_FlagPieceData"]) -> set[str]:
    """Return the set of keys (category or category:token) that are blocked.

    A blocked key means:
      - If it is a plain category name → all items in that category are hidden.
      - If it is "category:token"      → only that specific first_token is hidden.
    """
    # Map first_token → conflict-key for lookup
    _TOKEN_TO_KEY: dict[str, str] = {
        "-sn": "scan_type:sn",
        "-f":  "evasion:f",
        "-sT": "scan_type:sT",
        "-A":  "detection:A",
        "-sO": "scan_type:sO",
    }
    disabled: set[str] = set()
    for fd in placed:
        conflict_key = _TOKEN_TO_KEY.get(fd.first_token)
        if conflict_key and conflict_key in _HARD_CONFLICTS:
            disabled |= _HARD_CONFLICTS[conflict_key]
    return disabled


# ---------------------------------------------------------------------------
# Canvas piece colours — used for fade-in animation
# ---------------------------------------------------------------------------
# A newly-placed piece starts with a bright highlight colour and gradually
# transitions to the resting colour over ~8 frames (400 ms at 50 ms/frame).

_PIECE_REST_FILL    = "#1a3a5a"
_PIECE_REST_OUTLINE = "#3a7aaa"
_PIECE_NEW_FILL     = "#2a5a8a"
_PIECE_NEW_OUTLINE  = "#7abcee"

_NSE_PIECE_REST_FILL    = "#1a3a2a"
_NSE_PIECE_REST_OUTLINE = "#3aaa6a"
_NSE_PIECE_NEW_FILL     = "#2a6a3a"
_NSE_PIECE_NEW_OUTLINE  = "#7aee9a"


class _FlagPieceData:
    """Data container for a flag definition."""
    def __init__(self, tokens: list[str], label: str, category: str, desc: str) -> None:
        self.tokens = tokens
        self.label = label
        self.category = category
        self.desc = desc
        self.first_token = tokens[0]
        self.is_nse = category == "nse_scripts"


# ---------------------------------------------------------------------------
# CommandFactoryView
# ---------------------------------------------------------------------------

class CommandFactoryView(ctk.CTkFrame):
    """
    Click-to-place Nmap command builder.

    Left:   scrollable palette of flag and NSE-script pieces
    Right:  canvas where placed pieces live
    Bottom: target + ports entry + live command preview + action buttons
    """

    _PIECE_H = 36
    _PIECE_W = 200
    _PAD_X   = 10
    _PAD_Y   = 8
    # Fade-in highlight animation: 8 steps × 50 ms = 400 ms total duration.
    _ANIM_STEPS = 8
    _ANIM_DELAY = 50   # ms per step

    def __init__(
        self,
        master: ctk.CTk | ctk.CTkFrame,
        on_run_command: Callable[[str], None],
        on_save_preset: Callable[[str, str], None],
        on_explain_command: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._on_run = on_run_command
        self._on_save = on_save_preset
        self._on_explain = on_explain_command

        self._flags_data = [_FlagPieceData(*f) for f in _FLAG_DEFS]
        self._placed: list[_FlagPieceData] = []
        # Track canvas item IDs for animation
        self._new_piece_ids: list[tuple[int, int]] = []  # [(rect_id, step)]

        # Command history — most recent runs (capped at 10)
        self._history: list[str] = []

        # Conflict-rule editor: set of rule names the user has muted
        self._disabled_rules: set[str] = set()

        # Drag-to-reorder: per-gesture state
        self._drag_data: dict = {}
        # [(x1, y1, x2, y2, piece_idx)] — rebuilt each _redraw_canvas call
        self._piece_hits: list[tuple[int, int, int, int, int]] = []

        # Diff view: tokens added/removed by the last load_preset call
        self._diff_added: set[str] = set()

        # Macros: {name: [token1, token2, …]}, persisted to ~/.redscan_macros.json
        self._macros: dict[str, list[str]] = {}
        self._macros_path: Path = Path.home() / ".redscan_macros.json"
        self._load_macros()

        self._target_var = tk.StringVar(value="192.168.1.1")
        self._target_var.trace_add("write", lambda *_: self._update_preview())
        self._ports_var = tk.StringVar(value="")
        self._ports_var.trace_add("write", lambda *_: self._update_preview())

        # Palette search variable (wired to _refresh_palette in _build)
        self._search_var = tk.StringVar(value="")

        self._build()

    @staticmethod
    def _safe_grab(window: ctk.CTkToplevel) -> None:
        """Best-effort modal grab that avoids 'window not viewable' TclError."""
        def _apply() -> None:
            try:
                if window.winfo_exists() and window.winfo_viewable():
                    window.grab_set()
            except tk.TclError:
                # Non-fatal; leave dialog modeless instead of crashing callback.
                pass
        window.after(1, _apply)

    # ── Build ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(0, weight=0, minsize=240)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=0)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=PAD, pady=(PAD, 0))
        ctk.CTkLabel(hdr, text="Command Factory", font=FONT_H1, anchor="w").pack(
            side="left"
        )
        ctk.CTkLabel(
            hdr,
            text="Click flag pieces to build · Ports auto-disable for ping/all-port scans",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=PAD)

        # ── Left: search + palette ────────────────────────────────────────────
        left_panel = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        left_panel.grid(row=1, column=0, sticky="nsew", padx=(PAD, PAD_S), pady=PAD)
        left_panel.columnconfigure(0, weight=1)
        left_panel.rowconfigure(0, weight=0)
        left_panel.rowconfigure(1, weight=0)
        left_panel.rowconfigure(2, weight=1)

        ctk.CTkLabel(
            left_panel,
            text="Flag & Script Palette",
            font=("Segoe UI", 10, "bold"),
            text_color="#5588aa",
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=PAD_S, pady=(PAD_S, 0))

        # Palette search/filter entry
        self._search_var.trace_add("write", lambda *_: self._refresh_palette())
        search_entry = ctk.CTkEntry(
            left_panel,
            textvariable=self._search_var,
            placeholder_text="🔍  Filter flags…",
            font=FONT_SMALL,
            height=28,
        )
        search_entry.grid(row=1, column=0, sticky="ew", padx=PAD_S, pady=(PAD_S, 2))

        self._palette_frame = ctk.CTkScrollableFrame(
            left_panel,
            fg_color="transparent",
        )
        self._palette_frame.grid(row=2, column=0, sticky="nsew")

        # ── Right: canvas ────────────────────────────────────────────────────
        canvas_outer = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        canvas_outer.grid(row=1, column=1, sticky="nsew", padx=(PAD_S, PAD), pady=PAD)
        canvas_outer.rowconfigure(0, weight=0)
        canvas_outer.rowconfigure(1, weight=1)
        canvas_outer.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            canvas_outer,
            text="  Canvas — placed flags appear here (click a piece to remove it)",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=PAD_S, pady=PAD_S)

        self._canvas = tk.Canvas(
            canvas_outer,
            bg="#0d1b2a",
            highlightthickness=0,
        )
        self._canvas.grid(row=1, column=0, sticky="nsew", padx=PAD_S, pady=(0, PAD_S))

        # ── Bottom: command preview + controls ────────────────────────────────
        bottom = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        bottom.grid(row=2, column=0, columnspan=2, sticky="ew", padx=PAD, pady=(0, PAD))

        # Target + Ports row
        tp_row = ctk.CTkFrame(bottom, fg_color="transparent")
        tp_row.pack(fill="x", padx=PAD, pady=(PAD_S, 0))

        ctk.CTkLabel(tp_row, text="Target:", font=FONT_SMALL, width=50).pack(side="left")
        ctk.CTkEntry(
            tp_row,
            textvariable=self._target_var,
            width=200,
            font=FONT_SMALL,
        ).pack(side="left", padx=(0, PAD_S))

        # CIDR host-count label — updated in _update_cidr_label()
        self._cidr_lbl = ctk.CTkLabel(
            tp_row,
            text="",
            font=("Segoe UI", 9),
            text_color="#88bbff",
        )
        self._cidr_lbl.pack(side="left", padx=(0, PAD))

        ctk.CTkLabel(tp_row, text="Ports:", font=FONT_SMALL, width=44).pack(side="left")
        self._ports_entry = ctk.CTkEntry(
            tp_row,
            textvariable=self._ports_var,
            width=130,
            font=FONT_SMALL,
            placeholder_text="e.g. 80,443 or 1-1024",
        )
        self._ports_entry.pack(side="left", padx=(0, PAD_S))

        self._ports_status_lbl = ctk.CTkLabel(
            tp_row,
            text="",
            font=("Segoe UI", 9),
            text_color="#888",
        )
        self._ports_status_lbl.pack(side="left", padx=(0, PAD_S))

        # Command preview row (with history button)
        preview_row = ctk.CTkFrame(bottom, fg_color="transparent")
        preview_row.pack(fill="x", padx=PAD, pady=PAD_S)

        ctk.CTkLabel(preview_row, text="Command:", font=FONT_SMALL, width=70).pack(
            side="left"
        )
        self._cmd_var = tk.StringVar(value="nmap  <no flags placed>")
        self._cmd_label = ctk.CTkLabel(
            preview_row,
            textvariable=self._cmd_var,
            font=FONT_MONO,
            text_color="#7feeaa",
            anchor="w",
        )
        self._cmd_label.pack(side="left", fill="x", expand=True)

        # History drop-down button next to the command preview
        ctk.CTkButton(
            preview_row,
            text="📋",
            width=32,
            height=28,
            font=("Segoe UI", 13),
            fg_color="#1a3050",
            hover_color="#2a5080",
            corner_radius=6,
            command=self._show_history_popup,
        ).pack(side="right", padx=(PAD_S, 0))

        # Conflict warning bar (hidden when command is clean)
        self._conflict_bar = ctk.CTkFrame(
            bottom,
            fg_color="#2a1a0a",
            corner_radius=6,
            border_width=1,
            border_color="#8a4a0a",
        )
        self._conflict_text = ctk.CTkLabel(
            self._conflict_bar,
            text="",
            font=FONT_SMALL,
            text_color="#ffcc88",
            wraplength=800,
            justify="left",
            anchor="w",
        )
        self._conflict_text.pack(fill="x", padx=PAD_S, pady=PAD_S)

        # Action buttons
        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=PAD, pady=(0, PAD))

        ctk.CTkButton(
            btn_row,
            text="▶  Run Command",
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER,
            command=self._run_command,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="💾  Save as Preset",
            fg_color="#1e4a6e",
            hover_color="#2a6a9e",
            corner_radius=BTN_CORNER,
            command=self._save_preset_dialog,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="🗑  Clear Canvas",
            fg_color="#3a1a1a",
            hover_color="#5a2a2a",
            corner_radius=BTN_CORNER,
            command=self._clear_canvas,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="📂  Template",
            fg_color="#1a3a2a",
            hover_color="#2a5a3a",
            corner_radius=BTN_CORNER,
            command=self._show_template_dialog,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="🤖  Explain",
            fg_color="#2a1a3a",
            hover_color="#4a2a5a",
            corner_radius=BTN_CORNER,
            command=self._explain_command,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="⚙  Rules",
            fg_color="#1a2a1a",
            hover_color="#2a4a2a",
            corner_radius=BTN_CORNER,
            command=self._show_rules_dialog,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="✓  Validate",
            fg_color="#1a2a3a",
            hover_color="#2a4a5a",
            corner_radius=BTN_CORNER,
            command=self._validate_command,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="🔗  Macros",
            fg_color="#2a1a2a",
            hover_color="#4a2a4a",
            corner_radius=BTN_CORNER,
            command=self._show_macros_dialog,
        ).pack(side="left")

        self._refresh_palette()
        self.after(50, self._redraw_canvas)
        # Drag-to-reorder bindings on the canvas widget
        self._canvas.bind("<B1-Motion>", self._on_drag_motion)
        self._canvas.bind("<ButtonRelease-1>", self._on_drag_end)

    # ── Palette ──────────────────────────────────────────────────────────────

    def _refresh_palette(self) -> None:
        for w in self._palette_frame.winfo_children():
            w.destroy()

        placed_tokens: set[str] = {f.first_token for f in self._placed}
        placed_cats: set[str]   = {f.category for f in self._placed}
        hard_conflicts           = _check_hard_conflict(self._placed)
        search = getattr(self, "_search_var", None)
        search_term = search.get().strip().lower() if search else ""

        current_cat = ""
        for fd in self._flags_data:
            # Skip already-placed token
            if fd.first_token in placed_tokens:
                continue

            # Single-select: skip if another item from this category is placed
            if fd.category in _SINGLE_SELECT_CATS and fd.category in placed_cats:
                continue

            # Hard-conflict check
            blocked = False
            for conflict_key in hard_conflicts:
                if ":" in conflict_key:
                    cat_k, tok_suffix = conflict_key.split(":", 1)
                    # Block this specific token within its category
                    if fd.category == cat_k and fd.first_token.lstrip("-") == tok_suffix:
                        blocked = True
                        break
                    # Also allow plain "category:token" notation for NSE where
                    # first_token starts with "--script" — compare label suffix
                    if fd.category == cat_k and tok_suffix in fd.first_token:
                        blocked = True
                        break
                elif fd.category == conflict_key:
                    blocked = True
                    break
            if blocked:
                continue

            # Search / filter — hide items that don't match the typed term
            if search_term and not any(
                search_term in s.lower()
                for s in (fd.label, fd.desc, fd.category, fd.first_token)
            ):
                continue

            # Category header
            if fd.category != current_cat:
                current_cat = fd.category
                _cat_label = {
                    "scan_type":  "🔍 Scan Type",
                    "timing":     "⏱ Timing",
                    "port_scope": "🔌 Port Scope",
                    "detection":  "📡 Detection",
                    "evasion":    "🕵 Evasion",
                    "operators":  "⚙ Operators",
                    "output":     "📄 Output",
                    "nse_scripts":"📜 NSE Scripts",
                }.get(fd.category, fd.category.title())
                ctk.CTkLabel(
                    self._palette_frame,
                    text=_cat_label,
                    font=("Segoe UI", 9, "bold"),
                    text_color="#5588aa",
                    anchor="w",
                ).pack(fill="x", padx=PAD_S, pady=(PAD_S, 0))

            # Colour NSE pieces distinctly
            fg_c = "#1a3a2a" if fd.is_nse else "#1a3050"
            hv_c = "#2a5a3a" if fd.is_nse else "#2a5080"

            btn = ctk.CTkButton(
                self._palette_frame,
                text=fd.label,
                font=("Courier New", 10),
                height=self._PIECE_H,
                fg_color=fg_c,
                hover_color=hv_c,
                corner_radius=6,
                anchor="w",
                command=lambda f=fd: self._place_piece(f),
            )
            btn.pack(fill="x", padx=PAD_S, pady=2)

            # Tooltip-style description as a muted sub-label
            ctk.CTkLabel(
                self._palette_frame,
                text=f"  {fd.desc}",
                font=("Segoe UI", 8),
                text_color="#4a6a8a",
                anchor="w",
            ).pack(fill="x", padx=(PAD_S + 4, PAD_S))

    def _place_piece(self, fd: _FlagPieceData) -> None:
        # For output flags that write to a file, ask the user to choose a path.
        if fd.category == "output" and fd.first_token in {"-oN", "-oX", "-oG"}:
            fd = self._prompt_output_path(fd)
        self._placed.append(fd)
        self._refresh_palette()
        self._redraw_canvas(new_piece=fd)
        self._update_preview()

    def _prompt_output_path(self, fd: _FlagPieceData) -> _FlagPieceData:
        """Open a save-file dialog so the user can choose the output path for
        nmap output flags (-oN, -oX, -oG).  Returns a new _FlagPieceData with
        the chosen path, or the original (with its default path) if cancelled.
        """
        ext_map = {"-oN": ".txt", "-oX": ".xml", "-oG": ".gnmap"}
        ext = ext_map.get(fd.first_token, ".txt")
        try:
            path = filedialog.asksaveasfilename(
                parent=self,
                title=f"Choose output file for {fd.first_token}",
                defaultextension=ext,
                filetypes=[
                    ("All files", "*.*"),
                    ("Text files", "*.txt"),
                    ("XML files", "*.xml"),
                    ("Grepable files", "*.gnmap"),
                ],
            )
        except Exception:
            path = ""
        if not path:
            return fd
        short = os.path.basename(path)
        return _FlagPieceData(
            tokens=[fd.first_token, path],
            label=f"{fd.first_token}  {short}",
            category=fd.category,
            desc=f"Output to {short}",
        )

    def _remove_piece(self, fd: _FlagPieceData) -> None:
        self._placed = [p for p in self._placed if p is not fd]
        self._refresh_palette()
        self._redraw_canvas()
        self._update_preview()

    # ── Canvas ───────────────────────────────────────────────────────────────

    def _redraw_canvas(self, new_piece: _FlagPieceData | None = None) -> None:
        self._canvas.delete("all")
        self._piece_hits = []

        if not self._placed:
            self._canvas.create_text(
                200, 80,
                text="← Click flag pieces from the palette\n   to build your command",
                fill="#3a5a7a",
                font=("Segoe UI", 13),
                justify="center",
            )
            return

        x, y = 14, 14
        canvas_w = self._canvas.winfo_width() or 700
        row_h = self._PIECE_H + self._PAD_Y
        new_rect_id: int | None = None

        for idx, fd in enumerate(self._placed):
            w = max(self._PIECE_W, len(fd.label) * 9 + 30)
            if x + w > canvas_w - 14 and x > 14:
                x = 14
                y += row_h + 4

            is_new = (fd is new_piece)
            is_diff = fd.first_token in self._diff_added

            if is_new:
                fill    = _NSE_PIECE_NEW_FILL    if fd.is_nse else _PIECE_NEW_FILL
                outline = _NSE_PIECE_NEW_OUTLINE  if fd.is_nse else _PIECE_NEW_OUTLINE
            elif is_diff:
                # Diff-highlight: green tint for pieces added by last load_preset
                fill, outline = "#1a3a1a", "#3aaa3a"
            else:
                fill    = _NSE_PIECE_REST_FILL    if fd.is_nse else _PIECE_REST_FILL
                outline = _NSE_PIECE_REST_OUTLINE  if fd.is_nse else _PIECE_REST_OUTLINE

            txt_c = "#aaffcc" if fd.is_nse else ("#ccffcc" if is_diff else "#aaddff")

            r = self._canvas.create_rectangle(
                x, y, x + w, y + self._PIECE_H,
                fill=fill, outline=outline, width=2,
            )
            self._canvas.create_text(
                x + 10, y + self._PIECE_H // 2,
                text=fd.label,
                fill=txt_c,
                font=("Courier New", 10),
                anchor="w",
            )
            close_x = x + w - 14
            close_y = y + self._PIECE_H // 2
            c = self._canvas.create_text(
                close_x, close_y, text="✕", fill="#e74c3c",
                font=("Segoe UI", 11, "bold"),
            )
            # Close "✕" removes the piece on click (not a drag)
            self._canvas.tag_bind(c, "<Button-1>", lambda _e, f=fd: self._remove_piece(f))
            # Piece body starts a drag on press
            self._canvas.tag_bind(
                r, "<ButtonPress-1>",
                lambda _e, i=idx: self._on_drag_start(_e, i),
            )
            # Record bounding box for hit testing during drag
            self._piece_hits.append((x, y, x + w, y + self._PIECE_H, idx))

            if is_new:
                new_rect_id = r

            x += w + self._PAD_X

        # Kick off fade-in animation for the new piece
        if new_rect_id is not None:
            rest_f   = _NSE_PIECE_REST_FILL    if new_piece and new_piece.is_nse else _PIECE_REST_FILL
            rest_o   = _NSE_PIECE_REST_OUTLINE  if new_piece and new_piece.is_nse else _PIECE_REST_OUTLINE
            self._animate_piece(new_rect_id, self._ANIM_STEPS, rest_f, rest_o)

    def _animate_piece(self, rect_id: int, steps_left: int,
                        rest_fill: str, rest_outline: str) -> None:
        """Gradually fade a newly-placed canvas piece to its resting colour."""
        if steps_left <= 0:
            try:
                self._canvas.itemconfig(rect_id, fill=rest_fill, outline=rest_outline)
            except tk.TclError:
                pass
            return
        # Interpolate towards resting colour each step
        t = 1.0 - steps_left / self._ANIM_STEPS  # 0.0 → 1.0
        fill    = self._lerp_color(_PIECE_NEW_FILL    if rest_fill == _PIECE_REST_FILL    else _NSE_PIECE_NEW_FILL,    rest_fill,    t)
        outline = self._lerp_color(_PIECE_NEW_OUTLINE if rest_outline == _PIECE_REST_OUTLINE else _NSE_PIECE_NEW_OUTLINE, rest_outline, t)
        try:
            self._canvas.itemconfig(rect_id, fill=fill, outline=outline)
        except tk.TclError:
            return  # Item was deleted (user removed piece mid-animation)
        self.after(
            self._ANIM_DELAY,
            lambda: self._animate_piece(rect_id, steps_left - 1, rest_fill, rest_outline),
        )

    @staticmethod
    def _lerp_color(hex_a: str, hex_b: str, t: float) -> str:
        """Linearly interpolate between two hex colours."""
        def _parse(h: str) -> tuple[int, int, int]:
            h = h.lstrip("#")
            return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        r1, g1, b1 = _parse(hex_a)
        r2, g2, b2 = _parse(hex_b)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    # ── Preview + port gating ─────────────────────────────────────────────────

    def _update_preview(self) -> None:
        parts = ["nmap"]
        for fd in self._placed:
            parts.extend(fd.tokens)

        # Append ports if enabled and non-empty
        ports_str = self._ports_var.get().strip()
        if ConflictManager.needs_ports_input(parts) and ports_str:
            parts += ["-p", ports_str]

        target = self._target_var.get().strip() or "<target>"
        parts.append(target)
        self._cmd_var.set(" ".join(parts))
        self._update_cidr_label(target)
        self._refresh_port_gate(parts)
        self._refresh_conflict_bar(parts, target)

    def _refresh_port_gate(self, cmd: list[str]) -> None:
        """Enable or disable the Ports entry widget based on active flags."""
        want_input = ConflictManager.needs_ports_input(cmd)
        if want_input:
            self._ports_entry.configure(state="normal", text_color=TEXT_PRIMARY)
            self._ports_status_lbl.configure(text="")
        else:
            # Determine the reason
            flags = set(cmd)
            if flags & {"-sn"}:
                reason = "disabled — ping-only scan"
            elif "-p-" in flags:
                reason = "disabled — all 65535 ports"
            elif "-F" in flags:
                reason = "disabled — top-100 ports"
            elif "--top-ports" in flags:
                reason = "disabled — --top-ports set"
            else:
                reason = "disabled"
            self._ports_entry.configure(state="disabled", text_color="#555")
            self._ports_status_lbl.configure(text=f"({reason})", text_color="#777")

    def _refresh_conflict_bar(self, cmd: list[str], target: str) -> None:
        """Run the conflict manager and update the warning bar."""
        if not self._placed:
            self._conflict_bar.pack_forget()
            return

        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            is_root = True

        _, messages = ConflictManager(disabled_rules=self._disabled_rules).apply(
            cmd, target, "", is_root
        )
        if not messages:
            self._conflict_bar.pack_forget()
            return

        severity_order = {"error": 0, "warning": 1, "auto_fix": 2, "info": 3}
        worst = min(messages, key=lambda m: severity_order.get(m[0], 99))[0]
        bar_colors = {
            "error":    ("#2a0a0a", "#aa2a2a"),
            "warning":  ("#2a1a0a", "#8a4a0a"),
            "auto_fix": ("#0a1a2a", "#2a6aaa"),
            "info":     ("#0a1a0a", "#2a6a2a"),
        }
        text_colors = {
            "error":    "#ffaaaa",
            "warning":  "#ffcc88",
            "auto_fix": "#88ccff",
            "info":     "#aaffaa",
        }
        fg, border = bar_colors.get(worst, ("#1a1a1a", "#444"))
        tc = text_colors.get(worst, "#cccccc")
        self._conflict_bar.configure(fg_color=fg, border_color=border)
        self._conflict_text.configure(text_color=tc)

        lines = [
            f"{'⛔' if sev == 'error' else '⚠' if sev == 'warning' else '🔧' if sev == 'auto_fix' else 'ℹ'}  {text}"
            for sev, text in messages
        ]
        self._conflict_text.configure(text="\n".join(lines))
        self._conflict_bar.pack(fill="x", padx=PAD, pady=(0, PAD_S))
        self._conflict_bar.lift()

    # ── Public API ────────────────────────────────────────────────────────────

    def get_command(self) -> str:
        self._update_preview()
        return self._cmd_var.get()

    def load_preset(self, preset: ScanPreset) -> None:
        """Load a preset's flags + scripts into the canvas, highlighting new pieces."""
        before_tokens = {fd.first_token for fd in self._placed}
        self._clear_canvas()
        preset_flags = list(preset.flags)
        preset_scripts = list(preset.scripts)

        for fd in self._flags_data:
            n = len(fd.tokens)
            # Match flags
            matched_flag = any(
                preset_flags[i: i + n] == fd.tokens
                for i in range(len(preset_flags) - n + 1)
            )
            # Match NSE script pieces
            matched_script = False
            if fd.is_nse and preset_scripts:
                script_val = fd.tokens[1] if len(fd.tokens) > 1 else ""
                # Check if any script in the preset matches this piece's script list
                piece_scripts = {s.strip() for s in script_val.split(",")}
                matched_script = bool(piece_scripts & set(preset_scripts))
            if matched_flag or matched_script:
                self._placed.append(fd)
        # Record which tokens are new (for diff highlighting)
        after_tokens = {fd.first_token for fd in self._placed}
        self._diff_added = after_tokens - before_tokens
        self._redraw_canvas()
        self._refresh_palette()
        self._update_preview()
        # Clear diff highlights after 2 s so the canvas returns to normal
        self.after(2000, self._clear_diff)

    # ── Actions ──────────────────────────────────────────────────────────────

    def _clear_canvas(self) -> None:
        self._placed.clear()
        self._diff_added = set()
        self._redraw_canvas()
        self._refresh_palette()
        self._update_preview()

    def _run_command(self) -> None:
        cmd = self.get_command()
        # Record in history (dedup, most-recent-first, capped at 10)
        if cmd and "<no flags" not in cmd:
            if cmd in self._history:
                self._history.remove(cmd)
            self._history.append(cmd)
            if len(self._history) > 10:
                self._history.pop(0)
        self._on_run(cmd)

    def _save_preset_dialog(self) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("Save as Preset")
        dlg.geometry("400x180")
        self._safe_grab(dlg)

        ctk.CTkLabel(dlg, text="Preset Name:", font=FONT_SMALL).pack(padx=PAD, pady=(PAD, 0), anchor="w")
        name_entry = ctk.CTkEntry(dlg, font=FONT_BODY, placeholder_text="My Custom Scan")
        name_entry.pack(fill="x", padx=PAD, pady=PAD_S)

        ctk.CTkLabel(dlg, text="Description (optional):", font=FONT_SMALL).pack(padx=PAD, anchor="w")
        desc_entry = ctk.CTkEntry(dlg, font=FONT_SMALL, placeholder_text="…")
        desc_entry.pack(fill="x", padx=PAD, pady=PAD_S)

        def _save() -> None:
            name = name_entry.get().strip()
            desc = desc_entry.get().strip()
            if name:
                self._on_save(name, desc)
            dlg.destroy()

        ctk.CTkButton(dlg, text="Save", fg_color=ACCENT, command=_save).pack(pady=PAD)

    # ── New enhancement methods ───────────────────────────────────────────────

    def _update_cidr_label(self, target: str) -> None:
        """Show an approximate host count when the target contains a CIDR prefix."""
        if "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
                count = net.num_addresses
                # For IPv4 subtract network and broadcast addresses
                if net.version == 4 and count > 2:
                    count -= 2
                self._cidr_lbl.configure(text=f"(~{count:,} hosts)", text_color="#88bbff")
                return
            except ValueError:
                pass
        self._cidr_lbl.configure(text="")

    def _show_history_popup(self) -> None:
        """Show the last 10 run commands in a popup; clicking Re-run sends them
        to the dashboard immediately."""
        popup = ctk.CTkToplevel(self)
        popup.title("Command History")
        popup.geometry("740x320")
        self._safe_grab(popup)

        if not self._history:
            ctk.CTkLabel(
                popup,
                text="No commands in history yet.\nRun a command to start recording.",
                font=FONT_SMALL,
                justify="center",
            ).pack(padx=PAD, pady=PAD, expand=True)
            ctk.CTkButton(popup, text="Close", command=popup.destroy).pack(pady=(0, PAD))
            return

        ctk.CTkLabel(
            popup,
            text="Recent commands — click ▶ Run to send directly to the Dashboard:",
            font=FONT_SMALL,
            anchor="w",
        ).pack(padx=PAD, pady=(PAD, 0), anchor="w")

        frame = ctk.CTkScrollableFrame(popup, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=PAD, pady=PAD_S)

        for cmd in reversed(self._history):
            row = ctk.CTkFrame(frame, fg_color="#1a2a3a", corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(
                row,
                text=cmd,
                font=FONT_MONO,
                text_color="#7feeaa",
                anchor="w",
                wraplength=580,
            ).pack(side="left", fill="x", expand=True, padx=PAD_S, pady=4)
            ctk.CTkButton(
                row,
                text="▶ Run",
                width=70,
                height=28,
                font=FONT_SMALL,
                fg_color=ACCENT,
                hover_color=ACCENT_HOVER,
                corner_radius=6,
                command=lambda c=cmd: (self._on_run(c), popup.destroy()),
            ).pack(side="right", padx=(0, PAD_S), pady=4)

        ctk.CTkButton(popup, text="Close", command=popup.destroy).pack(pady=(0, PAD))

    def _show_template_dialog(self) -> None:
        """Show a dialog listing preset categories so the user can pre-load a
        representative template onto the canvas."""
        popup = ctk.CTkToplevel(self)
        popup.title("Start from Template")
        popup.geometry("480x440")
        self._safe_grab(popup)

        ctk.CTkLabel(
            popup,
            text="Choose a preset category to pre-load its flags onto the canvas:",
            font=FONT_SMALL,
            anchor="w",
        ).pack(padx=PAD, pady=(PAD, 0), anchor="w")

        groups = get_by_category()
        frame = ctk.CTkScrollableFrame(popup, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=PAD, pady=PAD_S)

        for cat in CATEGORY_ORDER:
            presets = groups.get(cat, [])
            if not presets:
                continue
            preset = presets[0]  # first preset is the representative
            icon = CATEGORY_ICONS.get(cat, "📄")

            row = ctk.CTkFrame(frame, fg_color="#1a2a3a", corner_radius=8)
            row.pack(fill="x", pady=3)
            row.columnconfigure(0, weight=1)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=PAD_S, pady=PAD_S)
            ctk.CTkLabel(
                info,
                text=f"{icon}  {cat}",
                font=("Segoe UI", 11, "bold"),
                text_color="#aaddff",
                anchor="w",
            ).pack(anchor="w")
            ctk.CTkLabel(
                info,
                text=f"e.g. {preset.name}",
                font=FONT_SMALL,
                text_color="#6a8aaa",
                anchor="w",
            ).pack(anchor="w")

            ctk.CTkButton(
                row,
                text="Load",
                width=70,
                height=28,
                font=FONT_SMALL,
                fg_color="#1e4a6e",
                hover_color="#2a6a9e",
                corner_radius=6,
                command=lambda p=preset: (self.load_preset(p), popup.destroy()),
            ).pack(side="right", padx=PAD_S, pady=PAD_S)

        ctk.CTkButton(popup, text="Cancel", command=popup.destroy).pack(
            pady=(0, PAD)
        )

    def _explain_command(self) -> None:
        """Send the current command to the LLM panel for a plain-English
        explanation.  If no callback was wired, shows a small info dialog."""
        cmd = self.get_command()
        if self._on_explain:
            self._on_explain(cmd)
        else:
            dlg = ctk.CTkToplevel(self)
            dlg.title("Explain Command")
            dlg.geometry("440x160")
            self._safe_grab(dlg)
            ctk.CTkLabel(
                dlg,
                text=(
                    "The LLM Insights panel is not connected.\n"
                    "Navigate to the AI Insights view to use this feature."
                ),
                font=FONT_SMALL,
                justify="center",
                wraplength=400,
            ).pack(padx=PAD, pady=PAD, expand=True)
            ctk.CTkButton(dlg, text="OK", command=dlg.destroy).pack(pady=(0, PAD))

    # ── Drag-to-reorder canvas pieces ────────────────────────────────────────

    _DRAG_THRESHOLD = 6  # pixels — below this a "drag" is treated as a click

    def _on_drag_start(self, event: tk.Event, piece_idx: int) -> None:
        self._drag_data = {
            "idx": piece_idx,
            "x0": event.x,
            "y0": event.y,
            "dragging": False,
        }

    def _on_drag_motion(self, event: tk.Event) -> None:
        dd = self._drag_data
        if not dd:
            return
        dx = abs(event.x - dd["x0"])
        dy = abs(event.y - dd["y0"])
        if not dd["dragging"] and (dx > self._DRAG_THRESHOLD or dy > self._DRAG_THRESHOLD):
            dd["dragging"] = True
        if dd["dragging"]:
            # Draw a vertical insertion indicator
            self._canvas.delete("drag_indicator")
            ins = self._get_insert_idx(event.x, event.y)
            x_ins = self._get_insert_x(ins)
            if x_ins >= 0:
                y1 = max(0, event.y - 20)
                y2 = event.y + 20
                self._canvas.create_line(
                    x_ins, y1, x_ins, y2,
                    fill="#ffdd44", width=3, tags="drag_indicator",
                )

    def _on_drag_end(self, event: tk.Event) -> None:
        dd = self._drag_data
        if not dd:
            return
        if dd.get("dragging"):
            self._canvas.delete("drag_indicator")
            src_idx = dd["idx"]
            ins_idx = self._get_insert_idx(event.x, event.y)
            # Adjust for removal of src element before insertion
            if ins_idx > src_idx:
                ins_idx -= 1
            if ins_idx != src_idx and 0 <= src_idx < len(self._placed):
                piece = self._placed.pop(src_idx)
                self._placed.insert(ins_idx, piece)
                self._diff_added = set()
                self._redraw_canvas()
                self._update_preview()
        self._drag_data = {}

    def _get_insert_idx(self, x: int, y: int) -> int:
        """Return the insertion index (0..len) corresponding to canvas position (x, y)."""
        if not self._piece_hits:
            return len(self._placed)
        best_idx = len(self._placed)
        best_dist = float("inf")
        for x1, y1, x2, y2, idx in self._piece_hits:
            cx = (x1 + x2) / 2
            cy = (y1 + y2) / 2
            dist = abs(x - cx) + abs(y - cy) * 2  # weight vertical distance more
            if dist < best_dist:
                best_dist = dist
                # If cursor is left of piece midpoint → insert before; else after
                best_idx = idx if x < cx else idx + 1
        return max(0, min(best_idx, len(self._placed)))

    def _get_insert_x(self, ins_idx: int) -> int:
        """Return the x coordinate for the insertion indicator line."""
        if not self._piece_hits:
            return -1
        if ins_idx == 0:
            return self._piece_hits[0][0] - 4
        if ins_idx >= len(self._piece_hits):
            return self._piece_hits[-1][2] + 4
        return (self._piece_hits[ins_idx - 1][2] + self._piece_hits[ins_idx][0]) // 2

    # ── Conflict rule editor ─────────────────────────────────────────────────

    def _show_rules_dialog(self) -> None:
        """Open a panel listing all conflict rules with per-rule on/off toggles."""
        popup = ctk.CTkToplevel(self)
        popup.title("Conflict Rule Editor")
        popup.geometry("700x500")
        self._safe_grab(popup)

        ctk.CTkLabel(
            popup,
            text="Toggle rules on/off — disabled rules are skipped by the conflict checker:",
            font=FONT_SMALL,
            anchor="w",
        ).pack(padx=PAD, pady=(PAD, 0), anchor="w")

        sev_icons = {
            "auto_fix": "🔧",
            "warning":  "⚠",
            "error":    "⛔",
            "info":     "ℹ",
        }
        sev_colors = {
            "auto_fix": "#88ccff",
            "warning":  "#ffcc88",
            "error":    "#ffaaaa",
            "info":     "#aaffaa",
        }

        scroll = ctk.CTkScrollableFrame(popup, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=PAD, pady=PAD_S)

        # Track vars so we can read them on "Apply"
        check_vars: dict[str, tk.BooleanVar] = {}

        for rule in DEFAULT_RULES:
            enabled = rule.name not in self._disabled_rules
            var = tk.BooleanVar(value=enabled)
            check_vars[rule.name] = var

            row = ctk.CTkFrame(scroll, fg_color="#1a2a3a", corner_radius=6)
            row.pack(fill="x", pady=2)

            ctk.CTkCheckBox(
                row,
                text="",
                variable=var,
                width=30,
                fg_color=ACCENT,
                hover_color=ACCENT_HOVER,
            ).pack(side="left", padx=(PAD_S, 0), pady=6)

            icon = sev_icons.get(rule.severity, "•")
            col = sev_colors.get(rule.severity, "#cccccc")
            ctk.CTkLabel(
                row,
                text=f"{icon} {rule.severity}",
                font=("Segoe UI", 9, "bold"),
                text_color=col,
                width=80,
            ).pack(side="left", padx=(PAD_S, 0))

            ctk.CTkLabel(
                row,
                text=rule.name.replace("_", " "),
                font=FONT_SMALL,
                text_color="#aaddff",
                anchor="w",
            ).pack(side="left", fill="x", expand=True, padx=PAD_S)

        def _apply_rules() -> None:
            self._disabled_rules = {
                name for name, var in check_vars.items() if not var.get()
            }
            self._update_preview()
            popup.destroy()

        btn_row = ctk.CTkFrame(popup, fg_color="transparent")
        btn_row.pack(fill="x", padx=PAD, pady=(0, PAD))
        ctk.CTkButton(
            btn_row, text="Apply", fg_color=ACCENT, hover_color=ACCENT_HOVER,
            command=_apply_rules,
        ).pack(side="left", padx=(0, PAD_S))
        ctk.CTkButton(
            btn_row, text="Enable All",
            fg_color="#1a3a1a", hover_color="#2a5a2a",
            command=lambda: [v.set(True) for v in check_vars.values()],
        ).pack(side="left", padx=(0, PAD_S))
        ctk.CTkButton(
            btn_row, text="Cancel", fg_color="#3a1a1a", hover_color="#5a2a2a",
            command=popup.destroy,
        ).pack(side="left")

    # ── Live nmap validation ─────────────────────────────────────────────────

    def _validate_command(self) -> None:
        """Check nmap availability and flag syntax in a background thread."""
        popup = ctk.CTkToplevel(self)
        popup.title("Validate Command")
        popup.geometry("640x380")
        self._safe_grab(popup)

        status_var = tk.StringVar(value="⏳  Running validation…")
        ctk.CTkLabel(
            popup, textvariable=status_var, font=FONT_SMALL,
        ).pack(padx=PAD, pady=(PAD, 0), anchor="w")

        result_box = ctk.CTkTextbox(popup, font=FONT_MONO, fg_color="#0d1b2a",
                                    text_color="#7feeaa", state="disabled")
        result_box.pack(fill="both", expand=True, padx=PAD, pady=PAD_S)
        ctk.CTkButton(popup, text="Close", command=popup.destroy).pack(pady=(0, PAD))

        cmd = self.get_command().split()

        def _run() -> None:
            lines: list[str] = []
            # --- nmap version ---
            try:
                ver_res = subprocess.run(
                    ["nmap", "--version"],
                    capture_output=True, text=True, timeout=8,
                )
                if ver_res.returncode == 0:
                    first_line = ver_res.stdout.splitlines()[0] if ver_res.stdout else ""
                    lines.append(f"✅  nmap found: {first_line}")
                else:
                    lines.append("❌  nmap --version returned non-zero exit code.")
                    lines.append(ver_res.stderr.strip())
            except FileNotFoundError:
                lines.append("❌  nmap is NOT on PATH.  Install nmap to use this feature.")
                _post(lines, ok=False)
                return
            except Exception as exc:
                lines.append(f"❌  Error running nmap: {exc}")
                _post(lines, ok=False)
                return

            # --- ConflictManager check ---
            target = self._target_var.get().strip() or "127.0.0.1"
            ports_str = self._ports_var.get().strip()
            try:
                is_root = os.geteuid() == 0
            except AttributeError:
                is_root = True
            _, messages = ConflictManager(
                disabled_rules=self._disabled_rules,
            ).apply(cmd, target, ports_str, is_root)
            if not messages:
                lines.append("✅  No conflict-manager warnings.")
            for sev, txt in messages:
                icon = "⛔" if sev == "error" else ("⚠" if sev == "warning" else "🔧")
                lines.append(f"{icon}  [{sev}] {txt}")

            # --- list-targets dry-run ---
            try:
                user_flags = [t for t in cmd if t.startswith("-")]
                dry_cmd = ["nmap", "-sL", "-n"] + user_flags + ["192.0.2.0/30"]
                dry_res = subprocess.run(
                    dry_cmd, capture_output=True, text=True, timeout=12,
                )
                if dry_res.returncode == 0:
                    lines.append("✅  nmap accepted the flags (list-targets dry-run passed).")
                else:
                    err = (dry_res.stderr or dry_res.stdout).strip()
                    lines.append(f"⚠   nmap flag syntax issue:\n    {err}")
            except Exception as exc:
                lines.append(f"ℹ   Could not run dry-run check: {exc}")

            _post(lines, ok=True)

        def _post(lines: list[str], ok: bool) -> None:
            def _update() -> None:
                if not popup.winfo_exists():
                    return
                status_var.set("✅  Validation complete." if ok else "❌  Validation failed.")
                result_box.configure(state="normal")
                result_box.delete("0.0", "end")
                result_box.insert("end", "\n\n".join(lines))
                result_box.configure(state="disabled")
            popup.after(0, _update)

        threading.Thread(target=_run, daemon=True).start()

    # ── Command diff helper ───────────────────────────────────────────────────

    def _clear_diff(self) -> None:
        """Remove diff highlighting and redraw the canvas normally."""
        if self._diff_added:
            self._diff_added = set()
            self._redraw_canvas()

    # ── Macros ───────────────────────────────────────────────────────────────

    def _load_macros(self) -> None:
        try:
            if self._macros_path.exists():
                data = json.loads(self._macros_path.read_text())
                if isinstance(data, dict):
                    self._macros = data
        except Exception:
            self._macros = {}

    def _save_macros(self) -> None:
        try:
            self._macros_path.write_text(json.dumps(self._macros, indent=2))
        except OSError:
            pass

    def _show_macros_dialog(self) -> None:
        """Manage piece groups / macros: save the current canvas as a macro,
        or merge-load a saved macro onto the canvas."""
        popup = ctk.CTkToplevel(self)
        popup.title("Piece Macros")
        popup.geometry("600x460")
        self._safe_grab(popup)

        # ── Save current canvas as macro ──────────────────────────────────────
        save_frame = ctk.CTkFrame(popup, fg_color="#1a2a3a", corner_radius=8)
        save_frame.pack(fill="x", padx=PAD, pady=(PAD, PAD_S))

        ctk.CTkLabel(
            save_frame,
            text="💾  Save current canvas as a macro:",
            font=("Segoe UI", 11, "bold"),
            text_color="#aaddff",
            anchor="w",
        ).pack(padx=PAD_S, pady=(PAD_S, 0), anchor="w")

        name_row = ctk.CTkFrame(save_frame, fg_color="transparent")
        name_row.pack(fill="x", padx=PAD_S, pady=PAD_S)
        name_entry = ctk.CTkEntry(
            name_row,
            font=FONT_SMALL,
            placeholder_text="Macro name, e.g. Web Recon",
            width=300,
        )
        name_entry.pack(side="left", padx=(0, PAD_S))

        def _save_macro() -> None:
            name = name_entry.get().strip()
            if not name:
                return
            tokens = [fd.first_token for fd in self._placed]
            if not tokens:
                return
            self._macros[name] = tokens
            self._save_macros()
            name_entry.delete(0, "end")
            _refresh_list()

        ctk.CTkButton(
            name_row,
            text="Save Macro",
            width=110,
            fg_color="#1e4a6e",
            hover_color="#2a6a9e",
            corner_radius=6,
            font=FONT_SMALL,
            command=_save_macro,
        ).pack(side="left")

        # ── Saved macros list ─────────────────────────────────────────────────
        ctk.CTkLabel(
            popup,
            text="Saved macros — click ▶ Load to merge-place onto canvas, 🗑 to delete:",
            font=FONT_SMALL,
            anchor="w",
        ).pack(padx=PAD, pady=(0, 0), anchor="w")

        list_frame = ctk.CTkScrollableFrame(popup, fg_color="transparent")
        list_frame.pack(fill="both", expand=True, padx=PAD, pady=PAD_S)

        def _refresh_list() -> None:
            for w in list_frame.winfo_children():
                w.destroy()
            if not self._macros:
                ctk.CTkLabel(
                    list_frame,
                    text="No macros saved yet.",
                    font=FONT_SMALL,
                    text_color=TEXT_MUTED,
                ).pack(pady=PAD)
                return
            for macro_name, tokens in list(self._macros.items()):
                row = ctk.CTkFrame(list_frame, fg_color="#1a2a3a", corner_radius=6)
                row.pack(fill="x", pady=2)

                info = ctk.CTkFrame(row, fg_color="transparent")
                info.pack(side="left", fill="x", expand=True, padx=PAD_S, pady=4)
                ctk.CTkLabel(
                    info,
                    text=macro_name,
                    font=("Segoe UI", 11, "bold"),
                    text_color="#aaddff",
                    anchor="w",
                ).pack(anchor="w")
                ctk.CTkLabel(
                    info,
                    text="  ".join(tokens[:8]) + ("  …" if len(tokens) > 8 else ""),
                    font=("Courier New", 9),
                    text_color="#5588aa",
                    anchor="w",
                ).pack(anchor="w")

                ctk.CTkButton(
                    row,
                    text="▶ Load",
                    width=72,
                    height=28,
                    font=FONT_SMALL,
                    fg_color=ACCENT,
                    hover_color=ACCENT_HOVER,
                    corner_radius=6,
                    command=lambda t=tokens: self._merge_macro(t),
                ).pack(side="right", padx=(0, PAD_S), pady=4)

                def _delete(n: str = macro_name) -> None:
                    self._macros.pop(n, None)
                    self._save_macros()
                    _refresh_list()

                ctk.CTkButton(
                    row,
                    text="🗑",
                    width=36,
                    height=28,
                    font=("Segoe UI", 13),
                    fg_color="#3a1a1a",
                    hover_color="#5a2a2a",
                    corner_radius=6,
                    command=_delete,
                ).pack(side="right", pady=4)

        _refresh_list()
        ctk.CTkButton(popup, text="Close", command=popup.destroy).pack(pady=(0, PAD))

    def _merge_macro(self, tokens: list[str]) -> None:
        """Merge-load a macro by placing any of its pieces that aren't already
        on the canvas and that aren't blocked by conflict rules."""
        placed_tokens = {fd.first_token for fd in self._placed}
        before_tokens = set(placed_tokens)
        added = False
        for fd in self._flags_data:
            if fd.first_token in tokens and fd.first_token not in placed_tokens:
                self._placed.append(fd)
                placed_tokens.add(fd.first_token)
                added = True
        if added:
            after_tokens = {fd.first_token for fd in self._placed}
            self._diff_added = after_tokens - before_tokens
            self._redraw_canvas()
            self._refresh_palette()
            self._update_preview()
            self.after(2000, self._clear_diff)

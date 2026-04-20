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

import os
import tkinter as tk
from typing import Callable

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, BG_CARD, BG_PRIMARY, BG_SECONDARY, BTN_CORNER,
    CARD_CORNER, FONT_BODY, FONT_H1, FONT_H2, FONT_MONO, FONT_SMALL, PAD,
    PAD_S, TEXT_MUTED, TEXT_PRIMARY,
)
from redscan.conflict_manager import ConflictManager
from redscan.preset_library import ScanPreset

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
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._on_run = on_run_command
        self._on_save = on_save_preset

        self._flags_data = [_FlagPieceData(*f) for f in _FLAG_DEFS]
        self._placed: list[_FlagPieceData] = []
        # Track canvas item IDs for animation
        self._new_piece_ids: list[tuple[int, int]] = []  # [(rect_id, step)]

        self._target_var = tk.StringVar(value="192.168.1.1")
        self._target_var.trace_add("write", lambda *_: self._update_preview())
        self._ports_var = tk.StringVar(value="")
        self._ports_var.trace_add("write", lambda *_: self._update_preview())

        self._build()

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

        # ── Left: palette ────────────────────────────────────────────────────
        self._palette_frame = ctk.CTkScrollableFrame(
            self, width=240, fg_color=BG_SECONDARY, label_text="Flag & Script Palette"
        )
        self._palette_frame.grid(
            row=1, column=0, sticky="nsew", padx=(PAD, PAD_S), pady=PAD
        )

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
        ).pack(side="left", padx=(0, PAD))

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

        # Command preview row
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
        ).pack(side="left")

        self._refresh_palette()
        self.after(50, self._redraw_canvas)

    # ── Palette ──────────────────────────────────────────────────────────────

    def _refresh_palette(self) -> None:
        for w in self._palette_frame.winfo_children():
            w.destroy()

        placed_tokens: set[str] = {f.first_token for f in self._placed}
        placed_cats: set[str]   = {f.category for f in self._placed}
        hard_conflicts           = _check_hard_conflict(self._placed)

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
        self._placed.append(fd)
        self._refresh_palette()
        self._redraw_canvas(new_piece=fd)
        self._update_preview()

    def _remove_piece(self, fd: _FlagPieceData) -> None:
        self._placed = [p for p in self._placed if p is not fd]
        self._refresh_palette()
        self._redraw_canvas()
        self._update_preview()

    # ── Canvas ───────────────────────────────────────────────────────────────

    def _redraw_canvas(self, new_piece: _FlagPieceData | None = None) -> None:
        self._canvas.delete("all")
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
            fill    = (_NSE_PIECE_NEW_FILL    if fd.is_nse else _PIECE_NEW_FILL)    if is_new else (_NSE_PIECE_REST_FILL    if fd.is_nse else _PIECE_REST_FILL)
            outline = (_NSE_PIECE_NEW_OUTLINE  if fd.is_nse else _PIECE_NEW_OUTLINE) if is_new else (_NSE_PIECE_REST_OUTLINE if fd.is_nse else _PIECE_REST_OUTLINE)
            txt_c   = "#aaffcc" if fd.is_nse else "#aaddff"

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
            self._canvas.tag_bind(c, "<Button-1>", lambda _e, f=fd: self._remove_piece(f))
            self._canvas.tag_bind(r, "<Button-1>", lambda _e, f=fd: self._remove_piece(f))

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

        _, messages = _factory_conflict_manager.apply(cmd, target, "", is_root)
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
        """Load a preset's flags + scripts into the canvas."""
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
        self._redraw_canvas()
        self._refresh_palette()
        self._update_preview()

    # ── Actions ──────────────────────────────────────────────────────────────

    def _clear_canvas(self) -> None:
        self._placed.clear()
        self._redraw_canvas()
        self._refresh_palette()
        self._update_preview()

    def _run_command(self) -> None:
        self._on_run(self.get_command())

    def _save_preset_dialog(self) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("Save as Preset")
        dlg.geometry("400x180")
        dlg.grab_set()

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


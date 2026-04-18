"""
Command Factory – a drag-and-drop canvas-based Nmap command builder.

The palette (left panel) contains flag "pieces".  The user drags pieces onto
the canvas (right panel).  When a piece is placed the palette updates in real
time to disable any flag that conflicts with the active set.  A preview bar
below the canvas always shows the live nmap command.  The built command can be
sent directly to the dashboard (run now) or saved as a preset.
"""
from __future__ import annotations

import tkinter as tk
from typing import Callable

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, BG_CARD, BG_PRIMARY, BG_SECONDARY, BTN_CORNER,
    CARD_CORNER, FONT_BODY, FONT_H1, FONT_H2, FONT_MONO, FONT_SMALL, PAD,
    PAD_S, TEXT_MUTED, TEXT_PRIMARY,
)
from redscan.preset_library import ScanPreset


# ---------------------------------------------------------------------------
# Flag definitions and conflict catalogue
# ---------------------------------------------------------------------------

# Each entry: (flag_tokens, display_label, category, description)
# category controls mutual-exclusion: only one flag per category is allowed.
_FLAG_DEFS: list[tuple[list[str], str, str, str]] = [
    # Scan types
    (["-sT"],            "-sT  TCP Connect",   "scan_type", "Full TCP handshake"),
    (["-sS"],            "-sS  SYN Stealth",   "scan_type", "Half-open; needs root"),
    (["-sU"],            "-sU  UDP Scan",       "scan_type", "UDP ports; slow"),
    (["-sX"],            "-sX  Xmas Scan",      "scan_type", "FIN+PSH+URG flags"),
    (["-sF"],            "-sF  FIN Scan",       "scan_type", "FIN only; evades some filters"),
    (["-sN"],            "-sN  NULL Scan",      "scan_type", "No flags set"),
    (["-sn"],            "-sn  Ping Only",      "scan_type", "Host discovery, no port scan"),

    # Timing templates
    (["-T0"],            "-T0  Paranoid",       "timing", "IDS evasion, very slow"),
    (["-T1"],            "-T1  Sneaky",         "timing", "Slow, avoids most IDS"),
    (["-T2"],            "-T2  Polite",         "timing", "Slower to avoid bandwidth"),
    (["-T3"],            "-T3  Normal",         "timing", "Default Nmap timing"),
    (["-T4"],            "-T4  Aggressive",     "timing", "Fast on good networks"),
    (["-T5"],            "-T5  Insane",         "timing", "Fastest, may miss results"),

    # Port scope (only one at a time)
    (["-F"],             "-F   Top 100",        "port_scope", "Scan top 100 ports"),
    (["-p-"],            "-p-  All Ports",      "port_scope", "Full 1-65535 range"),
    (["-p", "1-1024"],   "-p   1-1024",         "port_scope", "Well-known port range"),

    # Version / OS detection (multi-select allowed → category="detection")
    (["-sV"],            "-sV  Version",        "detection", "Service version detection"),
    (["-O"],             "-O   OS Detect",      "detection", "OS fingerprinting (root)"),
    (["-A"],             "-A   Aggressive",     "detection", "sV+O+scripts+traceroute"),
    (["-sC"],            "-sC  Default Scripts","detection", "Run default NSE scripts"),

    # Evasion
    (["-f"],             "-f   Fragment",       "evasion", "Fragment IP packets"),
    (["-D", "RND:10"],   "-D   Decoys",         "evasion", "Use random decoy IPs"),
    (["--data-length", "20"], "--data-length",  "evasion", "Append random data"),

    # Output
    (["-v"],             "-v   Verbose",        "output", "Verbose output"),
    (["-vv"],            "-vv  Very Verbose",   "output", "Very verbose output"),
    (["--reason"],       "--reason",            "output", "Show reason for state"),

    # Misc
    (["-Pn"],            "-Pn  No Ping",        "misc", "Skip host discovery"),
    (["--open"],         "--open",              "misc", "Show only open ports"),
]

# Conflicts: if a flag with these categories is present, these other categories
# must be removed from the palette.
_HARD_CONFLICTS: dict[str, set[str]] = {
    "scan_type:sn":  {"port_scope"},   # Ping-only has no port scope
    "evasion:f":     {"scan_type:sT"}, # Fragmentation breaks connect scan
}

# Detect fragmentation (-f) conflicts with -sT
def _check_hard_conflict(placed_tokens: set[str]) -> set[str]:
    """Return the set of flag categories that must be disabled.

    Rules (from Nmap documentation):
    - -sn (ping only) has no concept of port scope → disable port_scope.
    - -f (fragmentation) is incompatible with -sT (connect scan uses OS
      sockets, not raw packets) → disable scan_type if fragmentation is
      already placed, and vice-versa.
    """
    disabled: set[str] = set()
    if "-sn" in placed_tokens:
        disabled.add("port_scope")
    # Fragmentation/-f requires raw sockets; -sT uses the OS connect() API.
    # Block the opposite category so the user cannot create an invalid pair.
    if "-f" in placed_tokens:
        disabled.add("scan_type:sT")   # prevents adding -sT while -f is active
    if "-sT" in placed_tokens:
        disabled.add("evasion:f")      # prevents adding -f while -sT is active
    return disabled


class _FlagPieceData:
    """Data container for a flag definition."""
    def __init__(self, tokens: list[str], label: str, category: str, desc: str) -> None:
        self.tokens = tokens
        self.label = label
        self.category = category
        self.desc = desc
        self.first_token = tokens[0]


class CommandFactoryView(ctk.CTkFrame):
    """
    Drag-and-drop Nmap command builder.

    Left:   palette of available flag pieces
    Right:  canvas where pieces are placed
    Bottom: live command preview + action buttons
    """

    _PIECE_H = 36
    _PIECE_W = 200
    _PAD_X   = 10
    _PAD_Y   = 8

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
        # Placed pieces: list of _FlagPieceData
        self._placed: list[_FlagPieceData] = []
        self._target_var = tk.StringVar(value="192.168.1.1")

        self._build()

    # ── Build ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(0, weight=0, minsize=230)
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
            text="Drag pieces from the palette onto the canvas to build your command",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=PAD)

        # ── Left: palette ────────────────────────────────────────────────────
        self._palette_frame = ctk.CTkScrollableFrame(
            self, width=230, fg_color=BG_SECONDARY, label_text="Flag Palette"
        )
        self._palette_frame.grid(
            row=1, column=0, sticky="nsew", padx=(PAD, PAD_S), pady=PAD
        )

        # ── Right: canvas ────────────────────────────────────────────────────
        canvas_outer = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        canvas_outer.grid(row=1, column=1, sticky="nsew", padx=(PAD_S, PAD), pady=PAD)
        canvas_outer.rowconfigure(0, weight=0)
        canvas_outer.rowconfigure(1, weight=1)

        ctk.CTkLabel(
            canvas_outer,
            text="  Canvas – dropped flags appear here",
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
        canvas_outer.columnconfigure(0, weight=1)

        # ── Bottom: command preview + controls ────────────────────────────────
        bottom = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        bottom.grid(row=2, column=0, columnspan=2, sticky="ew", padx=PAD, pady=(0, PAD))

        target_row = ctk.CTkFrame(bottom, fg_color="transparent")
        target_row.pack(fill="x", padx=PAD, pady=(PAD_S, 0))

        ctk.CTkLabel(target_row, text="Target:", font=FONT_SMALL, width=50).pack(
            side="left"
        )
        ctk.CTkEntry(
            target_row,
            textvariable=self._target_var,
            width=200,
            font=FONT_SMALL,
        ).pack(side="left", padx=(0, PAD))

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

        # Initial render
        self._refresh_palette()

    # ── Palette ──────────────────────────────────────────────────────────────

    def _refresh_palette(self) -> None:
        for w in self._palette_frame.winfo_children():
            w.destroy()

        placed_tokens: set[str] = {f.first_token for f in self._placed}
        placed_cats: set[str] = {f.category for f in self._placed}
        hard_conflicts = _check_hard_conflict(placed_tokens)

        current_cat = ""
        for fd in self._flags_data:
            # Skip if this exact token is already placed
            if fd.first_token in placed_tokens:
                continue

            # Skip if category is single-select and already has one member placed
            single_select_cats = {"scan_type", "timing", "port_scope"}
            if fd.category in single_select_cats and fd.category in placed_cats:
                continue

            # Skip if this specific flag is blocked by a hard conflict.
            # Hard conflicts use the form "category:token" (e.g. "scan_type:sT")
            # or plain "category" to block the whole category.
            blocked = False
            for conflict_key in hard_conflicts:
                if ":" in conflict_key:
                    _, flag_suffix = conflict_key.split(":", 1)
                    if fd.first_token.lstrip("-") == flag_suffix:
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
                ctk.CTkLabel(
                    self._palette_frame,
                    text=f"── {fd.category} ──",
                    font=("Segoe UI", 9, "bold"),
                    text_color="#5588aa",
                    anchor="w",
                ).pack(fill="x", padx=PAD_S, pady=(PAD_S, 0))

            btn = ctk.CTkButton(
                self._palette_frame,
                text=fd.label,
                font=("Courier New", 10),
                height=self._PIECE_H,
                fg_color="#1a3050",
                hover_color="#2a5080",
                corner_radius=6,
                anchor="w",
                command=lambda f=fd: self._place_piece(f),
            )
            btn.pack(fill="x", padx=PAD_S, pady=2)

    def _place_piece(self, fd: _FlagPieceData) -> None:
        self._placed.append(fd)
        self._redraw_canvas()
        self._refresh_palette()
        self._update_preview()

    def _remove_piece(self, fd: _FlagPieceData) -> None:
        self._placed = [p for p in self._placed if p is not fd]
        self._redraw_canvas()
        self._refresh_palette()
        self._update_preview()

    # ── Canvas ───────────────────────────────────────────────────────────────

    def _redraw_canvas(self) -> None:
        self._canvas.delete("all")
        if not self._placed:
            self._canvas.create_text(
                200, 80,
                text="← Drag flag pieces here\n   or click pieces in the palette",
                fill="#3a5a7a",
                font=("Segoe UI", 13),
                justify="center",
            )
            return

        x, y = 14, 14
        canvas_w = self._canvas.winfo_width() or 600
        row_h = self._PIECE_H + self._PAD_Y

        for idx, fd in enumerate(self._placed):
            w = max(self._PIECE_W, len(fd.label) * 9 + 30)
            if x + w > canvas_w - 14 and x > 14:
                x = 14
                y += row_h + 4

            # Piece rectangle
            r = self._canvas.create_rectangle(
                x, y, x + w, y + self._PIECE_H,
                fill="#1a3a5a", outline="#3a7aaa", width=2,
            )
            t = self._canvas.create_text(
                x + 10, y + self._PIECE_H // 2,
                text=fd.label,
                fill="#aaddff",
                font=("Courier New", 10),
                anchor="w",
            )
            # ✕ button
            close_x = x + w - 14
            close_y = y + self._PIECE_H // 2
            c = self._canvas.create_text(
                close_x, close_y, text="✕", fill="#e74c3c",
                font=("Segoe UI", 11, "bold"),
            )
            self._canvas.tag_bind(
                c, "<Button-1>",
                lambda _e, f=fd: self._remove_piece(f),
            )
            self._canvas.tag_bind(
                r, "<Button-1>",
                lambda _e, f=fd: self._remove_piece(f),
            )
            x += w + self._PAD_X

    # ── Preview ──────────────────────────────────────────────────────────────

    def _update_preview(self) -> None:
        parts = ["nmap"]
        for fd in self._placed:
            parts.extend(fd.tokens)
        target = self._target_var.get().strip() or "<target>"
        parts.append(target)
        self._cmd_var.set(" ".join(parts))

    def get_command(self) -> str:
        self._update_preview()
        return self._cmd_var.get()

    def load_preset(self, preset: ScanPreset) -> None:
        """Load a preset's flags into the canvas."""
        self._clear_canvas()
        token_set: set[str] = set(preset.flags)
        for fd in self._flags_data:
            if fd.first_token in token_set:
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

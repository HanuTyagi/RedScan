"""
Preset Library view – scrollable grid of scan preset cards organised by category.
Provides a "Run" button that emits the preset back to the main app for execution.
"""
from __future__ import annotations

import tkinter as tk
from typing import Callable

import customtkinter as ctk

from gui.styles import (
    AGG_COLORS, ACCENT, ACCENT_HOVER, BG_CARD, BG_SECONDARY, BORDER_W,
    BTN_CORNER, CARD_CORNER, FONT_BODY, FONT_H1, FONT_H2, FONT_SMALL,
    PAD, PAD_S, TEXT_MUTED, TEXT_PRIMARY,
)
from redscan.preset_library import PRESET_CATALOGUE, ScanPreset, get_by_category


class PresetCard(ctk.CTkFrame):
    """A single card widget displaying one scan preset."""

    def __init__(
        self,
        master: ctk.CTkFrame,
        preset: ScanPreset,
        on_run: Callable[[ScanPreset], None],
        on_to_factory: Callable[[ScanPreset], None],
        **kwargs: object,
    ) -> None:
        super().__init__(
            master,
            fg_color=BG_CARD,
            corner_radius=CARD_CORNER,
            border_width=BORDER_W,
            border_color="#2a4a7f",
            **kwargs,
        )

        self.preset = preset
        agg_color = AGG_COLORS.get(preset.aggressiveness, "#888")

        # ── Row 1: name + aggressiveness badge ──────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=PAD_S, pady=(PAD_S, 0))

        ctk.CTkLabel(
            header,
            text=preset.name,
            font=FONT_H2,
            text_color=TEXT_PRIMARY,
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            header,
            text=f" {preset.aggressiveness} ",
            font=FONT_SMALL,
            text_color="#fff",
            fg_color=agg_color,
            corner_radius=4,
        ).pack(side="right", padx=(0, PAD_S))

        # ── Row 2: description ───────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text=preset.description,
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            wraplength=300,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=PAD_S, pady=(2, PAD_S))

        # ── Row 3: flags preview ─────────────────────────────────────────────
        flag_str = " ".join(preset.flags) if preset.flags else "(no flags)"
        ctk.CTkLabel(
            self,
            text=flag_str,
            font=("Courier New", 10),
            text_color="#7faacc",
            anchor="w",
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

        # ── Row 4: action buttons ────────────────────────────────────────────
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="▶  Run",
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER,
            font=FONT_SMALL,
            width=90,
            command=lambda: on_run(preset),
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="🔧  To Factory",
            fg_color="#1e4a6e",
            hover_color="#2a6a9e",
            corner_radius=BTN_CORNER,
            font=FONT_SMALL,
            width=110,
            command=lambda: on_to_factory(preset),
        ).pack(side="left")

        # Root privilege badge
        if preset.requires_root:
            ctk.CTkLabel(
                btn_row,
                text="  ⚠ root  ",
                font=FONT_SMALL,
                text_color="#f39c12",
                fg_color="transparent",
            ).pack(side="right", padx=(0, PAD_S))


class PresetBrowserView(ctk.CTkFrame):
    """Scrollable preset library with per-category headers and filter bar."""

    def __init__(
        self,
        master: ctk.CTk | ctk.CTkFrame,
        on_run: Callable[[ScanPreset], None],
        on_to_factory: Callable[[ScanPreset], None],
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._on_run = on_run
        self._on_to_factory = on_to_factory
        self._all_cards: list[tuple[ctk.CTkFrame, ScanPreset]] = []
        self._build()

    def _build(self) -> None:
        # ── Top toolbar ──────────────────────────────────────────────────────
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", padx=PAD, pady=(PAD, 0))

        ctk.CTkLabel(toolbar, text="Preset Library", font=FONT_H1, anchor="w").pack(
            side="left"
        )

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", self._apply_filter)
        ctk.CTkEntry(
            toolbar,
            textvariable=self._search_var,
            placeholder_text="🔍  Filter presets…",
            width=260,
            font=FONT_BODY,
        ).pack(side="right")

        # Category filter dropdown
        categories = ["All Categories"] + sorted(
            {p.category for p in PRESET_CATALOGUE}
        )
        self._cat_var = tk.StringVar(value="All Categories")
        ctk.CTkComboBox(
            toolbar,
            values=categories,
            variable=self._cat_var,
            font=FONT_SMALL,
            width=180,
            command=self._apply_filter,  # type: ignore[arg-type]
        ).pack(side="right", padx=(0, PAD))

        # ── Scrollable card area ─────────────────────────────────────────────
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent", label_text=""
        )
        self._scroll.pack(fill="both", expand=True, padx=PAD, pady=PAD)

        self._render_cards()

    def _render_cards(self) -> None:
        # Remove existing widgets
        for child in self._scroll.winfo_children():
            child.destroy()
        self._all_cards.clear()

        grouped = get_by_category()
        query = self._search_var.get().lower()
        cat_filter = self._cat_var.get()

        for category, presets in grouped.items():
            if cat_filter not in ("All Categories", category):
                continue

            # Filter by search text
            visible = [
                p
                for p in presets
                if query in p.name.lower()
                or query in p.description.lower()
                or query in " ".join(p.flags).lower()
            ]
            if not visible:
                continue

            # Category header
            hdr = ctk.CTkFrame(self._scroll, fg_color="#0a1a3a", corner_radius=6)
            hdr.pack(fill="x", pady=(PAD, PAD_S))
            ctk.CTkLabel(
                hdr,
                text=f"  {category}  ({len(visible)} presets)",
                font=FONT_H2,
                text_color="#7faaee",
                anchor="w",
            ).pack(fill="x", padx=PAD, pady=PAD_S)

            # 2-column grid
            grid = ctk.CTkFrame(self._scroll, fg_color="transparent")
            grid.pack(fill="x", pady=(0, PAD))
            grid.columnconfigure((0, 1), weight=1, uniform="col")

            for idx, preset in enumerate(visible):
                card = PresetCard(
                    grid,
                    preset,
                    self._on_run,
                    self._on_to_factory,
                )
                card.grid(
                    row=idx // 2,
                    column=idx % 2,
                    padx=PAD_S,
                    pady=PAD_S,
                    sticky="nsew",
                )
                self._all_cards.append((card, preset))

    def _apply_filter(self, *_: object) -> None:
        self._render_cards()

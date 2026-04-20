"""
Preset Library view.

Navigation flow
───────────────
1. Landing page — a grid of category tiles, each showing the category name,
   emoji icon, and preset count.  Loading is deferred until a tile is clicked
   so the view opens instantly regardless of library size.

2. Category page — a 2-column card grid for the selected category with a
   ← Back button, a search bar, and per-card Run / To Factory actions.

Search mode — if the user types in the search bar while on the landing page
the view switches directly to an "All" results page filtered by the query.
Cross-category presets appear once per matching category.
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
from redscan.preset_library import (
    CATEGORY_ICONS, CATEGORY_ORDER, PRESET_CATALOGUE, ScanPreset,
    get_by_category,
)

# ---------------------------------------------------------------------------
# Preset card widget
# ---------------------------------------------------------------------------

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

        # ── Row 3: flags + scripts preview ──────────────────────────────────
        flag_str = " ".join(preset.flags) if preset.flags else ""
        if preset.scripts:
            flag_str += ("  --script " + ",".join(preset.scripts[:2]))
            if len(preset.scripts) > 2:
                flag_str += f" (+{len(preset.scripts)-2})"
        if not flag_str:
            flag_str = "(no flags)"
        ctk.CTkLabel(
            self,
            text=flag_str,
            font=("Courier New", 10),
            text_color="#7faacc",
            anchor="w",
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

        # ── Row 4: cross-category tags (if preset appears in multiple places) ─
        if preset.extra_categories:
            tag_text = "  Also in: " + ", ".join(preset.extra_categories)
            ctk.CTkLabel(
                self,
                text=tag_text,
                font=("Segoe UI", 9),
                text_color="#5a7a9a",
                anchor="w",
            ).pack(fill="x", padx=PAD_S, pady=(0, 2))

        # ── Row 5: action buttons ────────────────────────────────────────────
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

        badges: list[str] = []
        if preset.requires_root:
            badges.append("⚠ root")
        if preset.requires_domain:
            badges.append("🌐 domain")
        if badges:
            ctk.CTkLabel(
                btn_row,
                text="  " + "  ".join(badges) + "  ",
                font=FONT_SMALL,
                text_color="#f39c12",
                fg_color="transparent",
            ).pack(side="right", padx=(0, PAD_S))


# ---------------------------------------------------------------------------
# Category tile widget (landing page)
# ---------------------------------------------------------------------------

class _CategoryTile(ctk.CTkFrame):
    """A large clickable tile representing one preset category."""

    def __init__(
        self,
        master: ctk.CTkFrame,
        category: str,
        count: int,
        on_click: Callable[[str], None],
        **kwargs: object,
    ) -> None:
        super().__init__(
            master,
            fg_color="#0f2a4a",
            corner_radius=CARD_CORNER,
            border_width=BORDER_W,
            border_color="#1e4a7f",
            cursor="hand2",
            **kwargs,
        )
        icon = CATEGORY_ICONS.get(category, "📂")
        ctk.CTkLabel(
            self, text=icon, font=("Segoe UI", 28), anchor="center"
        ).pack(pady=(PAD, 0))
        ctk.CTkLabel(
            self, text=category, font=FONT_H2, text_color=TEXT_PRIMARY, anchor="center",
            wraplength=130,
        ).pack(padx=PAD_S)
        ctk.CTkLabel(
            self, text=f"{count} presets", font=FONT_SMALL, text_color=TEXT_MUTED,
            anchor="center",
        ).pack(pady=(0, PAD))

        # Whole tile is clickable
        self.bind("<Button-1>", lambda _: on_click(category))
        for child in self.winfo_children():
            child.bind("<Button-1>", lambda _, cat=category: on_click(cat))


# ---------------------------------------------------------------------------
# Main browser view
# ---------------------------------------------------------------------------

class PresetBrowserView(ctk.CTkFrame):
    """Two-stage lazy-loading preset library.

    Stage 1 (landing): category tiles grid.
    Stage 2 (detail):  2-column preset card grid for the selected category.

    Typing in the search bar from Stage 1 jumps directly to a cross-category
    search result page.
    """

    def __init__(
        self,
        master: ctk.CTk | ctk.CTkFrame,
        on_run: Callable[[ScanPreset], None],
        on_to_factory: Callable[[ScanPreset], None],
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._on_run = on_run
        self._on_to_factory = on_to_factory
        # Cache: category → list of ScanPreset (populated lazily)
        self._grouped = get_by_category()
        self._current_category: str | None = None
        self._build()

    # ── Initial build ────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        # ── Toolbar (always visible) ─────────────────────────────────────────
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=PAD, pady=(PAD, 0))

        self._title_lbl = ctk.CTkLabel(
            toolbar, text="Preset Library", font=FONT_H1, anchor="w"
        )
        self._title_lbl.pack(side="left")

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", self._on_search_change)
        ctk.CTkEntry(
            toolbar,
            textvariable=self._search_var,
            placeholder_text="🔍  Search all presets…",
            width=260,
            font=FONT_BODY,
        ).pack(side="right")

        # Back button (hidden on landing page)
        self._back_btn = ctk.CTkButton(
            toolbar,
            text="← Back",
            fg_color="#1a3a5a",
            hover_color="#2a5a7a",
            corner_radius=BTN_CORNER,
            width=80,
            font=FONT_SMALL,
            command=self._show_landing,
        )
        # Not packed yet — shown only in category / search view

        # ── Scrollable content area ──────────────────────────────────────────
        self._scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent", label_text=""
        )
        self._scroll.grid(row=1, column=0, sticky="nsew", padx=PAD, pady=PAD)

        self._show_landing()

    # ── Landing page ─────────────────────────────────────────────────────────

    def _show_landing(self) -> None:
        self._current_category = None
        self._search_var.set("")
        self._back_btn.pack_forget()
        self._title_lbl.configure(text="Preset Library")
        self._clear_scroll()

        grouped = self._grouped
        # Show in CATEGORY_ORDER, then any remaining categories alphabetically
        ordered_cats = [c for c in CATEGORY_ORDER if c in grouped]
        ordered_cats += sorted(c for c in grouped if c not in ordered_cats)

        # 3-column tile grid
        grid = ctk.CTkFrame(self._scroll, fg_color="transparent")
        grid.pack(fill="x")
        cols = 3
        for i in range(cols):
            grid.columnconfigure(i, weight=1, uniform="cat")

        for idx, cat in enumerate(ordered_cats):
            count = len(grouped.get(cat, []))
            tile = _CategoryTile(
                grid,
                category=cat,
                count=count,
                on_click=self._show_category,
            )
            tile.grid(
                row=idx // cols,
                column=idx % cols,
                padx=PAD_S,
                pady=PAD_S,
                sticky="nsew",
            )

    # ── Category detail page ──────────────────────────────────────────────────

    def _show_category(self, category: str) -> None:
        self._current_category = category
        self._search_var.set("")
        icon = CATEGORY_ICONS.get(category, "📂")
        self._title_lbl.configure(text=f"{icon}  {category}")
        self._back_btn.pack(side="left", padx=(PAD_S, 0))
        self._render_preset_cards(self._grouped.get(category, []))

    # ── Search results page ───────────────────────────────────────────────────

    def _on_search_change(self, *_: object) -> None:
        query = self._search_var.get().strip().lower()
        if not query:
            if self._current_category:
                self._show_category(self._current_category)
            else:
                self._show_landing()
            return

        # Show back button
        self._back_btn.pack(side="left", padx=(PAD_S, 0))
        self._title_lbl.configure(text=f"🔍  Search: "{query}"")

        # Deduplicate by key while preserving order
        seen: set[str] = set()
        results: list[ScanPreset] = []
        for preset in PRESET_CATALOGUE:
            if preset.key in seen:
                continue
            if (
                query in preset.name.lower()
                or query in preset.description.lower()
                or query in " ".join(preset.flags).lower()
                or any(query in s.lower() for s in preset.scripts)
                or query in preset.category.lower()
            ):
                results.append(preset)
                seen.add(preset.key)

        self._render_preset_cards(results)

    # ── Card grid renderer (shared by category and search views) ─────────────

    def _render_preset_cards(self, presets: list[ScanPreset]) -> None:
        self._clear_scroll()
        if not presets:
            ctk.CTkLabel(
                self._scroll,
                text="No presets match your search.",
                font=FONT_BODY,
                text_color=TEXT_MUTED,
            ).pack(pady=PAD * 3)
            return

        grid = ctk.CTkFrame(self._scroll, fg_color="transparent")
        grid.pack(fill="x")
        grid.columnconfigure((0, 1), weight=1, uniform="col")

        for idx, preset in enumerate(presets):
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

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _clear_scroll(self) -> None:
        for child in self._scroll.winfo_children():
            child.destroy()


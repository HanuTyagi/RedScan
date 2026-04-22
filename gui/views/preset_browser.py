"""
Preset Library view.

Navigation flow
───────────────
1. Landing page — a grid of category tiles, each showing the category name,
   emoji icon, and preset count.  A virtual "⭐ Favourites" tile is shown when
   any presets have been starred.  Loading is deferred until a tile is clicked
   so the view opens instantly regardless of library size.

2. Category page — a 2-column card grid for the selected category with a
   ← Back button, a search bar, and per-card Run / ⭐ / ⚙ / To Factory actions.

Search mode — if the user types in the search bar while on the landing page
the view switches directly to an "All" results page filtered by the query.
Cross-category presets appear once per matching category.

Import / Export — toolbar buttons allow sharing preset packs as JSON files.
"""
from __future__ import annotations

import tkinter as tk
from typing import Callable
from pathlib import Path

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
from redscan.favourites import _favourites
from redscan.preset_io import (
    CommunityPresetStore, export_presets, import_presets, _community_store,
)

_VIRTUAL_FAVOURITES = "⭐ Favourites"
_VIRTUAL_IMPORTED   = "📥 Imported"

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
        on_favourite_changed: Callable[[], None] | None = None,
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
        self._on_run = on_run
        self._on_to_factory = on_to_factory
        self._on_favourite_changed = on_favourite_changed
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

        # ── ⚙ Script Args button (only when preset has scripts) ───────────
        if preset.scripts:
            ctk.CTkButton(
                btn_row,
                text="⚙ Args",
                fg_color="#1a3a2a",
                hover_color="#2a5a3a",
                corner_radius=BTN_CORNER,
                font=FONT_SMALL,
                width=70,
                command=self._open_script_args_dialog,
            ).pack(side="left", padx=(PAD_S, 0))

        # ── ⭐ Favourite toggle ────────────────────────────────────────────
        self._star_btn_var = tk.StringVar(
            value="⭐" if _favourites.is_favourite(preset.key) else "☆"
        )
        self._star_btn = ctk.CTkButton(
            btn_row,
            textvariable=self._star_btn_var,
            fg_color="transparent",
            hover_color="#2a3a1a",
            corner_radius=BTN_CORNER,
            font=("Segoe UI", 13),
            width=36,
            command=self._toggle_favourite,
        )
        self._star_btn.pack(side="right", padx=(0, PAD_S))

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

    # ── Favourites ────────────────────────────────────────────────────────────

    def _toggle_favourite(self) -> None:
        now_starred = _favourites.toggle(self.preset.key)
        self._star_btn_var.set("⭐" if now_starred else "☆")
        if self._on_favourite_changed:
            self._on_favourite_changed()

    # ── Script Args dialog ────────────────────────────────────────────────────

    def _open_script_args_dialog(self) -> None:
        """Open a modal dialog letting the user edit script_args before running."""
        preset = self.preset
        dlg = ctk.CTkToplevel(self)
        dlg.title(f"Script Arguments — {preset.name}")
        dlg.geometry("520x340")
        dlg.grab_set()

        ctk.CTkLabel(
            dlg,
            text=f"Scripts: {', '.join(preset.scripts)}",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            anchor="w",
        ).pack(fill="x", padx=PAD, pady=(PAD, 0))

        ctk.CTkLabel(
            dlg,
            text="Script arguments (one per line, format: key=value):",
            font=FONT_SMALL,
            anchor="w",
        ).pack(fill="x", padx=PAD, pady=(PAD_S, 0))

        args_text = ctk.CTkTextbox(dlg, height=140, font=("Courier New", 11))
        args_text.pack(fill="x", padx=PAD, pady=PAD_S)
        # Pre-populate with existing script_args
        for arg in preset.script_args:
            args_text.insert("end", arg + "\n")

        hint = ctk.CTkLabel(
            dlg,
            text="Leave empty to use the preset defaults. These args are used only for this run.",
            font=("Segoe UI", 9),
            text_color=TEXT_MUTED,
            wraplength=480,
            justify="left",
        )
        hint.pack(fill="x", padx=PAD)

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(pady=PAD)

        def _run_with_args() -> None:
            raw = args_text.get("1.0", "end").strip()
            extra_args = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            # Build a one-off ScanPreset with the overridden script_args
            modified = ScanPreset(
                key=preset.key,
                name=preset.name,
                category=preset.category,
                description=preset.description,
                flags=preset.flags,
                scripts=preset.scripts,
                script_args=extra_args if extra_args else list(preset.script_args),
                aggressiveness=preset.aggressiveness,
                requires_root=preset.requires_root,
                requires_ports=preset.requires_ports,
                extra_categories=preset.extra_categories,
                no_port_scan=preset.no_port_scan,
                requires_domain=preset.requires_domain,
            )
            dlg.destroy()
            self._on_run(modified)

        ctk.CTkButton(
            btn_row,
            text="▶  Run with These Args",
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER,
            command=_run_with_args,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_row,
            text="Cancel",
            fg_color="#1e3a5e",
            hover_color="#2a5a7e",
            corner_radius=BTN_CORNER,
            command=dlg.destroy,
        ).pack(side="left")


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

    Stage 1 (landing): category tiles grid (+ virtual Favourites & Imported tiles).
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

        # Import / Export buttons (right-aligned, before search)
        ctk.CTkButton(
            toolbar,
            text="📤 Export",
            fg_color="#1a3a1a",
            hover_color="#2a5a2a",
            corner_radius=BTN_CORNER,
            font=FONT_SMALL,
            width=80,
            command=self._export_dialog,
        ).pack(side="right", padx=(PAD_S, 0))

        ctk.CTkButton(
            toolbar,
            text="📥 Import",
            fg_color="#1a2a3a",
            hover_color="#2a4a5a",
            corner_radius=BTN_CORNER,
            font=FONT_SMALL,
            width=80,
            command=self._import_dialog,
        ).pack(side="right", padx=(PAD_S, 0))

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", self._on_search_change)
        ctk.CTkEntry(
            toolbar,
            textvariable=self._search_var,
            placeholder_text="🔍  Search all presets…",
            width=260,
            font=FONT_BODY,
        ).pack(side="right", padx=(0, PAD_S))

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

        # Prepend virtual "Favourites" tile when any presets are starred
        fav_keys = _favourites.all()
        show_fav_tile = bool(fav_keys)

        # Append virtual "Imported" tile when community presets exist
        imported = _community_store.all()
        show_imported_tile = bool(imported)

        # 3-column tile grid
        grid = ctk.CTkFrame(self._scroll, fg_color="transparent")
        grid.pack(fill="x")
        cols = 3
        for i in range(cols):
            grid.columnconfigure(i, weight=1, uniform="cat")

        all_tiles: list[tuple[str, int]] = []
        if show_fav_tile:
            all_tiles.append((_VIRTUAL_FAVOURITES, len(fav_keys)))
        if show_imported_tile:
            all_tiles.append((_VIRTUAL_IMPORTED, len(imported)))
        for cat in ordered_cats:
            all_tiles.append((cat, len(grouped.get(cat, []))))

        for idx, (cat, count) in enumerate(all_tiles):
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

        if category == _VIRTUAL_FAVOURITES:
            fav_keys = _favourites.all()
            presets = [p for p in PRESET_CATALOGUE if p.key in fav_keys]
            # Also include imported presets that are starred
            for p in _community_store.all():
                if p.key in fav_keys:
                    presets.append(p)
        elif category == _VIRTUAL_IMPORTED:
            presets = _community_store.all()
        else:
            presets = self._grouped.get(category, [])

        self._render_preset_cards(presets)

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

        # Deduplicate by key while preserving order; include imported presets
        seen: set[str] = set()
        results: list[ScanPreset] = []
        all_presets = list(PRESET_CATALOGUE) + _community_store.all()
        for preset in all_presets:
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
                on_favourite_changed=self._on_favourite_changed,
            )
            card.grid(
                row=idx // 2,
                column=idx % 2,
                padx=PAD_S,
                pady=PAD_S,
                sticky="nsew",
            )

    # ── Favourites change callback ────────────────────────────────────────────

    def _on_favourite_changed(self) -> None:
        """Called when a ⭐ is toggled.  Refreshes landing tile counts."""
        # If we're on the landing page, re-render so tile counts stay correct.
        if self._current_category is None:
            self._show_landing()
        elif self._current_category == _VIRTUAL_FAVOURITES:
            # Re-render the favourites page if we just un-starred the last preset
            self._show_category(_VIRTUAL_FAVOURITES)

    # ── Import / Export ───────────────────────────────────────────────────────

    def _import_dialog(self) -> None:
        """Open a file picker and import presets from a JSON file."""
        from tkinter import filedialog, messagebox
        path = filedialog.askopenfilename(
            title="Import Preset Pack",
            filetypes=[("RedScan Preset Pack", "*.json"), ("All Files", "*")],
        )
        if not path:
            return
        try:
            presets = import_presets(Path(path))
        except (OSError, ValueError, __import__("json").JSONDecodeError) as exc:
            messagebox.showerror("Import Failed", f"Could not import presets:\n{exc}")
            return

        _community_store.add_many(presets)
        messagebox.showinfo(
            "Import Complete",
            f"Successfully imported {len(presets)} preset(s) into the "
            f""{_VIRTUAL_IMPORTED}" category.",
        )
        # Refresh landing so the Imported tile appears / updates
        if self._current_category is None:
            self._show_landing()

    def _export_dialog(self) -> None:
        """Open a file picker and export the currently visible presets."""
        from tkinter import filedialog, messagebox
        path = filedialog.asksaveasfilename(
            title="Export Presets",
            defaultextension=".json",
            filetypes=[("RedScan Preset Pack", "*.json")],
        )
        if not path:
            return

        # Export whichever presets are currently in view; fall back to all
        if self._current_category and self._current_category not in (
            _VIRTUAL_FAVOURITES, _VIRTUAL_IMPORTED
        ):
            presets = self._grouped.get(self._current_category, [])
        elif self._current_category == _VIRTUAL_FAVOURITES:
            fav_keys = _favourites.all()
            presets = [p for p in PRESET_CATALOGUE if p.key in fav_keys]
        elif self._current_category == _VIRTUAL_IMPORTED:
            presets = _community_store.all()
        else:
            presets = list(PRESET_CATALOGUE)

        try:
            export_presets(presets, Path(path))
        except OSError as exc:
            messagebox.showerror("Export Failed", f"Could not write file:\n{exc}")
            return

        messagebox.showinfo(
            "Export Complete",
            f"Exported {len(presets)} preset(s) to:\n{path}",
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _clear_scroll(self) -> None:
        for child in self._scroll.winfo_children():
            child.destroy()


"""
RedScan – Main CTk Application.

Wires together all views via a sidebar navigation.  Views communicate through
callback closures so they stay decoupled from each other.
"""
from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from typing import Any

import customtkinter as ctk

from gui.styles import (
    APP_APPEARANCE, APP_COLOR_THEME, BG_PRIMARY, BG_SECONDARY, FONT_H1,
    FONT_SMALL, NAV_ITEMS, PAD, PAD_S, SIDEBAR_W, TEXT_MUTED, TEXT_PRIMARY,
    WINDOW_H, WINDOW_W,
)
from gui.views.command_factory import CommandFactoryView
from gui.views.dashboard import DashboardView, HostRecord
from gui.views.llm_panel import LLMInsightsView
from gui.views.preset_browser import PresetBrowserView
from gui.views.smart_scan import SmartScanView
from redscan.preset_library import ScanPreset


def _build_window_icon(root: ctk.CTk) -> None:
    """Set a minimal icon without external image files."""
    try:
        root.iconbitmap("")  # clear default
    except Exception:
        pass


class RedScanApp(ctk.CTk):
    """Top-level application window."""

    def __init__(self) -> None:
        ctk.set_appearance_mode(APP_APPEARANCE)
        ctk.set_default_color_theme(APP_COLOR_THEME)

        super().__init__()
        self.title("RedScan v2 – Network Intelligence Platform")
        self.geometry(f"{WINDOW_W}x{WINDOW_H}")
        self.minsize(900, 600)

        _build_window_icon(self)
        self._active_view = tk.StringVar(value="presets")
        self._build_layout()
        self._show_view("presets")
        # Ensure any running nmap process is terminated when the window is closed.
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Window close ─────────────────────────────────────────────────────────

    def _on_close(self) -> None:
        """Stop any running nmap process before destroying the window.

        Without this handler, closing the window while a scan is in progress
        leaves an orphaned nmap subprocess running until the scan naturally
        finishes.
        """
        try:
            self._dashboard._stop_scan()
        except Exception:
            pass
        self.destroy()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self) -> None:
        self.columnconfigure(0, weight=0, minsize=SIDEBAR_W)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Sidebar
        self._sidebar = self._build_sidebar()
        self._sidebar.grid(row=0, column=0, sticky="nsew")

        # Content area
        self._content = ctk.CTkFrame(self, fg_color="transparent")
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.columnconfigure(0, weight=1)
        self._content.rowconfigure(0, weight=1)

        # Instantiate all views (they start hidden)
        self._dashboard = DashboardView(
            self._content,
            on_ai_insights=self._on_ai_insights,
        )
        self._preset_browser = PresetBrowserView(
            self._content,
            on_run=self._on_preset_run,
            on_to_factory=self._on_preset_to_factory,
        )
        self._factory = CommandFactoryView(
            self._content,
            on_run_command=self._on_factory_run,
            on_save_preset=self._on_factory_save_preset,
        )
        self._smart_scan = SmartScanView(
            self._content,
            on_hosts_discovered=self._on_smart_scan_results,
        )
        self._llm_panel = LLMInsightsView(self._content)

        self._views: dict[str, ctk.CTkFrame] = {
            "presets":    self._preset_browser,
            "factory":    self._factory,
            "dashboard":  self._dashboard,
            "smart_scan": self._smart_scan,
            "llm":        self._llm_panel,
        }

    def _build_sidebar(self) -> ctk.CTkFrame:
        sidebar = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=0)
        sidebar.columnconfigure(0, weight=1)

        # Logo / title
        logo_frame = ctk.CTkFrame(sidebar, fg_color="#0f1e3a", corner_radius=0)
        logo_frame.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            logo_frame,
            text="🛡 RedScan",
            font=FONT_H1,
            text_color="#e94560",
        ).pack(padx=PAD, pady=PAD)
        ctk.CTkLabel(
            logo_frame,
            text="Network Intelligence",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
        ).pack(pady=(0, PAD))

        # Nav buttons
        self._nav_btns: dict[str, ctk.CTkButton] = {}
        for idx, (key, label) in enumerate(NAV_ITEMS, start=1):
            btn = ctk.CTkButton(
                sidebar,
                text=label,
                anchor="w",
                fg_color="transparent",
                hover_color="#1a3a5a",
                text_color=TEXT_PRIMARY,
                corner_radius=6,
                font=("Segoe UI", 12),
                command=lambda k=key: self._show_view(k),
            )
            btn.grid(row=idx, column=0, sticky="ew", padx=PAD_S, pady=2)
            self._nav_btns[key] = btn

        # Spacer
        sidebar.rowconfigure(len(NAV_ITEMS) + 1, weight=1)

        # Footer
        ctk.CTkLabel(
            sidebar,
            text="v2.0  |  github.com/HanuTyagi/RedScan",
            font=("Segoe UI", 9),
            text_color="#3a5a7a",
        ).grid(row=len(NAV_ITEMS) + 2, column=0, pady=PAD, sticky="ew")

        return sidebar

    # ── View management ───────────────────────────────────────────────────────

    def _show_view(self, key: str) -> None:
        for vkey, view in self._views.items():
            if vkey == key:
                view.grid(row=0, column=0, sticky="nsew")
            else:
                view.grid_remove()

        for bkey, btn in self._nav_btns.items():
            btn.configure(
                fg_color="#1a3a5a" if bkey == key else "transparent",
                text_color="#e94560" if bkey == key else TEXT_PRIMARY,
            )
        self._active_view.set(key)

    # ── Cross-view callbacks ──────────────────────────────────────────────────

    def _on_preset_run(self, preset: ScanPreset) -> None:
        """Preset Library: run a preset on the Dashboard."""
        self._show_view("dashboard")
        self._dashboard.set_preset(preset.key)
        self._dashboard.start_scan()

    def _on_preset_to_factory(self, preset: ScanPreset) -> None:
        """Preset Library: load a preset into the Command Factory canvas."""
        self._factory.load_preset(preset)
        self._show_view("factory")

    def _on_factory_run(self, command: str) -> None:
        """Command Factory: run the built command on the Dashboard."""
        self._show_view("dashboard")
        self._dashboard.run_custom_command(command)

    def _on_factory_save_preset(self, name: str, desc: str) -> None:
        """Command Factory: persist the current command as a JSON entry in
        ~/.redscan_presets.json so it survives restarts."""
        command = self._factory.get_command()
        preset_path = Path.home() / ".redscan_presets.json"
        try:
            existing: list[dict[str, Any]] = []
            if preset_path.exists():
                existing = json.loads(preset_path.read_text())
            existing.append({"name": name, "description": desc, "command": command})
            preset_path.write_text(json.dumps(existing, indent=2))
            _info_dialog(self, "Preset Saved", f"'{name}' saved to {preset_path}")
        except OSError as exc:
            _info_dialog(self, "Save Failed", f"Could not write presets file:\n{exc}")

    def _on_ai_insights(self, hosts: list[HostRecord], command: str) -> None:
        """Dashboard: open AI Insights with the current scan context."""
        self._llm_panel.load_context(hosts, command)
        self._show_view("llm")

    def _on_smart_scan_results(self, results: list[dict[str, Any]], rate: float) -> None:
        """Smart Scan: populate the Dashboard with discovered endpoints and navigate to it."""
        if results:
            self._dashboard.load_from_smart_scan(results, rate)
            self._show_view("dashboard")
        else:
            _info_dialog(
                self,
                "Smart Scan Complete",
                "No open endpoints were discovered.\n"
                "Try expanding the port range or target CIDR.",
            )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _info_dialog(parent: ctk.CTk | ctk.CTkFrame, title: str, message: str) -> None:
    dlg = ctk.CTkToplevel(parent)
    dlg.title(title)
    dlg.geometry("400x160")
    dlg.grab_set()
    ctk.CTkLabel(dlg, text=message, font=FONT_SMALL, wraplength=360, justify="left").pack(
        padx=PAD, pady=PAD
    )
    ctk.CTkButton(dlg, text="OK", command=dlg.destroy).pack(pady=PAD)

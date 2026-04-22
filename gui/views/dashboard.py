"""
Scan Dashboard – real-time scan output, host/port table, and session
persistence.  The dashboard drives nmap via subprocess in a background thread
and streams events to the GUI through a thread-safe queue.

Layout
──────
┌────────────────────────────────────────────────────────────────┐
│ [target input]  [preset ▼]  [ports]  [▶ Run]  [📂 Load]  [💾 Save] │
├─────────────────┬──────────────────────────────────────────────┤
│  Hosts table    │  Port / service detail for selected host      │
│  (filterable)   │                                              │
├─────────────────┴──────────────────────────────────────────────┤
│  Live output log (scrolling text)                              │
└────────────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, BG_CARD, BG_SECONDARY, BTN_CORNER, CARD_CORNER,
    FONT_BODY, FONT_H1, FONT_H2, FONT_MONO_SM, FONT_SMALL, PAD, PAD_S,
    TEXT_DANGER, TEXT_MUTED, TEXT_PRIMARY, TEXT_SUCCESS,
)
from redscan.preset_library import PRESET_CATALOGUE, get_by_key
from redscan.conflict_manager import ConflictManager, _INFO as _ConflictInfo

_OPEN_PORT_RE = re.compile(r"(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<version>.*))?")
_HOST_RE = re.compile(r"Nmap scan report for (.+)")
_OS_RE = re.compile(r"OS details?: (.+)")

# Shared conflict manager instance (stateless, safe to share)
_conflict_manager = ConflictManager()

# Path to user-saved Command-Factory presets.
_USER_PRESETS_PATH = Path.home() / ".redscan_presets.json"

# Optional XML enrichment via the root-level xml_parser module.
# The module lives alongside this package so a sys.path lookup is needed when
# running from an installed location rather than directly from the source root.
try:
    from xml_parser import parse_nmap_xml as _parse_nmap_xml  # type: ignore[import]
    _XML_PARSER_AVAILABLE = True
except ImportError:
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    try:
        from xml_parser import parse_nmap_xml as _parse_nmap_xml  # type: ignore[import]
        _XML_PARSER_AVAILABLE = True
    except ImportError:
        _parse_nmap_xml = None  # type: ignore[assignment]
        _XML_PARSER_AVAILABLE = False


class HostRecord:
    """Holds parsed data for a single scanned host."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.ports: list[dict[str, str]] = []
        self.os_guess: str = "Unknown"
        self.status: str = "up"
        self.hostnames: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ports": self.ports,
            "os_guess": self.os_guess,
            "status": self.status,
            "hostnames": self.hostnames,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "HostRecord":
        r = HostRecord(d["host"])
        r.ports = d["ports"]
        r.os_guess = d.get("os_guess", "Unknown")
        r.status = d.get("status", "up")
        r.hostnames = d.get("hostnames", [])
        return r


def _is_root_runtime() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows: best-effort fallback
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except Exception:
            return False


class DashboardView(ctk.CTkFrame):
    """Main scan dashboard with real-time output and host/port table."""

    def __init__(
        self,
        master: ctk.CTk | ctk.CTkFrame,
        on_ai_insights: Callable[[list[HostRecord], str], None],
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._on_ai_insights = on_ai_insights
        self._hosts: dict[str, HostRecord] = {}
        self._current_host: str | None = None
        self._scan_process: subprocess.Popen[str] | None = None
        self._event_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._running = False
        self._command_used = ""
        # Temporary XML output file for post-scan enrichment (set per scan).
        self._xml_tempfile: str | None = None
        # User-defined presets loaded from ~/.redscan_presets.json.
        # Maps display-name to nmap command string.
        self._user_presets: dict[str, str] = {}

        self._build()
        self._poll_events()
        # Defer user preset loading until the event loop is running.
        self.after(200, self._load_user_presets)
        self.after(250, self._refresh_ports_gate)

    # ── Build ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.rowconfigure(0, weight=0)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=0, minsize=180)
        self.columnconfigure(0, weight=1)

        # ── Row 0: control bar ───────────────────────────────────────────────
        ctrl = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        ctrl.grid(row=0, column=0, sticky="ew", padx=PAD, pady=(PAD, 0))

        ctk.CTkLabel(ctrl, text="Target:", font=FONT_SMALL).pack(side="left", padx=(PAD, PAD_S))
        self._target_var = tk.StringVar(value="")
        ctk.CTkEntry(ctrl, textvariable=self._target_var, width=180, font=FONT_SMALL).pack(
            side="left", padx=(0, PAD)
        )

        preset_keys = ["(none)"] + [p.key for p in PRESET_CATALOGUE]
        self._preset_var = tk.StringVar(value="(none)")
        self._preset_var.trace_add("write", lambda *_: self._refresh_ports_gate())
        ctk.CTkLabel(ctrl, text="Preset:", font=FONT_SMALL).pack(side="left")
        self._preset_combo = ctk.CTkComboBox(
            ctrl,
            values=preset_keys,
            variable=self._preset_var,
            width=200,
            font=FONT_SMALL,
        )
        self._preset_combo.pack(side="left", padx=(PAD_S, PAD))

        ctk.CTkLabel(ctrl, text="Ports:", font=FONT_SMALL).pack(side="left")
        self._ports_var = tk.StringVar(value="1-1024")
        self._ports_entry = ctk.CTkEntry(ctrl, textvariable=self._ports_var, width=120, font=FONT_SMALL)
        self._ports_entry.pack(side="left", padx=(PAD_S, PAD))
        self._ports_status_lbl = ctk.CTkLabel(ctrl, text="", font=FONT_SMALL, text_color=TEXT_MUTED)
        self._ports_status_lbl.pack(side="left", padx=(0, PAD))

        priv_text = "ROOT / ADMIN" if _is_root_runtime() else "STANDARD USER"
        priv_color = TEXT_SUCCESS if _is_root_runtime() else "#f39c12"
        ctk.CTkLabel(ctrl, text=f"Privileges: {priv_text}", font=FONT_SMALL, text_color=priv_color).pack(
            side="left", padx=(0, PAD)
        )

        self._run_btn = ctk.CTkButton(
            ctrl, text="▶  Run Scan",
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER, width=110,
            command=self._start_scan,
        )
        self._run_btn.pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            ctrl, text="⏹  Stop",
            fg_color="#4a2020", hover_color="#6a3030",
            corner_radius=BTN_CORNER, width=80,
            command=self._stop_scan,
        ).pack(side="left", padx=(0, PAD))

        ctk.CTkButton(
            ctrl, text="💾  Save Session",
            fg_color="#1a3a1a", hover_color="#2a5a2a",
            corner_radius=BTN_CORNER,
            command=self._save_session,
        ).pack(side="right", padx=(0, PAD))

        ctk.CTkButton(
            ctrl, text="📂  Load Session",
            fg_color="#1a2a3a", hover_color="#2a4a5a",
            corner_radius=BTN_CORNER,
            command=self._load_session,
        ).pack(side="right", padx=(0, PAD_S))

        # ── Row 1: hosts table + port details ────────────────────────────────
        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.grid(row=1, column=0, sticky="nsew", padx=PAD, pady=PAD_S)
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1, minsize=260)
        mid.columnconfigure(1, weight=3)

        # Hosts panel
        host_panel = ctk.CTkFrame(mid, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        host_panel.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_S))
        host_panel.rowconfigure(1, weight=1)
        host_panel.columnconfigure(0, weight=1)

        ctk.CTkLabel(host_panel, text="Discovered Hosts", font=FONT_H2, anchor="w").grid(
            row=0, column=0, padx=PAD, pady=PAD_S, sticky="w"
        )

        # Filter entry
        filter_row = ctk.CTkFrame(host_panel, fg_color="transparent")
        filter_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=PAD_S, pady=(0, PAD_S))
        ctk.CTkLabel(filter_row, text="🔍", font=FONT_SMALL, width=20).pack(side="left")
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", self._on_filter_change)
        ctk.CTkEntry(
            filter_row,
            textvariable=self._filter_var,
            placeholder_text="Filter hosts…",
            font=FONT_SMALL,
        ).pack(side="left", fill="x", expand=True, padx=(PAD_S, 0))

        self._host_listbox = tk.Listbox(
            host_panel,
            bg="#0d1b2a",
            fg=TEXT_PRIMARY,
            selectbackground="#1a4a6a",
            activestyle="none",
            font=("Courier New", 11),
            borderwidth=0,
            highlightthickness=0,
        )
        self._host_listbox.grid(row=2, column=0, sticky="nsew", padx=PAD_S, pady=PAD_S)
        self._host_listbox.bind("<<ListboxSelect>>", self._on_host_select)

        host_scroll = tk.Scrollbar(host_panel, command=self._host_listbox.yview)
        host_scroll.grid(row=2, column=1, sticky="ns")
        self._host_listbox.configure(yscrollcommand=host_scroll.set)
        host_panel.rowconfigure(2, weight=1)

        # Port details panel
        detail_panel = ctk.CTkFrame(mid, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        detail_panel.grid(row=0, column=1, sticky="nsew")
        detail_panel.rowconfigure(1, weight=1)
        detail_panel.columnconfigure(0, weight=1)

        detail_hdr = ctk.CTkFrame(detail_panel, fg_color="transparent")
        detail_hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=PAD, pady=PAD_S)
        self._detail_host_lbl = ctk.CTkLabel(
            detail_hdr, text="Select a host →", font=FONT_H2, anchor="w"
        )
        self._detail_host_lbl.pack(side="left")

        self._ai_btn = ctk.CTkButton(
            detail_hdr,
            text="🤖  AI Insights",
            fg_color="#4a1a6a",
            hover_color="#6a2a8a",
            corner_radius=BTN_CORNER,
            command=self._trigger_ai,
        )
        self._ai_btn.pack(side="right")

        # Stats row
        stats_row = ctk.CTkFrame(detail_panel, fg_color="transparent")
        stats_row.grid(row=1, column=0, sticky="ew", padx=PAD, pady=(0, PAD_S))

        self._stat_hosts = self._make_stat(stats_row, "Hosts", "0")
        self._stat_open = self._make_stat(stats_row, "Open Ports", "0")
        self._stat_services = self._make_stat(stats_row, "Services", "0")
        self._stat_os = self._make_stat(stats_row, "OS Guesses", "0")

        # Port table using text widget (for simplicity and real-time streaming)
        self._port_table = ctk.CTkTextbox(
            detail_panel,
            font=FONT_MONO_SM,
            fg_color="#0d1b2a",
            text_color="#aaddff",
        )
        self._port_table.grid(row=2, column=0, sticky="nsew", padx=PAD_S, pady=(0, PAD_S))
        detail_panel.rowconfigure(2, weight=1)

        # ── Row 2: live log ───────────────────────────────────────────────────
        log_frame = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        log_frame.grid(row=2, column=0, sticky="nsew", padx=PAD, pady=(0, PAD))
        log_frame.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)

        log_hdr = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_hdr.grid(row=0, column=0, sticky="ew", padx=PAD, pady=PAD_S)

        ctk.CTkLabel(log_hdr, text="Live Output", font=FONT_H2, anchor="w").pack(side="left")

        ctk.CTkButton(
            log_hdr, text="Clear Log",
            fg_color="#2a1a1a", hover_color="#3a2a2a",
            corner_radius=BTN_CORNER, width=90, font=FONT_SMALL,
            command=lambda: self._log_text.delete("1.0", "end"),
        ).pack(side="right")

        self._log_text = ctk.CTkTextbox(
            log_frame,
            font=FONT_MONO_SM,
            fg_color="#0a1020",
            text_color="#88cc88",
        )
        self._log_text.grid(row=1, column=0, sticky="nsew", padx=PAD_S, pady=(0, PAD_S))

        # Status bar
        self._status_var = tk.StringVar(value="Ready")
        ctk.CTkLabel(self, textvariable=self._status_var, font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").grid(
            row=3, column=0, sticky="w", padx=PAD, pady=(0, PAD_S)
        )
        self.rowconfigure(3, weight=0)

    def _make_stat(self, parent: ctk.CTkFrame, label: str, value: str) -> ctk.CTkLabel:
        box = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        box.pack(side="left", padx=PAD_S, pady=PAD_S)
        ctk.CTkLabel(box, text=label, font=FONT_SMALL, text_color=TEXT_MUTED).pack(padx=PAD, pady=(PAD_S, 0))
        lbl = ctk.CTkLabel(box, text=value, font=FONT_H1, text_color=TEXT_SUCCESS)
        lbl.pack(padx=PAD, pady=(0, PAD_S))
        return lbl

    # ── Scan execution ────────────────────────────────────────────────────────

    def _build_command(self) -> list[str]:
        target = self._target_var.get().strip()
        preset_key = self._preset_var.get()
        ports_str = self._ports_var.get().strip()

        # ── User preset: run the stored command, replacing the original target
        # with the current dashboard target. ──────────────────────────────────
        if preset_key in self._user_presets:
            import shlex
            try:
                parts = shlex.split(self._user_presets[preset_key])
            except ValueError:
                parts = self._user_presets[preset_key].split()
            # Replace last non-flag argument (the stored target) with current one.
            if parts and not parts[-1].startswith("-"):
                parts = parts[:-1] + [target]
            elif target:
                parts.append(target)
            # Inject XML output alongside the user command.
            self._xml_tempfile = self._new_xml_tempfile()
            if self._xml_tempfile:
                parts = list(parts)
                # Insert -oX before the target (last element).
                parts.insert(-1, "-oX")
                parts.insert(-1, self._xml_tempfile)
            self._command_used = " ".join(parts)
            return parts

        # ── Normal preset / fallback ──────────────────────────────────────────
        preset = get_by_key(preset_key) if preset_key != "(none)" else None

        cmd: list[str] = ["nmap"]
        if preset:
            cmd.extend(preset.flags)
            if preset.scripts:
                cmd.extend(["--script", ",".join(preset.scripts)])
            if preset.script_args:
                cmd.extend(["--script-args", ",".join(preset.script_args)])
        else:
            cmd.extend(["-sT", "-sV", "-T4"])

        # Conflict rule: -sn (host-discovery-only) has no port-scan phase.
        # Silently drop the port specification; _log_preflight_warnings() will
        # tell the user what happened.
        if ports_str and ConflictManager.needs_ports_input(cmd):
            cmd.extend(["-p", ports_str])

        # Write XML to a temp file in addition to the default text output.
        # Both formats can coexist: nmap streams text to stdout while writing
        # XML to the file.  We parse the XML post-scan for richer version/OS data.
        self._xml_tempfile = self._new_xml_tempfile()
        if self._xml_tempfile:
            cmd.extend(["-oX", self._xml_tempfile])

        # Use default nmap text output (not greppable -oG).
        # The three regexes (_HOST_RE, _OPEN_PORT_RE, _OS_RE) expect the normal
        # human-readable format ("Nmap scan report for …", "22/tcp  open  ssh …",
        # "OS details: …").  Using -oG would produce a completely different format
        # and those regexes would never match, leaving the dashboard empty.
        cmd.append(target)
        return cmd

    def _refresh_ports_gate(self) -> None:
        """Disable Ports input when active scan flags already define port scope."""
        preset_key = self._preset_var.get()
        preset = get_by_key(preset_key) if preset_key != "(none)" else None
        cmd: list[str] = ["nmap"]
        if preset:
            cmd.extend(preset.flags)
        else:
            cmd.extend(["-sT", "-sV", "-T4"])

        if ConflictManager.needs_ports_input(cmd):
            self._ports_entry.configure(state="normal", text_color=TEXT_PRIMARY)
            self._ports_status_lbl.configure(text="")
            return

        flags = set(cmd)
        if "-sn" in flags:
            reason = "disabled — ping-only scan"
        elif "-p-" in flags:
            reason = "disabled — all 65535 ports"
        elif "-F" in flags:
            reason = "disabled — top-100 ports"
        elif "--top-ports" in flags:
            reason = "disabled — --top-ports set"
        else:
            reason = "disabled"

        self._ports_entry.configure(state="disabled", text_color="#777")
        self._ports_status_lbl.configure(text=f"({reason})")

    @staticmethod
    def _new_xml_tempfile() -> str | None:
        """Create a temp file for nmap XML output.  Returns None on failure."""
        try:
            fd, path = tempfile.mkstemp(prefix="redscan_", suffix=".xml")
            os.close(fd)
            return path
        except OSError:
            return None

    def _log_preflight_warnings(self, cmd: list[str]) -> tuple[list[str], list[_ConflictInfo]]:
        """Run the dynamic conflict manager against *cmd*.

        Auto-fix rules mutate the command (e.g. remove -sV when -sn is set);
        warn-only rules emit advisory messages to the log;
        error rules emit a message but do NOT mutate — the caller must gate
        the scan start on the returned message list.

        Returns
        -------
        (clean_cmd, messages)
            ``clean_cmd`` – the possibly-modified command list.
            ``messages``  – all (severity, text) pairs from triggered rules.
        """
        target = self._target_var.get().strip()
        ports_str = self._ports_var.get().strip()

        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            is_root = True  # Windows

        clean_cmd, messages = _conflict_manager.apply(cmd, target, ports_str, is_root)
        for severity, text in messages:
            self._log(text + "\n")

        return clean_cmd, messages

    def _start_scan(self) -> None:
        if self._running:
            return
        if not self._target_var.get().strip():
            self._status_var.set("Enter a target IP/hostname before running.")
            _error_dialog(self, "Missing Target", "Please enter a target IP, hostname, or CIDR range.")
            return
        self._hosts.clear()
        self._host_listbox.delete(0, "end")
        self._port_table.delete("1.0", "end")
        self._log_text.delete("1.0", "end")
        self._running = True
        self._run_btn.configure(state="disabled")

        cmd = self._build_command()
        # Run the conflict manager: auto-fix rules may return a cleaned cmd;
        # error-level rules block the scan entirely.
        cmd, preflight_msgs = self._log_preflight_warnings(cmd)
        if ConflictManager.has_errors(preflight_msgs):
            error_texts = [
                text for sev, text in preflight_msgs if sev == "error"
            ]
            self._running = False
            self._run_btn.configure(state="normal")
            self._status_var.set("Scan blocked — fix errors first.")
            _error_dialog(
                self,
                "Scan Blocked — Error Detected",
                "\n\n".join(error_texts),
            )
            return
        self._command_used = " ".join(cmd)
        self._log(f"[*] Starting scan: {self._command_used}\n")
        self._status_var.set("Scanning…")

        threading.Thread(target=self._scan_worker, args=(cmd,), daemon=True).start()

    def _scan_worker(self, cmd: list[str]) -> None:
        returncode: int | None = None
        try:
            self._scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            current_host: str | None = None
            for line in self._scan_process.stdout:  # type: ignore[union-attr]
                self._event_queue.put({"type": "line", "text": line.rstrip()})
                # Parse host
                m_host = _HOST_RE.search(line)
                if m_host:
                    current_host = m_host.group(1).strip()
                    self._event_queue.put({"type": "new_host", "host": current_host})
                # Parse open port
                m_port = _OPEN_PORT_RE.search(line)
                if m_port and current_host:
                    self._event_queue.put({
                        "type": "open_port",
                        "host": current_host,
                        "port": m_port.group("port"),
                        "proto": m_port.group("proto"),
                        "service": m_port.group("service"),
                        "version": (m_port.group("version") or "").strip(),
                    })
                # Parse OS
                m_os = _OS_RE.search(line)
                if m_os and current_host:
                    self._event_queue.put({"type": "os", "host": current_host, "os": m_os.group(1)})

            returncode = self._scan_process.wait()
        except FileNotFoundError:
            self._event_queue.put({"type": "line", "text": "[!] nmap not found in PATH"})
        except Exception as exc:
            self._event_queue.put({"type": "line", "text": f"[!] Error: {exc}"})
        finally:
            self._event_queue.put({"type": "done", "returncode": returncode})

    def _stop_scan(self) -> None:
        if self._scan_process:
            self._scan_process.terminate()
        # Immediately restore the UI state so the user can start a new scan
        # without waiting for the worker thread's "done" event.
        self._running = False
        self._run_btn.configure(state="normal")
        self._status_var.set("Scan stopped by user.")

    # ── Event polling (called from Tk main thread) ────────────────────────────

    def _poll_events(self) -> None:
        try:
            while True:
                event = self._event_queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _handle_event(self, event: dict[str, Any]) -> None:
        etype = event["type"]

        if etype == "line":
            self._log(event["text"] + "\n")

        elif etype == "new_host":
            host = event["host"]
            if host not in self._hosts:
                self._hosts[host] = HostRecord(host)
                self._host_listbox.insert("end", f"  {host}")
                self._update_stats()

        elif etype == "open_port":
            host = event["host"]
            if host not in self._hosts:
                self._hosts[host] = HostRecord(host)
                self._host_listbox.insert("end", f"  {host}")
            self._hosts[host].ports.append({
                "port": event["port"],
                "proto": event["proto"],
                "state": "open",
                "service": event["service"],
                "version": event["version"],
                "scripts": [],
            })
            self._update_stats()
            if self._current_host == host:
                self._refresh_port_table(host)

        elif etype == "os":
            host = event["host"]
            if host in self._hosts:
                self._hosts[host].os_guess = event["os"]

        elif etype == "done":
            returncode = event.get("returncode")
            self._running = False
            self._run_btn.configure(state="normal")
            if returncode is not None and returncode != 0:
                self._status_var.set(
                    f"Scan finished with error (exit code {returncode}) at "
                    f"{datetime.now().strftime('%H:%M:%S')}"
                )
                self._log(f"[!] nmap exited with code {returncode}\n")
            else:
                self._status_var.set(
                    f"Scan complete — {len(self._hosts)} host(s) found at "
                    f"{datetime.now().strftime('%H:%M:%S')}"
                )
            # Enrich host records from the XML output file (richer version/OS data).
            if self._xml_tempfile:
                self._enrich_from_xml(self._xml_tempfile)
                self._xml_tempfile = None

    # ── Display helpers ───────────────────────────────────────────────────────

    def _log(self, text: str) -> None:
        self._log_text.insert("end", text)
        self._log_text.see("end")

    def _on_filter_change(self, *_: Any) -> None:
        """Re-populate the host listbox with hosts matching the filter text."""
        query = self._filter_var.get().strip().lower()
        self._host_listbox.delete(0, "end")
        for host in self._hosts:
            if not query or query in host.lower():
                self._host_listbox.insert("end", f"  {host}")

    def _load_user_presets(self) -> None:
        """Load Command-Factory presets from ~/.redscan_presets.json.

        Each entry is added to the preset ComboBox with the name as given.
        Entries are prefixed with "[user] " to distinguish them from the
        built-in catalogue presets.
        """
        if not _USER_PRESETS_PATH.exists():
            return
        try:
            entries: list[dict[str, Any]] = json.loads(_USER_PRESETS_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(entries, list):
            return
        added: list[str] = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            command = str(item.get("command", "")).strip()
            if name and command:
                display = f"[user] {name}"
                self._user_presets[display] = command
                added.append(display)
        if added:
            current = list(self._preset_combo.cget("values"))
            new_values = current + [k for k in added if k not in current]
            self._preset_combo.configure(values=new_values)

    def _enrich_from_xml(self, xml_path: str) -> None:
        """Parse nmap's XML output and update host records with richer data.

        The text-based parser captures port/proto/service/version via regex.
        The XML output additionally provides:
          - Accurate service product strings (e.g. "nginx 1.18.0")
          - OS detection matches with confidence percentages
          - NSE script output per port

        We merge this data into existing host records (updating in place) and
        clean up the temp file afterwards.
        """
        if not _XML_PARSER_AVAILABLE or _parse_nmap_xml is None:
            self._log(
                "[i] XML enrichment unavailable (xml_parser module not found). "
                "Version/OS data from the text stream only.\n"
            )
            try:
                os.unlink(xml_path)
            except OSError:
                pass
            return
        try:
            scan_info = _parse_nmap_xml(xml_path)
        except Exception as exc:
            self._log(f"[!] XML enrichment failed: {exc}\n")
            scan_info = None
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

        if not scan_info or not scan_info.get("hosts"):
            return

        for host_data in scan_info["hosts"]:
            # Resolve primary IP address
            ip = next(
                (a["addr"] for a in host_data.get("addresses", []) if a.get("type") == "ipv4"),
                None,
            ) or next(
                (a["addr"] for a in host_data.get("addresses", []) if a.get("addr")),
                None,
            )
            if not ip:
                continue

            # The dashboard may have recorded the host under its hostname
            # ("hostname.local") or its IP.  Try both.
            record = self._hosts.get(ip)
            if record is None:
                # Also try the first hostname listed by nmap
                hostnames = host_data.get("hostnames", [])
                for hn in hostnames:
                    record = self._hosts.get(hn)
                    if record:
                        break
            if record is None:
                continue  # Host not tracked by the text parser (shouldn't happen)

            # ── OS guess ──────────────────────────────────────────────────────
            os_matches = host_data.get("os_matches", [])
            if os_matches:
                best = os_matches[0]
                record.os_guess = f"{best['name']} ({best.get('accuracy', '?')}%)"
            record.hostnames = [str(h) for h in host_data.get("hostnames", []) if h]

            # ── Port enrichment ───────────────────────────────────────────────
            # Build a lookup by (port, protocol) from the XML.
            xml_ports: dict[tuple[str, str], dict[str, Any]] = {}
            for p in host_data.get("ports", []):
                if p.get("state") == "open":
                    xml_ports[(str(p["port"]), str(p.get("protocol", "tcp")))] = p

            # Update existing port records with richer version data.
            for port_rec in record.ports:
                key = (str(port_rec["port"]), str(port_rec.get("proto", "tcp")))
                xml_p = xml_ports.get(key)
                if xml_p:
                    product = xml_p.get("product", "").strip()
                    version = xml_p.get("version", "").strip()
                    full_version = f"{product} {version}".strip()
                    if full_version:
                        port_rec["version"] = full_version
                    if xml_p.get("service") and xml_p["service"] != "Unknown":
                        port_rec["service"] = xml_p["service"]
                    port_rec["state"] = xml_p.get("state", port_rec.get("state", "open"))
                    port_rec["scripts"] = list(xml_p.get("scripts", []))

            # Add any ports that were in the XML but missed by the text regex
            # (rare but possible for filtered/closed ports shown in XML).
            existing_keys = {
                (str(p["port"]), str(p.get("proto", "tcp"))) for p in record.ports
            }
            for (port_num, proto), xml_p in xml_ports.items():
                if (port_num, proto) not in existing_keys:
                    product = xml_p.get("product", "").strip()
                    version = xml_p.get("version", "").strip()
                    record.ports.append({
                        "port": port_num,
                        "proto": proto,
                        "state": xml_p.get("state", "open"),
                        "service": xml_p.get("service", "unknown"),
                        "version": f"{product} {version}".strip(),
                        "scripts": list(xml_p.get("scripts", [])),
                    })

        # Re-render the currently-selected host table with enriched data.
        if self._current_host:
            self._refresh_port_table(self._current_host)
        self._update_stats()

    def _on_host_select(self, _: tk.Event) -> None:  # type: ignore[type-arg]
        sel = self._host_listbox.curselection()
        if not sel:
            return
        label = self._host_listbox.get(sel[0]).strip()
        self._current_host = label
        self._detail_host_lbl.configure(text=label)
        self._refresh_port_table(label)

    def _refresh_port_table(self, host: str) -> None:
        self._port_table.delete("1.0", "end")
        if host not in self._hosts:
            return
        record = self._hosts[host]
        hostnames = f" ({', '.join(record.hostnames)})" if record.hostnames else ""
        self._port_table.insert("end", f"HOST: {record.host}{hostnames}   OS: {record.os_guess}\n")
        self._port_table.insert("end", "─" * 70 + "\n")
        self._port_table.insert("end", f"{'PORT':<8}{'PROTO':<8}{'STATE':<10}{'SERVICE':<16}{'VERSION'}\n")
        self._port_table.insert("end", "─" * 70 + "\n")
        for p in record.ports:
            self._port_table.insert(
                "end",
                f"{p['port']:<8}{p['proto']:<8}{p.get('state', 'open'):<10}{p['service']:<16}{p['version']}\n",
            )
            scripts = p.get("scripts", [])
            if isinstance(scripts, list) and scripts:
                ids = ", ".join(str(s.get("id", "")) for s in scripts[:3] if isinstance(s, dict) and s.get("id"))
                if ids:
                    self._port_table.insert("end", f"   ↳ NSE: {ids}\n")

    def _update_stats(self) -> None:
        total_ports = sum(len(h.ports) for h in self._hosts.values())
        services = {p["service"] for h in self._hosts.values() for p in h.ports}
        os_count = sum(1 for h in self._hosts.values() if h.os_guess != "Unknown")
        self._stat_hosts.configure(text=str(len(self._hosts)))
        self._stat_open.configure(text=str(total_ports))
        self._stat_services.configure(text=str(len(services)))
        self._stat_os.configure(text=str(os_count))

    def _trigger_ai(self) -> None:
        self._on_ai_insights(list(self._hosts.values()), self._command_used)

    # ── Session persistence ───────────────────────────────────────────────────

    def _save_session(self) -> None:
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("RedScan Session", "*.json")],
        )
        if not path:
            return
        data = {
            "saved_at": datetime.now().isoformat(),
            "command": self._command_used,
            "hosts": [h.to_dict() for h in self._hosts.values()],
        }
        Path(path).write_text(json.dumps(data, indent=2))
        self._status_var.set(f"Session saved → {path}")

    def _load_session(self) -> None:
        from tkinter import filedialog, messagebox
        path = filedialog.askopenfilename(
            filetypes=[("RedScan Session", "*.json")]
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror(
                "Load Failed",
                f"Could not read session file:\n{exc}",
            )
            return
        self._hosts.clear()
        self._host_listbox.delete(0, "end")
        for hd in data.get("hosts", []):
            try:
                record = HostRecord.from_dict(hd)
            except (KeyError, TypeError):
                continue  # skip malformed host records; load what we can
            self._hosts[record.host] = record
            self._host_listbox.insert("end", f"  {record.host}")
        self._command_used = data.get("command", "")
        self._update_stats()
        self._status_var.set(
            f"Session loaded — {len(self._hosts)} host(s) from {data.get('saved_at', 'unknown')}"
        )

    # ── External API ─────────────────────────────────────────────────────────

    def set_preset(self, preset_key: str) -> None:
        """Public API: select a preset by key. Used by app.py to avoid
        reaching into private widget state."""
        self._preset_var.set(preset_key)
        self._refresh_ports_gate()

    def start_scan(self) -> None:
        """Public API: start a scan with the current target / preset / ports.

        Delegates to the internal _start_scan() so that callers (e.g. app.py
        when a preset is activated from the Preset Browser) do not depend on
        the private method name.
        """
        self._start_scan()

    def run_custom_command(self, command_str: str) -> None:
        """Called from Command Factory to run a free-form command string."""
        import shlex
        try:
            parts = shlex.split(command_str)
        except ValueError:
            # Malformed quoting — fall back to simple split so the user at
            # least sees something rather than a silent failure.
            parts = command_str.split()
        if not parts:
            return
        # Extract target (last non-flag arg)
        target = parts[-1] if not parts[-1].startswith("-") else "127.0.0.1"
        self._target_var.set(target)
        self._preset_var.set("(none)")
        self._ports_var.set("")
        self._refresh_ports_gate()
        self._hosts.clear()
        self._host_listbox.delete(0, "end")
        self._log_text.delete("1.0", "end")
        self._running = True
        self._run_btn.configure(state="disabled")
        # Route command-factory commands through ConflictManager as well.
        clean_cmd, preflight_msgs = self._log_preflight_warnings(parts)
        if ConflictManager.has_errors(preflight_msgs):
            error_texts = [text for sev, text in preflight_msgs if sev == "error"]
            self._running = False
            self._run_btn.configure(state="normal")
            self._status_var.set("Scan blocked — fix errors first.")
            _error_dialog(
                self,
                "Scan Blocked — Error Detected",
                "\n\n".join(error_texts),
            )
            return
        self._command_used = " ".join(clean_cmd)
        self._log(f"[*] Command Factory → {self._command_used}\n")
        self._status_var.set("Scanning…")
        threading.Thread(target=self._scan_worker, args=(clean_cmd,), daemon=True).start()

    def load_from_smart_scan(
        self, endpoints: list[dict[str, Any]], rate: float
    ) -> None:
        """Populate the dashboard with open endpoints discovered by Smart Scan.

        Because Smart Scan uses TCP connect probes (no -sV), service names and
        version strings are not available.  The port table shows "—" for those
        fields and prompts the user to run a -sV scan for full enumeration.
        """
        self._hosts.clear()
        self._current_host = None
        self._host_listbox.delete(0, "end")
        self._port_table.delete("1.0", "end")
        self._log_text.delete("1.0", "end")

        for ep in endpoints:
            host = str(ep["host"])
            port = str(ep["port"])
            if host not in self._hosts:
                self._hosts[host] = HostRecord(host)
                self._host_listbox.insert("end", f"  {host}")
            self._hosts[host].ports.append({
                "port": port,
                "proto": "tcp",
                "service": "—",
                "version": "(Smart Scan — run -sV for details)",
            })

        self._command_used = (
            f"[Smart Scan adaptive discovery — {rate:.0f} probes/s]"
        )
        self._update_stats()
        self._log(
            f"[*] Smart Scan results loaded — "
            f"{len(self._hosts)} host(s), {len(endpoints)} open port(s) "
            f"at {rate:.0f} probes/s\n"
            "[!] Service names not available — "
            "run a -sV enumeration scan on these ports for full details.\n"
        )
        self._status_var.set(
            f"Smart Scan: {len(self._hosts)} host(s), "
            f"{len(endpoints)} open port(s) discovered"
        )


# ---------------------------------------------------------------------------
# Module-level helper dialogs
# ---------------------------------------------------------------------------

def _error_dialog(parent: ctk.CTkFrame, title: str, message: str) -> None:
    """Show a blocking error dialog that cannot be dismissed accidentally.

    Uses a red accent colour to distinguish it from informational dialogs.
    """
    from gui.styles import FONT_SMALL, PAD
    import customtkinter as _ctk

    dlg = _ctk.CTkToplevel(parent)
    dlg.title(title)
    dlg.geometry("480x200")
    dlg.grab_set()
    dlg.configure(fg_color="#1a0a0a")

    _ctk.CTkLabel(
        dlg,
        text="⛔  " + title,
        font=("Segoe UI", 13, "bold"),
        text_color="#e94560",
    ).pack(padx=PAD, pady=(PAD, 0), anchor="w")

    _ctk.CTkLabel(
        dlg,
        text=message,
        font=FONT_SMALL,
        text_color="#ffbbbb",
        wraplength=440,
        justify="left",
    ).pack(padx=PAD, pady=PAD, fill="x")

    _ctk.CTkButton(
        dlg,
        text="Dismiss",
        fg_color="#5a1a1a",
        hover_color="#8a2a2a",
        command=dlg.destroy,
    ).pack(pady=(0, PAD))

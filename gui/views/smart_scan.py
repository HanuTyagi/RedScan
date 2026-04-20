"""
Smart Scan panel – adaptive PID+AIMD discovery layer.

Enhancements in this revision
──────────────────────────────
• Root-privilege warning banner
• Basic config (always visible) + collapsible Advanced Options section
  (PID/AIMD sliders, probe type, fragmented-packets toggle)
• Inline parameter descriptions on every slider/field
• Live packet-feed tab (per-probe events streamed in real time, capped)
• Breakpoint handoff dialog after the scan:
    – summary stats + recommended nmap timing template
    – scan-type picker, command preview
    – "Run Nmap Scan" / "Copy Command" / "Dashboard Only" buttons
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
import tkinter as tk
from typing import Any, Callable

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, BG_CARD, BG_SECONDARY, BTN_CORNER, CARD_CORNER,
    FONT_H1, FONT_H2, FONT_MONO_SM, FONT_SMALL, PAD, PAD_S,
    TEXT_MUTED, TEXT_SUCCESS,
)
from redscan.models import DiscoveryConfig, DiscoveryStats, Endpoint, ProbeResult
from redscan.smart_scan import SmartScanModule

# ── Timing recommendation ────────────────────────────────────────────────────

_T_LEVELS: list[tuple[float | None, str, str]] = [
    (5.0,   "T5", "Insane — very fast LAN (RTT < 5 ms)"),
    (20.0,  "T4", "Aggressive — fast network (RTT 5–20 ms)"),
    (100.0, "T3", "Normal — typical internet (RTT 20–100 ms)"),
    (300.0, "T2", "Polite — slow connection (RTT 100–300 ms)"),
    (None,  "T1", "Sneaky — congested / long-haul (RTT > 300 ms)"),
]


def _recommend_timing(rtt_ms: float | None) -> tuple[str, str]:
    if rtt_ms is None:
        return "T3", "Normal (no RTT data available)"
    for threshold, level, desc in _T_LEVELS:
        if threshold is None or rtt_ms < threshold:
            return level, desc
    return "T1", "Sneaky — congested / long-haul"


# ── Follow-up nmap scan templates ────────────────────────────────────────────

_HANDOFF_SCANS: list[tuple[str, str]] = [
    ("Quick SYN Scan",          "-sS -sV"),
    ("Full Service Detection",  "-sS -sV --version-intensity 9"),
    ("OS + Version Detection",  "-sS -sV -O"),
    ("Vulnerability Scripts",   "-sS --script=vuln"),
    ("Full TCP Connect",        "-sT -sV"),
    ("Aggressive (-A)",         "-A"),
    ("UDP Top Ports",           "-sU --top-ports 200"),
    ("Stealth FIN Scan",        "-sF"),
    ("NULL Scan",               "-sN"),
    ("XMAS Scan",               "-sX"),
]

# ── Labelled slider with description ─────────────────────────────────────────


class _LabeledSlider(ctk.CTkFrame):
    """Label + slider + numeric readout with an optional description line."""

    def __init__(
        self,
        master: ctk.CTkFrame,
        label: str,
        from_: float,
        to: float,
        default: float,
        fmt: str = "{:.3f}",
        desc: str = "",
        **kwargs: object,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._fmt = fmt
        self._var = tk.DoubleVar(value=default)
        self._var.trace_add("write", self._update_readout)

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x")
        ctk.CTkLabel(row, text=label, font=FONT_SMALL, width=200, anchor="w").pack(side="left")
        self._readout = ctk.CTkLabel(row, text=fmt.format(default), font=FONT_MONO_SM, width=70, anchor="e")
        self._readout.pack(side="right")

        ctk.CTkSlider(
            self, from_=from_, to=to, variable=self._var, progress_color=ACCENT,
        ).pack(fill="x", padx=PAD_S, pady=(0, 0))

        if desc:
            ctk.CTkLabel(
                self, text=desc, font=("Segoe UI", 9), text_color=TEXT_MUTED,
                wraplength=320, justify="left", anchor="w",
            ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

    def _update_readout(self, *_: object) -> None:
        self._readout.configure(text=self._fmt.format(self._var.get()))

    @property
    def value(self) -> float:
        return self._var.get()


# ── Main view ────────────────────────────────────────────────────────────────


class SmartScanView(ctk.CTkFrame):
    """Smart Scan configuration panel and results viewer."""

    def __init__(
        self,
        master: ctk.CTk | ctk.CTkFrame,
        on_hosts_discovered: Callable[[list[dict[str, int | str]], float], None],
        on_run_nmap_command: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._on_hosts_discovered = on_hosts_discovered
        self._on_run_nmap = on_run_nmap_command
        self._running = False
        self._adv_visible = False
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        ctk.CTkLabel(
            self, text="⚡  Smart Scan (Adaptive PID+AIMD)", font=FONT_H1, anchor="w",
        ).pack(fill="x", padx=PAD, pady=(PAD, 0))
        ctk.CTkLabel(
            self,
            text=(
                "Automatically calibrates probe rate using RTT feedback. "
                "Basic settings below are sufficient for most use cases. "
                "Expand Advanced Options for fine-grained PID/AIMD tuning and packet-type selection."
            ),
            font=FONT_SMALL, text_color=TEXT_MUTED, wraplength=900,
            justify="left", anchor="w",
        ).pack(fill="x", padx=PAD, pady=(0, PAD_S))

        # Root privilege warning ──────────────────────────────────────────────
        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            is_root = True  # Windows — skip check

        if not is_root:
            warn = ctk.CTkFrame(self, fg_color="#2a1a0a", corner_radius=6)
            warn.pack(fill="x", padx=PAD, pady=(0, PAD_S))
            ctk.CTkLabel(
                warn,
                text=(
                    "⚠  Smart Scan sends raw TCP probes and requires root / Administrator "
                    "privileges for full functionality.  TCP SYN and UDP probe types will "
                    "automatically fall back to TCP Connect when running without root."
                ),
                font=FONT_SMALL, text_color="#ffcc88",
                wraplength=880, justify="left", anchor="w",
            ).pack(padx=PAD_S, pady=PAD_S)

        # Body (two columns) ──────────────────────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD_S))
        body.columnconfigure(0, weight=1, minsize=340)
        body.columnconfigure(1, weight=2)

        # ── Left: config form ─────────────────────────────────────────────────
        cfg_frame = ctk.CTkScrollableFrame(
            body, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER,
            label_text="Scan Configuration",
        )
        cfg_frame.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_S))

        # Basic parameters (always visible)
        self._target_var     = tk.StringVar(value="192.168.1.0/24")
        self._port_range_var = tk.StringVar(value="22,80,443,8080")
        self._calib_host_var = tk.StringVar(value="8.8.8.8")
        self._calib_port_var = tk.IntVar(value=53)

        self._add_field(cfg_frame, "Target(s) (CIDR / IPv6 prefix / comma-separated IPs):", self._target_var,
            "e.g. 192.168.1.0/24, 10.0.0.1,10.0.0.2, or 2001:db8::/64.  "
            "The scanner probes every target IP × port combination.")
        self._add_field(cfg_frame, "Ports to probe (comma-separated):", self._port_range_var,
            "TCP/UDP ports checked on every host.  Examples: 22,80,443 for quick recon; "
            "1-1024 for thorough coverage.")
        self._add_field(cfg_frame, "Calibration Host:", self._calib_host_var,
            "A reliable always-reachable host used to measure RTT and calibrate the probe "
            "rate.  Use 8.8.8.8 for internet scans or your LAN gateway for internal scans.")
        self._add_field(cfg_frame, "Calibration Port:", self._calib_port_var,
            "Port on the calibration host to connect to.  Port 53 (DNS) is universally "
            "reachable and gives a fast response.")

        ctk.CTkFrame(cfg_frame, height=1, fg_color="#2a4a6a").pack(fill="x", pady=PAD)

        # Advanced options toggle ─────────────────────────────────────────────
        self._adv_btn = ctk.CTkButton(
            cfg_frame, text="⚙  Advanced Options ▶",
            fg_color="#1a2a3a", hover_color="#2a4a6a",
            corner_radius=BTN_CORNER, font=FONT_SMALL,
            command=self._toggle_advanced,
        )
        self._adv_btn.pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

        # Advanced options frame (hidden by default) ──────────────────────────
        self._adv_frame = ctk.CTkFrame(cfg_frame, fg_color="transparent")

        ctk.CTkLabel(self._adv_frame, text="Rate Controller", font=FONT_H2, anchor="w").pack(
            fill="x", padx=PAD_S)

        self._s_r_min   = _LabeledSlider(self._adv_frame, "R_min (probes/s)",  1,   200,  10, "{:.0f}",
            "Minimum probe rate enforced after AIMD backoffs.  Keep ≥ 5 for reasonable throughput.")
        self._s_r_max   = _LabeledSlider(self._adv_frame, "R_max (probes/s)", 10, 2000, 500, "{:.0f}",
            "Hard cap on probe rate.  Increase for fast LANs; lower for congested links or stealth.")
        self._s_r_init  = _LabeledSlider(self._adv_frame, "Initial Rate",      1,  500, 120, "{:.0f}",
            "Probe rate before the first calibration RTT sample arrives.  100–150 is safe for most networks.")
        self._s_alpha   = _LabeledSlider(self._adv_frame, "EWMA α (smoothing)", 0.01, 0.99, 0.2,
            "Controls how quickly filtered RTT tracks new samples.  Higher = more reactive; lower = smoother.")
        self._s_delta   = _LabeledSlider(self._adv_frame, "δ RTT target margin (ms)", 0, 20, 3, "{:.1f}",
            "Extra ms added to RTT_base to form the PID target.  A 2–5 ms margin avoids oscillation.")
        self._s_kp      = _LabeledSlider(self._adv_frame, "Kp (proportional gain)",  0, 0.5, 0.04,
            "Proportional PID term.  Increase for faster rate adjustment; too high causes oscillation.")
        self._s_ki      = _LabeledSlider(self._adv_frame, "Ki (integral gain)",      0, 0.1, 0.008,
            "Integral term eliminates steady-state error.  Keep very small (< 0.01) to avoid wind-up.")
        self._s_kd      = _LabeledSlider(self._adv_frame, "Kd (derivative gain)",    0, 0.1, 0.01,
            "Derivative term dampens rapid RTT changes.  Helps with sudden RTT spikes; too high amplifies noise.")
        self._s_beta    = _LabeledSlider(self._adv_frame, "β AIMD backoff factor",   0.1, 0.95, 0.5,
            "Multiplicative decrease on loss: new_rate = β × rate.  0.5 = classic TCP backoff.")
        self._s_loss_w  = _LabeledSlider(self._adv_frame, "Loss window (s)",         0.5, 30, 2, "{:.1f}",
            "Rolling window over which calibration timeouts are counted.  Shorter = more reactive.")
        self._s_loss_thr= _LabeledSlider(self._adv_frame, "Loss threshold (count)",  1, 50, 5,  "{:.0f}",
            "Calibration timeouts within the loss window that trigger AIMD backoff.  Lower = more sensitive.")
        self._s_timeout = _LabeledSlider(self._adv_frame, "Connect timeout (s)",     0.05, 5, 0.5,
            "How long to wait for a TCP connection before calling it a timeout.  Increase for slow hosts.")
        self._s_calib_n = _LabeledSlider(self._adv_frame, "Calibration ratio N",     1, 512, 64, "{:.0f}",
            "One calibration probe is sent for every N target probes.  Lower = more RTT updates (more overhead).")

        for sl in [
            self._s_r_min, self._s_r_max, self._s_r_init,
            self._s_alpha, self._s_delta,
            self._s_kp, self._s_ki, self._s_kd, self._s_beta,
            self._s_loss_w, self._s_loss_thr, self._s_timeout, self._s_calib_n,
        ]:
            sl.pack(fill="x", padx=PAD_S, pady=1)

        # Probe options ───────────────────────────────────────────────────────
        ctk.CTkFrame(self._adv_frame, height=1, fg_color="#2a4a6a").pack(
            fill="x", pady=PAD, padx=PAD_S)
        ctk.CTkLabel(self._adv_frame, text="Probe Options", font=FONT_H2, anchor="w").pack(
            fill="x", padx=PAD_S)

        ctk.CTkLabel(self._adv_frame, text="Probe Type:", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD_S, pady=(PAD_S, 0))
        self._probe_type_var = tk.StringVar(value="tcp_connect")
        ctk.CTkSegmentedButton(
            self._adv_frame,
            values=["tcp_connect", "udp", "icmp", "tcp_syn"],
            variable=self._probe_type_var,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))
        ctk.CTkLabel(
            self._adv_frame,
            text=(
                "tcp_connect — full TCP handshake (no root needed).\n"
                "udp — send a UDP datagram; ICMP port-unreachable = closed.\n"
                "icmp — ICMP echo ping (checks host liveness, ignores port).\n"
                "tcp_syn — half-open SYN scan (requires root; fastest & stealthy)."
            ),
            font=("Segoe UI", 9), text_color=TEXT_MUTED,
            justify="left", anchor="w", wraplength=310,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

        self._fragmented_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self._adv_frame, text="Use fragmented IP packets",
            variable=self._fragmented_var, fg_color=ACCENT, hover_color=ACCENT_HOVER,
        ).pack(padx=PAD_S, pady=(0, 0), anchor="w")
        ctk.CTkLabel(
            self._adv_frame,
            text=(
                "Splits probe packets into small IP fragments to evade some firewalls "
                "and IDS rules.  Requires root; not applicable to tcp_connect / icmp types."
            ),
            font=("Segoe UI", 9), text_color=TEXT_MUTED,
            justify="left", anchor="w", wraplength=310,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD))

        # ── Host-up prefilter & adaptive port ordering ────────────────────────
        ctk.CTkFrame(self._adv_frame, height=1, fg_color="#2a4a6a").pack(
            fill="x", pady=PAD, padx=PAD_S)
        ctk.CTkLabel(self._adv_frame, text="Discovery Optimisations", font=FONT_H2, anchor="w").pack(
            fill="x", padx=PAD_S)

        self._host_prefilter_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self._adv_frame, text="Host-up prefilter (ICMP ping sweep)",
            variable=self._host_prefilter_var, fg_color=ACCENT, hover_color=ACCENT_HOVER,
        ).pack(padx=PAD_S, pady=(PAD_S, 0), anchor="w")
        ctk.CTkLabel(
            self._adv_frame,
            text=(
                "Before port scanning, pings every host in the target list to confirm it is "
                "up.  Eliminates wasted probes against offline hosts but adds an extra sweep "
                "round.  Requires ICMP to be unblocked on the network."
            ),
            font=("Segoe UI", 9), text_color=TEXT_MUTED,
            justify="left", anchor="w", wraplength=310,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

        self._adaptive_ports_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            self._adv_frame, text="Adaptive port ordering",
            variable=self._adaptive_ports_var, fg_color=ACCENT, hover_color=ACCENT_HOVER,
        ).pack(padx=PAD_S, pady=(0, 0), anchor="w")
        ctk.CTkLabel(
            self._adv_frame,
            text=(
                "Reorders the port list so the most commonly open ports (e.g. 80, 443, 22) "
                "are probed first.  Helps surface interesting findings early in long scans."
            ),
            font=("Segoe UI", 9), text_color=TEXT_MUTED,
            justify="left", anchor="w", wraplength=310,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD))

        # ── Custom DNS ────────────────────────────────────────────────────────
        ctk.CTkFrame(self._adv_frame, height=1, fg_color="#2a4a6a").pack(
            fill="x", pady=PAD, padx=PAD_S)
        ctk.CTkLabel(self._adv_frame, text="Network Options", font=FONT_H2, anchor="w").pack(
            fill="x", padx=PAD_S)

        self._dns_server_var = tk.StringVar(value="")
        self._add_field(self._adv_frame, "Custom DNS Server (optional):", self._dns_server_var,
            "IP address of a DNS server to use when resolving hostnames.  Leave blank to "
            "use the system resolver.  Useful in isolated networks or for testing "
            "split-horizon DNS setups.  e.g. 1.1.1.1 or 192.168.1.1")

        # ── Checkpoint ───────────────────────────────────────────────────────
        self._checkpoint_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            self._adv_frame, text="Enable scan progress checkpoint",
            variable=self._checkpoint_var, fg_color=ACCENT, hover_color=ACCENT_HOVER,
        ).pack(padx=PAD_S, pady=(PAD_S, 0), anchor="w")
        ctk.CTkLabel(
            self._adv_frame,
            text=(
                "Periodically saves discovered endpoints to ~/.redscan_scan.ckpt so the "
                "scan can be resumed after a crash or manual abort.  The file is deleted "
                "on clean completion."
            ),
            font=("Segoe UI", 9), text_color=TEXT_MUTED,
            justify="left", anchor="w", wraplength=310,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD))

        # Action buttons ──────────────────────────────────────────────────────
        self._run_btn = ctk.CTkButton(
            cfg_frame, text="⚡  Start Smart Scan",
            fg_color=ACCENT, hover_color=ACCENT_HOVER, corner_radius=BTN_CORNER,
            command=self._start_scan,
        )
        self._run_btn.pack(fill="x", padx=PAD_S, pady=PAD)
        ctk.CTkButton(
            cfg_frame, text="⏹  Stop",
            fg_color="#4a1a1a", hover_color="#6a2a2a", corner_radius=BTN_CORNER,
            command=self._stop_scan,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD))

        # ── Right: live output ─────────────────────────────────────────────────
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.rowconfigure(2, weight=2)
        right.columnconfigure(0, weight=1)

        # Stat cards ──────────────────────────────────────────────────────────
        cards = ctk.CTkFrame(right, fg_color="transparent")
        cards.grid(row=0, column=0, sticky="ew")
        self._card_rate    = self._stat_card(cards, "Current Rate", "—")
        self._card_rtt     = self._stat_card(cards, "Filtered RTT", "—")
        self._card_open    = self._stat_card(cards, "Open Ports", "0")
        self._card_total   = self._stat_card(cards, "Probes Sent", "0")
        self._card_dropped = self._stat_card(cards, "Timeouts", "0")

        # Rate mini-chart ─────────────────────────────────────────────────────
        chart_frame = ctk.CTkFrame(right, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        chart_frame.grid(row=1, column=0, sticky="nsew", pady=(PAD, PAD_S))
        ctk.CTkLabel(chart_frame, text="Rate History", font=FONT_H2, anchor="w").pack(
            padx=PAD, pady=PAD_S, anchor="w")
        self._rate_canvas = tk.Canvas(chart_frame, bg="#0a1220", height=100, highlightthickness=0)
        self._rate_canvas.pack(fill="both", expand=True, padx=PAD_S, pady=(0, PAD_S))
        self._rate_history: list[float] = []

        # Tabview: Live Feed | Discovery Log ──────────────────────────────────
        tab_frame = ctk.CTkTabview(right, fg_color=BG_SECONDARY)
        tab_frame.grid(row=2, column=0, sticky="nsew")
        tab_frame.add("📡  Live Feed")
        tab_frame.add("📋  Discovery Log")

        self._live_feed = ctk.CTkTextbox(
            tab_frame.tab("📡  Live Feed"),
            font=FONT_MONO_SM, fg_color="#080e18", text_color="#cccccc",
        )
        self._live_feed.pack(fill="both", expand=True)
        self._feed_count = 0
        self._FEED_MAX = 800

        self._log = ctk.CTkTextbox(
            tab_frame.tab("📋  Discovery Log"),
            font=FONT_MONO_SM, fg_color="#080e18", text_color="#88ddaa",
        )
        self._log.pack(fill="both", expand=True)

        self._status_var = tk.StringVar(value="Idle")
        ctk.CTkLabel(
            self, textvariable=self._status_var,
            font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w",
        ).pack(fill="x", padx=PAD, pady=(0, PAD))

    # ── Advanced toggle ───────────────────────────────────────────────────────

    def _toggle_advanced(self) -> None:
        self._adv_visible = not self._adv_visible
        if self._adv_visible:
            self._adv_frame.pack(fill="x", padx=PAD_S, pady=(0, PAD_S),
                                 before=self._run_btn)
            self._adv_btn.configure(text="⚙  Advanced Options ▼")
        else:
            self._adv_frame.pack_forget()
            self._adv_btn.configure(text="⚙  Advanced Options ▶")

    # ── Field helpers ─────────────────────────────────────────────────────────

    def _add_field(
        self,
        parent: ctk.CTkFrame,
        label: str,
        var: tk.Variable,
        desc: str = "",
    ) -> None:
        ctk.CTkLabel(parent, text=label, font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD_S, pady=(PAD_S, 0))
        ctk.CTkEntry(parent, textvariable=var, font=FONT_SMALL).pack(
            fill="x", padx=PAD_S, pady=(0, 0))
        if desc:
            ctk.CTkLabel(
                parent, text=desc, font=("Segoe UI", 9), text_color=TEXT_MUTED,
                wraplength=310, justify="left", anchor="w",
            ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

    def _stat_card(self, parent: ctk.CTkFrame, label: str, value: str) -> ctk.CTkLabel:
        box = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        box.pack(side="left", padx=PAD_S, pady=PAD_S)
        ctk.CTkLabel(box, text=label, font=FONT_SMALL, text_color=TEXT_MUTED).pack(
            padx=PAD, pady=(PAD_S, 0))
        lbl = ctk.CTkLabel(box, text=value, font=FONT_H1, text_color=TEXT_SUCCESS)
        lbl.pack(padx=PAD, pady=(0, PAD_S))
        return lbl

    # ── Config builder ────────────────────────────────────────────────────────

    def _build_config(self) -> DiscoveryConfig:
        import os as _os
        checkpoint_path: str | None = None
        if self._checkpoint_var.get():
            checkpoint_path = str(_os.path.expanduser("~/.redscan_scan.ckpt"))
        dns = self._dns_server_var.get().strip() or None
        return DiscoveryConfig(
            calibration_host=self._calib_host_var.get().strip(),
            calibration_port=self._calib_port_var.get(),
            calibration_ratio=max(1, int(self._s_calib_n.value)),
            connect_timeout_s=self._s_timeout.value,
            ewma_alpha=self._s_alpha.value,
            target_delta_ms=self._s_delta.value,
            kp=self._s_kp.value,
            ki=self._s_ki.value,
            kd=self._s_kd.value,
            r_min=self._s_r_min.value,
            r_max=self._s_r_max.value,
            initial_rate=self._s_r_init.value,
            loss_window_s=self._s_loss_w.value,
            loss_threshold=max(1, int(self._s_loss_thr.value)),
            aimd_beta=self._s_beta.value,
            probe_type=self._probe_type_var.get(),          # type: ignore[arg-type]
            fragmented=self._fragmented_var.get(),
            host_prefilter=self._host_prefilter_var.get(),
            adaptive_port_ordering=self._adaptive_ports_var.get(),
            checkpoint_path=checkpoint_path,
            dns_server=dns,
        )

    def _parse_targets(self) -> list[Endpoint]:
        raw = self._target_var.get().strip()
        port_str = self._port_range_var.get().strip()
        ports = [int(p) for p in port_str.split(",") if p.strip().isdigit()]
        if not ports:
            ports = [80]

        _MAX_HOSTS = 65_534
        hosts: list[str] = []
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                import ipaddress
                try:
                    # Handles both IPv4 and IPv6 CIDR notation
                    net = ipaddress.ip_network(token, strict=False)
                    host_list = list(net.hosts())
                    if len(host_list) > _MAX_HOSTS:
                        self._log_msg(
                            f"[!] CIDR {token} expands to {len(host_list):,} hosts "
                            f"(limit {_MAX_HOSTS:,}).  Use a /16 or smaller prefix.\n"
                        )
                        continue
                    hosts.extend(str(ip) for ip in host_list)
                except ValueError:
                    hosts.append(token)
            else:
                hosts.append(token)

        return [Endpoint(host=h, port=p) for h in hosts for p in ports]

    # ── Scan execution ────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        if self._running:
            return
        # ── Checkpoint resume prompt ──────────────────────────────────────────
        _resume = False
        if self._checkpoint_var.get():
            import os as _os
            ckpt_path = _os.path.expanduser("~/.redscan_scan.ckpt")
            if _os.path.exists(ckpt_path):
                import tkinter.messagebox as _mb
                _resume = _mb.askyesno(
                    "Resume Scan",
                    "A previous scan checkpoint was found.\n\n"
                    "Would you like to resume from where it left off?\n\n"
                    "Click 'Yes' to resume, 'No' to start fresh.",
                )
                if not _resume:
                    try:
                        _os.unlink(ckpt_path)
                    except OSError:
                        pass
        self._running = True
        self._run_btn.configure(state="disabled")
        self._rate_history.clear()
        self._log.delete("1.0", "end")
        self._live_feed.delete("1.0", "end")
        self._feed_count = 0
        self._status_var.set("Smart scan running…")
        cfg = self._build_config()
        endpoints = self._parse_targets()
        self._log_msg(
            f"[*] Probing {len(endpoints)} endpoint(s) via {cfg.probe_type}"
            f"{' (resume)' if _resume else ''}\n"
        )
        threading.Thread(
            target=self._scan_thread, args=(cfg, endpoints, _resume), daemon=True
        ).start()

    def _scan_thread(self, cfg: DiscoveryConfig, endpoints: list[Endpoint], resume: bool = False) -> None:
        module = SmartScanModule(cfg)
        loop = asyncio.new_event_loop()

        all_open: list[dict[str, Any]] = []
        final_rate_box: list[float] = [cfg.initial_rate]
        final_stats_box: list[DiscoveryStats | None] = [None]

        def _on_probe(result: ProbeResult, is_calib: bool) -> None:
            self.after(0, self._update_live_feed, result, is_calib)

        async def _run() -> None:
            batch_size = 20
            open_count = 0
            total = 0
            total_dropped = 0
            for i in range(0, len(endpoints), batch_size):
                if not self._running:
                    break
                batch = endpoints[i : i + batch_size]
                output = await module.discovery_pass(batch, per_probe_callback=_on_probe,
                                                     resume=(resume and i == 0))
                total += output.stats.total_count
                total_dropped += output.stats.timeout_count
                for ep in output.open_endpoints:
                    open_count += 1
                    all_open.append({"host": ep.host, "port": ep.port})
                    rtt_result = next(
                        (r for r in output.all_results if r.endpoint == ep and r.rtt_ms), None
                    )
                    rtt_str = (
                        f"{rtt_result.rtt_ms:.1f}ms"
                        if rtt_result and rtt_result.rtt_ms else "—"
                    )
                    self.after(0, self._log_msg, f"[+] OPEN  {ep.host}:{ep.port}  rtt={rtt_str}\n")
                final_rate_box[0] = output.stats.final_rate
                final_stats_box[0] = output.stats
                self.after(
                    0, self._update_live,
                    output.stats.final_rate,
                    output.stats.calibration_rtt_filtered_ms,
                    open_count, total, total_dropped,
                )
                self.after(0, self._card_open.configure, {"text": str(open_count)})

        try:
            loop.run_until_complete(_run())
        finally:
            loop.close()
            self.after(0, self._scan_done, all_open, final_rate_box[0], final_stats_box[0])

    def _stop_scan(self) -> None:
        self._running = False

    def _scan_done(
        self,
        all_open: list[dict[str, Any]],
        final_rate: float,
        stats: DiscoveryStats | None,
    ) -> None:
        self._running = False
        self._run_btn.configure(state="normal")
        msg = f"Smart scan complete — {len(all_open)} open endpoint(s) found"
        self._status_var.set(msg)
        self._log_msg(f"[*] {msg}\n")
        # Always show the breakpoint dialog (even with zero results)
        self._show_breakpoint_dialog(all_open, final_rate, stats)

    # ── Live feed ─────────────────────────────────────────────────────────────

    def _update_live_feed(self, result: ProbeResult, is_calib: bool) -> None:
        ts = time.strftime("%H:%M:%S")
        ep = result.endpoint
        status = result.status.upper()
        rtt = f"  rtt={result.rtt_ms:.1f}ms" if result.rtt_ms else ""
        kind = "CALIB" if is_calib else status
        line = f"[{ts}] {kind:<7} {ep.host}:{ep.port}{rtt}\n"

        if self._feed_count >= self._FEED_MAX:
            # Remove oldest line to keep the feed from growing unbounded
            self._live_feed.delete("1.0", "2.0")
        else:
            self._feed_count += 1
        self._live_feed.insert("end", line)
        self._live_feed.see("end")

    # ── UI update helpers ─────────────────────────────────────────────────────

    def _update_live(
        self, rate: float, rtt: float | None,
        open_c: int, total: int, dropped: int = 0,
    ) -> None:
        self._card_rate.configure(text=f"{rate:.0f}/s")
        self._card_rtt.configure(text=f"{rtt:.1f}ms" if rtt else "—")
        self._card_total.configure(text=str(total))
        self._card_dropped.configure(text=str(dropped))
        self._rate_history.append(rate)
        if len(self._rate_history) > 200:
            self._rate_history.pop(0)
        self._draw_rate_chart()

    def _log_msg(self, msg: str) -> None:
        self._log.insert("end", msg)
        self._log.see("end")

    def _draw_rate_chart(self) -> None:
        c = self._rate_canvas
        c.delete("all")
        w = c.winfo_width() or 500
        h = c.winfo_height() or 100
        data = self._rate_history[-w:]
        if not data or max(data) == 0:
            return
        max_v = max(data)
        pts: list[float] = []
        step = w / max(len(data) - 1, 1)
        for i, v in enumerate(data):
            x = i * step
            y = h - (v / max_v) * (h - 10) - 5
            pts.extend([x, y])
        if len(pts) >= 4:
            c.create_line(pts, fill=ACCENT, width=2, smooth=True)

    # ── Breakpoint handoff dialog ─────────────────────────────────────────────

    def _show_breakpoint_dialog(
        self,
        all_open: list[dict[str, Any]],
        final_rate: float,
        stats: DiscoveryStats | None,
    ) -> None:
        popup = ctk.CTkToplevel(self)
        popup.title("🔍 Smart Scan Complete — Results & Next Steps")
        popup.geometry("920x680")
        popup.resizable(True, True)
        popup.grab_set()

        unique_hosts = sorted({r["host"] for r in all_open})
        unique_ports = sorted({int(r["port"]) for r in all_open})
        rtt = stats.calibration_rtt_filtered_ms if stats else None
        t_level, t_desc = _recommend_timing(rtt)

        # ── Left: scan summary ────────────────────────────────────────────────
        left = ctk.CTkFrame(popup, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        left.pack(side="left", fill="both", expand=True, padx=(PAD, PAD_S), pady=PAD)

        ctk.CTkLabel(left, text="📊 Scan Results", font=FONT_H1, anchor="w").pack(
            fill="x", padx=PAD, pady=(PAD, PAD_S))

        def _stat(lbl: str, val: str) -> None:
            row = ctk.CTkFrame(left, fg_color="transparent")
            row.pack(fill="x", padx=PAD, pady=1)
            ctk.CTkLabel(row, text=lbl, font=FONT_SMALL, text_color=TEXT_MUTED, width=160, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=val, font=FONT_SMALL, anchor="w").pack(side="left")

        _stat("Open endpoints:", str(len(all_open)))
        _stat("Unique hosts:", str(len(unique_hosts)))
        _stat("Unique ports:", ", ".join(map(str, unique_ports[:12])) + ("…" if len(unique_ports) > 12 else "") or "—")
        _stat("Final scan rate:", f"{final_rate:.0f} probes/s")
        _stat("Filtered RTT:", f"{rtt:.1f} ms" if rtt else "—")

        ctk.CTkFrame(left, height=1, fg_color="#2a4a6a").pack(fill="x", padx=PAD, pady=PAD_S)

        ctk.CTkLabel(left, text="Recommended Nmap Timing:", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD)
        ctk.CTkLabel(left, text=f"  -{t_level}", font=FONT_H2, text_color=ACCENT, anchor="w").pack(
            fill="x", padx=PAD)
        ctk.CTkLabel(left, text=f"  {t_desc}", font=("Segoe UI", 9), text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=PAD, pady=(0, PAD_S))

        ctk.CTkFrame(left, height=1, fg_color="#2a4a6a").pack(fill="x", padx=PAD, pady=PAD_S)

        ctk.CTkLabel(left, text="Discovered hosts:", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD)
        hosts_box = ctk.CTkTextbox(left, font=FONT_MONO_SM, fg_color="#080e18", text_color="#88ddaa")
        hosts_box.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))
        hosts_box.insert("end", "\n".join(unique_hosts) if unique_hosts else "(none)")
        hosts_box.configure(state="disabled")

        # ── Right: nmap command builder ───────────────────────────────────────
        right = ctk.CTkFrame(popup, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        right.pack(side="right", fill="both", expand=True, padx=(PAD_S, PAD), pady=PAD)

        ctk.CTkLabel(right, text="🎯 Configure Nmap Follow-up", font=FONT_H1, anchor="w").pack(
            fill="x", padx=PAD, pady=(PAD, PAD_S))

        # Timing selector (pre-filled with recommendation)
        ctk.CTkLabel(right, text="Timing Template:", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD)
        timing_var = tk.StringVar(value=t_level)
        ctk.CTkSegmentedButton(
            right, values=["T1", "T2", "T3", "T4", "T5"], variable=timing_var,
        ).pack(fill="x", padx=PAD, pady=(0, PAD_S))

        # Scan type
        ctk.CTkLabel(right, text="Scan Type:", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD)
        scan_type_var = tk.StringVar(value=_HANDOFF_SCANS[0][0])
        ctk.CTkOptionMenu(
            right,
            values=[s[0] for s in _HANDOFF_SCANS],
            variable=scan_type_var,
        ).pack(fill="x", padx=PAD, pady=(0, PAD_S))

        # Target (editable)
        ctk.CTkLabel(right, text="Target:", font=FONT_SMALL, anchor="w").pack(fill="x", padx=PAD)
        target_var = tk.StringVar(value=self._target_var.get().strip())
        ctk.CTkEntry(right, textvariable=target_var, font=FONT_SMALL).pack(
            fill="x", padx=PAD, pady=(0, PAD_S))

        # Ports (editable, pre-filled from discovered ports)
        ctk.CTkLabel(right, text="Ports:", font=FONT_SMALL, anchor="w").pack(fill="x", padx=PAD)
        ports_default = (
            ",".join(map(str, unique_ports))
            if unique_ports
            else self._port_range_var.get()
        )
        ports_var = tk.StringVar(value=ports_default)
        ctk.CTkEntry(right, textvariable=ports_var, font=FONT_SMALL).pack(
            fill="x", padx=PAD, pady=(0, PAD_S))

        # Command preview
        ctk.CTkLabel(right, text="Command Preview:", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD)
        cmd_box = ctk.CTkTextbox(right, font=FONT_MONO_SM, fg_color="#080e18",
                                 text_color="#88ddaa", height=56)
        cmd_box.pack(fill="x", padx=PAD, pady=(0, PAD_S))

        _scan_map = dict(_HANDOFF_SCANS)
        cmd_holder: list[str] = [""]

        def _rebuild_cmd(*_: object) -> None:
            flags = _scan_map.get(scan_type_var.get(), "-sS -sV")
            t = timing_var.get()
            ports = ports_var.get().strip()
            target = target_var.get().strip()
            p_arg = f"-p {ports}" if ports else ""
            cmd = f"nmap -{t} {p_arg} {flags} {target}".strip()
            cmd_holder[0] = cmd
            cmd_box.configure(state="normal")
            cmd_box.delete("1.0", "end")
            cmd_box.insert("end", cmd)
            cmd_box.configure(state="disabled")

        for v in (timing_var, scan_type_var, target_var, ports_var):
            v.trace_add("write", _rebuild_cmd)
        _rebuild_cmd()

        # Action buttons ──────────────────────────────────────────────────────
        btn_row = ctk.CTkFrame(right, fg_color="transparent")
        btn_row.pack(fill="x", padx=PAD, pady=(PAD_S, PAD))

        def _run_nmap() -> None:
            if self._on_run_nmap and cmd_holder[0]:
                self._on_run_nmap(cmd_holder[0])
            popup.destroy()

        def _copy_cmd() -> None:
            self.clipboard_clear()
            self.clipboard_append(cmd_holder[0])

        def _view_dashboard() -> None:
            if all_open:
                self._on_hosts_discovered(all_open, final_rate)
            popup.destroy()

        ctk.CTkButton(
            btn_row, text="▶  Run Nmap Scan",
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER, command=_run_nmap,
        ).pack(fill="x", pady=(0, PAD_S))
        ctk.CTkButton(
            btn_row, text="📊  View Results on Dashboard",
            fg_color="#1a3a5a", hover_color="#2a4a6a",
            corner_radius=BTN_CORNER, command=_view_dashboard,
        ).pack(fill="x", pady=(0, PAD_S))
        ctk.CTkButton(
            btn_row, text="📋  Copy Command",
            fg_color="#1a2a2a", hover_color="#2a4a3a",
            corner_radius=BTN_CORNER, command=_copy_cmd,
        ).pack(fill="x", pady=(0, PAD_S))

        # Export buttons ──────────────────────────────────────────────────────
        export_row = ctk.CTkFrame(btn_row, fg_color="transparent")
        export_row.pack(fill="x", pady=(0, PAD_S))

        def _export_json() -> None:
            import json as _json
            import tkinter.filedialog as _fd
            path = _fd.asksaveasfilename(
                title="Export results as JSON",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            )
            if not path:
                return
            data = {
                "target": self._target_var.get().strip(),
                "timing_recommendation": t_level,
                "open_endpoints": all_open,
                "stats": {
                    "open": len(all_open),
                    "unique_hosts": len(unique_hosts),
                    "final_rate_pps": round(final_rate, 2),
                    "rtt_ms": round(rtt, 2) if rtt else None,
                },
            }
            try:
                with open(path, "w") as f:
                    _json.dump(data, f, indent=2)
            except OSError as exc:
                import tkinter.messagebox as _mb
                _mb.showerror("Export Failed", str(exc))

        def _export_csv() -> None:
            import csv
            import tkinter.filedialog as _fd
            path = _fd.asksaveasfilename(
                title="Export results as CSV",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            )
            if not path:
                return
            try:
                with open(path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["host", "port"])
                    writer.writeheader()
                    writer.writerows(all_open)
            except OSError as exc:
                import tkinter.messagebox as _mb
                _mb.showerror("Export Failed", str(exc))

        ctk.CTkButton(
            export_row, text="💾  Export JSON",
            fg_color="#1a3a2a", hover_color="#2a5a3a",
            corner_radius=BTN_CORNER, command=_export_json,
        ).pack(side="left", fill="x", expand=True, padx=(0, PAD_S))
        ctk.CTkButton(
            export_row, text="📄  Export CSV",
            fg_color="#1a3a2a", hover_color="#2a5a3a",
            corner_radius=BTN_CORNER, command=_export_csv,
        ).pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            btn_row, text="Close",
            fg_color="transparent", hover_color="#2a2a3a",
            corner_radius=BTN_CORNER, command=popup.destroy,
        ).pack(fill="x")

"""
Smart Scan panel – UI for configuring and running the adaptive discovery
algorithm described in the paper (PID+AIMD rate controller).

The panel feeds configuration into SmartScanModule and streams results back
to the dashboard host table.
"""
from __future__ import annotations

import asyncio
import threading
import tkinter as tk
from typing import Any, Callable

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, BG_CARD, BG_SECONDARY, BTN_CORNER, CARD_CORNER,
    FONT_BODY, FONT_H1, FONT_H2, FONT_MONO_SM, FONT_SMALL, PAD, PAD_S,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SUCCESS, TEXT_WARN,
)
from redscan.models import DiscoveryConfig, Endpoint
from redscan.smart_scan import SmartScanModule


class _LabeledSlider(ctk.CTkFrame):
    """A label + slider + numeric readout widget."""

    def __init__(
        self,
        master: ctk.CTkFrame,
        label: str,
        from_: float,
        to: float,
        default: float,
        fmt: str = "{:.3f}",
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
            self,
            from_=from_,
            to=to,
            variable=self._var,
            progress_color=ACCENT,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

    def _update_readout(self, *_: object) -> None:
        self._readout.configure(text=self._fmt.format(self._var.get()))

    @property
    def value(self) -> float:
        return self._var.get()


class SmartScanView(ctk.CTkFrame):
    """
    Smart Scan configuration panel and results viewer.

    The algorithm panel exposes all PID/AIMD parameters from the paper.
    Running a scan executes SmartScanModule in a background thread/asyncio loop
    and posts progress back via after() polling.
    """

    def __init__(
        self,
        master: ctk.CTk | ctk.CTkFrame,
        on_hosts_discovered: Callable[[list[dict[str, int | str]], float], None],
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._on_hosts_discovered = on_hosts_discovered
        self._running = False
        self._result_lines: list[str] = []

        self._build()

    # ── Build ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        ctk.CTkLabel(self, text="Smart Scan (Adaptive PID+AIMD)", font=FONT_H1, anchor="w").pack(
            fill="x", padx=PAD, pady=(PAD, PAD_S)
        )
        ctk.CTkLabel(
            self,
            text=(
                "Automatically calibrates probe rate using RTT feedback. "
                "Configure the algorithm parameters below, then start the adaptive discovery."
            ),
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            wraplength=900,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=PAD, pady=(0, PAD))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=PAD)
        body.columnconfigure(0, weight=1, minsize=340)
        body.columnconfigure(1, weight=2)

        # ── Left: config form ────────────────────────────────────────────────
        cfg_frame = ctk.CTkScrollableFrame(
            body, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER,
            label_text="Algorithm Parameters",
        )
        cfg_frame.grid(row=0, column=0, sticky="nsew", padx=(0, PAD_S))

        # Target
        self._target_var = tk.StringVar(value="192.168.1.0/24")
        self._calib_host_var = tk.StringVar(value="8.8.8.8")
        self._calib_port_var = tk.IntVar(value=53)
        self._port_range_var = tk.StringVar(value="22,80,443,8080")

        self._add_entry(cfg_frame, "Target(s) (CIDR / comma list):", self._target_var)
        self._add_entry(cfg_frame, "Calibration Host:", self._calib_host_var)
        self._add_int_entry(cfg_frame, "Calibration Port:", self._calib_port_var)
        self._add_entry(cfg_frame, "Ports to probe (comma list):", self._port_range_var)

        sep = ctk.CTkFrame(cfg_frame, height=1, fg_color="#2a4a6a")
        sep.pack(fill="x", pady=PAD)

        ctk.CTkLabel(cfg_frame, text="Rate Controller", font=FONT_H2, anchor="w").pack(fill="x", padx=PAD_S)

        self._s_r_min   = _LabeledSlider(cfg_frame, "R_min (probes/s)",  1,   200,  10,   "{:.0f}")
        self._s_r_max   = _LabeledSlider(cfg_frame, "R_max (probes/s)", 10, 2000, 500,   "{:.0f}")
        self._s_r_init  = _LabeledSlider(cfg_frame, "Initial Rate",      1,  500, 120,   "{:.0f}")
        self._s_alpha   = _LabeledSlider(cfg_frame, "EWMA α (smoothing)", 0.01, 0.99, 0.2)
        self._s_delta   = _LabeledSlider(cfg_frame, "δ RTT target margin (ms)", 0, 20, 3, "{:.1f}")
        self._s_kp      = _LabeledSlider(cfg_frame, "Kp (proportional gain)",  0, 0.5, 0.04)
        self._s_ki      = _LabeledSlider(cfg_frame, "Ki (integral gain)",      0, 0.1, 0.008)
        self._s_kd      = _LabeledSlider(cfg_frame, "Kd (derivative gain)",    0, 0.1, 0.01)
        self._s_beta    = _LabeledSlider(cfg_frame, "β AIMD backoff factor",   0.1, 0.95, 0.5)
        self._s_loss_w  = _LabeledSlider(cfg_frame, "Loss window (s)",         0.5, 30, 2, "{:.1f}")
        self._s_loss_thr= _LabeledSlider(cfg_frame, "Loss threshold (count)",  1, 50, 5,  "{:.0f}")
        self._s_timeout = _LabeledSlider(cfg_frame, "Connect timeout (s)",     0.05, 5, 0.5)
        self._s_calib_n = _LabeledSlider(cfg_frame, "Calibration ratio N",     1, 512, 64, "{:.0f}")

        for sl in [
            self._s_r_min, self._s_r_max, self._s_r_init,
            self._s_alpha, self._s_delta,
            self._s_kp, self._s_ki, self._s_kd, self._s_beta,
            self._s_loss_w, self._s_loss_thr, self._s_timeout, self._s_calib_n,
        ]:
            sl.pack(fill="x", padx=PAD_S, pady=1)

        # Run button
        self._run_btn = ctk.CTkButton(
            cfg_frame,
            text="⚡  Start Smart Scan",
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER,
            command=self._start_scan,
        )
        self._run_btn.pack(fill="x", padx=PAD_S, pady=PAD)

        ctk.CTkButton(
            cfg_frame,
            text="⏹  Stop",
            fg_color="#4a1a1a",
            hover_color="#6a2a2a",
            corner_radius=BTN_CORNER,
            command=self._stop_scan,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD))

        # ── Right: live output ────────────────────────────────────────────────
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)

        # Status cards row
        cards = ctk.CTkFrame(right, fg_color="transparent")
        cards.grid(row=0, column=0, sticky="ew")

        self._card_rate    = self._stat_card(cards, "Current Rate", "—")
        self._card_rtt     = self._stat_card(cards, "Filtered RTT", "—")
        self._card_open    = self._stat_card(cards, "Open Ports", "0")
        self._card_total   = self._stat_card(cards, "Probes Sent", "0")
        self._card_dropped = self._stat_card(cards, "Timeouts", "0")

        # Rate mini-chart (canvas based)
        chart_frame = ctk.CTkFrame(right, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        chart_frame.grid(row=1, column=0, sticky="nsew", pady=(PAD, PAD_S))
        ctk.CTkLabel(chart_frame, text="Rate History", font=FONT_H2, anchor="w").pack(
            padx=PAD, pady=PAD_S, anchor="w"
        )
        self._rate_canvas = tk.Canvas(chart_frame, bg="#0a1220", height=120, highlightthickness=0)
        self._rate_canvas.pack(fill="both", expand=True, padx=PAD_S, pady=(0, PAD_S))
        self._rate_history: list[float] = []

        # Results log
        log_frame = ctk.CTkFrame(right, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        log_frame.grid(row=2, column=0, sticky="nsew")
        log_frame.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(log_frame, text="Discovery Log", font=FONT_H2, anchor="w").grid(
            row=0, column=0, padx=PAD, pady=PAD_S, sticky="w"
        )
        self._log = ctk.CTkTextbox(
            log_frame, font=FONT_MONO_SM, fg_color="#080e18", text_color="#88ddaa"
        )
        self._log.grid(row=1, column=0, sticky="nsew", padx=PAD_S, pady=(0, PAD_S))

        self._status_var = tk.StringVar(value="Idle")
        ctk.CTkLabel(self, textvariable=self._status_var, font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=PAD, pady=(0, PAD)
        )

    def _add_entry(self, parent: ctk.CTkFrame, label: str, var: tk.StringVar) -> None:
        ctk.CTkLabel(parent, text=label, font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD_S, pady=(PAD_S, 0)
        )
        ctk.CTkEntry(parent, textvariable=var, font=FONT_SMALL).pack(
            fill="x", padx=PAD_S, pady=(0, PAD_S)
        )

    def _add_int_entry(self, parent: ctk.CTkFrame, label: str, var: tk.IntVar) -> None:
        ctk.CTkLabel(parent, text=label, font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD_S, pady=(PAD_S, 0)
        )
        ctk.CTkEntry(parent, textvariable=var, font=FONT_SMALL).pack(
            fill="x", padx=PAD_S, pady=(0, PAD_S)
        )

    def _stat_card(self, parent: ctk.CTkFrame, label: str, value: str) -> ctk.CTkLabel:
        box = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8)
        box.pack(side="left", padx=PAD_S, pady=PAD_S)
        ctk.CTkLabel(box, text=label, font=FONT_SMALL, text_color=TEXT_MUTED).pack(padx=PAD, pady=(PAD_S, 0))
        lbl = ctk.CTkLabel(box, text=value, font=FONT_H1, text_color=TEXT_SUCCESS)
        lbl.pack(padx=PAD, pady=(0, PAD_S))
        return lbl

    # ── Scan execution ────────────────────────────────────────────────────────

    def _build_config(self) -> DiscoveryConfig:
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
        )

    def _parse_targets(self) -> list[Endpoint]:
        raw = self._target_var.get().strip()
        port_str = self._port_range_var.get().strip()
        ports = [int(p) for p in port_str.split(",") if p.strip().isdigit()]
        if not ports:
            ports = [80]

        # Maximum addressable IPs: /16 = 65534 hosts × ports.  Anything larger
        # (e.g. a /8) would create millions of Endpoint objects and crash the
        # process before the first probe is sent.
        _MAX_HOSTS = 65_534

        hosts: list[str] = []
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                import ipaddress
                try:
                    net = ipaddress.ip_network(token, strict=False)
                    host_list = list(net.hosts())
                    if len(host_list) > _MAX_HOSTS:
                        self._log_msg(
                            f"[!] CIDR {token} expands to {len(host_list):,} hosts "
                            f"(limit {_MAX_HOSTS:,}).  "
                            "Use a /16 or smaller prefix.\n"
                        )
                        continue
                    hosts.extend(str(ip) for ip in host_list)
                except ValueError:
                    hosts.append(token)
            else:
                hosts.append(token)

        return [Endpoint(host=h, port=p) for h in hosts for p in ports]

    def _start_scan(self) -> None:
        if self._running:
            return
        self._running = True
        self._run_btn.configure(state="disabled")
        self._rate_history.clear()
        self._log.delete("1.0", "end")
        self._status_var.set("Smart scan running…")
        cfg = self._build_config()
        endpoints = self._parse_targets()
        self._log_msg(f"[*] Probing {len(endpoints)} endpoints with adaptive rate control\n")
        threading.Thread(target=self._scan_thread, args=(cfg, endpoints), daemon=True).start()

    def _scan_thread(self, cfg: DiscoveryConfig, endpoints: list[Endpoint]) -> None:
        module = SmartScanModule(cfg)
        loop = asyncio.new_event_loop()

        # Mutable containers shared between _run() closure and the outer scope.
        all_open: list[dict[str, Any]] = []
        final_rate_box: list[float] = [cfg.initial_rate]

        async def _run() -> None:
            # Use the public discovery_pass to scan all endpoints, then stream
            # per-result feedback by slicing into small batches.
            batch_size = 20
            open_count = 0
            total = 0
            total_dropped = 0
            for i in range(0, len(endpoints), batch_size):
                if not self._running:
                    break
                batch = endpoints[i : i + batch_size]
                output = await module.discovery_pass(batch)
                total += output.stats.total_count
                total_dropped += output.stats.timeout_count
                for ep in output.open_endpoints:
                    open_count += 1
                    all_open.append({"host": ep.host, "port": ep.port})
                    rtt_result = next(
                        (r for r in output.all_results if r.endpoint == ep and r.rtt_ms), None
                    )
                    rtt_str = f"{rtt_result.rtt_ms:.1f}ms" if rtt_result and rtt_result.rtt_ms else "—"
                    self.after(
                        0, self._log_msg,
                        f"[+] OPEN  {ep.host}:{ep.port}  rtt={rtt_str}\n",
                    )
                final_rate_box[0] = output.stats.final_rate
                self.after(
                    0, self._update_live,
                    output.stats.final_rate,
                    output.stats.calibration_rtt_filtered_ms,
                    open_count,
                    total,
                    total_dropped,
                )
                self.after(0, self._card_open.configure, {"text": str(open_count)})

        try:
            loop.run_until_complete(_run())
        finally:
            loop.close()
            self.after(0, self._scan_done, all_open, final_rate_box[0])

    def _stop_scan(self) -> None:
        self._running = False

    def _scan_done(self, all_open: list[dict[str, Any]], final_rate: float) -> None:
        self._running = False
        self._run_btn.configure(state="normal")
        msg = f"Smart scan complete — {len(all_open)} open endpoint(s) found"
        self._status_var.set(msg)
        self._log_msg(f"[*] {msg}\n")
        if all_open:
            self._on_hosts_discovered(all_open, final_rate)

    # ── UI update helpers ─────────────────────────────────────────────────────

    def _update_live(self, rate: float, rtt: float | None, open_c: int, total: int, dropped: int = 0) -> None:
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
        h = c.winfo_height() or 120
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

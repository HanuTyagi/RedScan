from __future__ import annotations

import asyncio
import contextlib
import os
import socket as _socket
import subprocess
import time
from collections import deque
from typing import Callable

from .models import DiscoveryConfig, DiscoveryOutput, DiscoveryStats, Endpoint, ProbeResult


class AdaptiveRateController:
    def __init__(self, cfg: DiscoveryConfig) -> None:
        self.cfg = cfg
        self.rate = cfg.initial_rate
        self._e_prev = 0.0
        self._e_prev2 = 0.0
        self._rtt_filtered: float | None = None
        self._rtt_base: float | None = None
        self._timeout_events: deque[float] = deque()
        # Warm-up counter: RTT_base is not locked in until this many calibration
        # samples have been collected.  Using the very first (often elevated)
        # sample as the baseline would set RTT_target too high and allow the
        # scanner to run faster than safe before meaningful data is available.
        self._warmup_count: int = 0

    def calibration_update(self, rtt_ms: float) -> None:
        if self._rtt_filtered is None:
            self._rtt_filtered = rtt_ms
        else:
            self._rtt_filtered = (1 - self.cfg.ewma_alpha) * self._rtt_filtered + self.cfg.ewma_alpha * rtt_ms

        self._warmup_count += 1
        if self._warmup_count >= self.cfg.rtt_base_warmup_samples:
            # Only update RTT_base after the warm-up period so the first noisy
            # samples (e.g. ARP resolution latency) do not inflate the baseline.
            if self._rtt_base is None:
                self._rtt_base = self._rtt_filtered
            else:
                self._rtt_base = min(self._rtt_base, self._rtt_filtered)

    def register_timeout(self) -> None:
        """Record a calibration-probe timeout as a potential loss event.

        This must only be called for *calibration* probe timeouts, not for
        timeouts against target hosts (which may legitimately be filtered or
        offline).  Callers are responsible for enforcing this distinction.
        """
        now = time.monotonic()
        self._timeout_events.append(now)
        self._prune_timeout_events(now)

    def _prune_timeout_events(self, now: float) -> None:
        while self._timeout_events and (now - self._timeout_events[0]) > self.cfg.loss_window_s:
            self._timeout_events.popleft()

    def control_update(self) -> None:
        if self._rtt_filtered is None or self._rtt_base is None:
            return

        now = time.monotonic()
        self._prune_timeout_events(now)

        # ── Loss event: AIMD backoff takes precedence over PID this step ──────
        # Applying both simultaneously would double-penalise the rate.  The
        # paper specifies that PID error history is reset after backoff to
        # prevent a derivative kick on the following step.
        if len(self._timeout_events) >= self.cfg.loss_threshold:
            self.rate = max(self.cfg.r_min, self.cfg.aimd_beta * self.rate)
            self._timeout_events.clear()
            # Reset stored error history to prevent derivative kick
            self._e_prev = 0.0
            self._e_prev2 = 0.0
            return

        # ── Continuous PID update (incremental / velocity form) ───────────────
        rtt_target = self._rtt_base + self.cfg.target_delta_ms
        e_t = rtt_target - self._rtt_filtered
        delta_u = (
            self.cfg.kp * (e_t - self._e_prev)
            + self.cfg.ki * e_t
            + self.cfg.kd * (e_t - 2 * self._e_prev + self._e_prev2)
        )

        self.rate = max(self.cfg.r_min, min(self.cfg.r_max, self.rate + delta_u))

        self._e_prev2 = self._e_prev
        self._e_prev = e_t

    @property
    def filtered_rtt_ms(self) -> float | None:
        return self._rtt_filtered

    @property
    def base_rtt_ms(self) -> float | None:
        return self._rtt_base


class SmartScanModule:
    # Convert rate units into an upper bound for concurrent in-flight probes.
    _CONCURRENCY_SCALING_FACTOR = 10

    def __init__(self, cfg: DiscoveryConfig | None = None) -> None:
        self.cfg = cfg or DiscoveryConfig()
        self.controller = AdaptiveRateController(self.cfg)

    async def _probe(self, endpoint: Endpoint) -> ProbeResult:
        """Dispatch to the probe implementation selected by cfg.probe_type."""
        pt = self.cfg.probe_type
        if pt == "udp":
            return await self._probe_udp(endpoint)
        if pt == "icmp":
            return await self._probe_icmp(endpoint)
        if pt == "tcp_syn":
            # TCP SYN half-open scan requires raw sockets (root).
            # Fall back to tcp_connect if the caller is unprivileged.
            try:
                if os.geteuid() != 0:
                    return await self._probe_tcp_connect(endpoint)
            except AttributeError:
                pass  # Windows — getuid unavailable; attempt raw probe
            # Raw SYN not implemented without scapy; use tcp_connect.
            return await self._probe_tcp_connect(endpoint)
        return await self._probe_tcp_connect(endpoint)

    # ── Probe implementations ─────────────────────────────────────────────────

    async def _probe_tcp_connect(self, endpoint: Endpoint) -> ProbeResult:
        """Standard full-handshake TCP connect probe (works without root)."""
        start = time.perf_counter()
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(endpoint.host, endpoint.port),
                timeout=self.cfg.connect_timeout_s,
            )
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
        except asyncio.TimeoutError:
            # Do NOT call register_timeout() here.  Target hosts may legitimately
            # be filtered or offline, so their timeouts are not a path-impairment
            # signal.  Only calibration-probe timeouts should feed the loss-event
            # counter; that decision is made in discovery_pass() where the caller
            # knows whether this probe is a calibration probe.
            return ProbeResult(endpoint=endpoint, status="timeout")
        except (ConnectionRefusedError, OSError):
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)
        except Exception as exc:  # pragma: no cover
            return ProbeResult(endpoint=endpoint, status="error", error=str(exc))
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def _probe_udp(self, endpoint: Endpoint) -> ProbeResult:
        """UDP probe: sends a short datagram and waits for a reply or ICMP error."""
        loop = asyncio.get_event_loop()
        try:
            result: ProbeResult = await asyncio.wait_for(
                loop.run_in_executor(None, self._udp_probe_sync, endpoint),
                timeout=self.cfg.connect_timeout_s + 1.0,
            )
            return result
        except asyncio.TimeoutError:
            return ProbeResult(endpoint=endpoint, status="timeout")

    def _udp_probe_sync(self, endpoint: Endpoint) -> ProbeResult:
        start = time.perf_counter()
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(self.cfg.connect_timeout_s)
        try:
            sock.connect((endpoint.host, endpoint.port))
            sock.send(b"\x00" * 4)
            try:
                sock.recv(64)
                rtt_ms = (time.perf_counter() - start) * 1000.0
                return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
            except _socket.timeout:
                # No ICMP port-unreachable within timeout → open|filtered.
                rtt_ms = (time.perf_counter() - start) * 1000.0
                return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
        except ConnectionRefusedError:
            # ICMP port-unreachable received → port closed.
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)
        except _socket.error as exc:
            return ProbeResult(endpoint=endpoint, status="error", error=str(exc))
        finally:
            sock.close()

    async def _probe_icmp(self, endpoint: Endpoint) -> ProbeResult:
        """ICMP echo probe: uses subprocess ping (works without scapy)."""
        loop = asyncio.get_event_loop()
        try:
            result: ProbeResult = await asyncio.wait_for(
                loop.run_in_executor(None, self._icmp_probe_sync, endpoint),
                timeout=self.cfg.connect_timeout_s * 4 + 2.0,
            )
            return result
        except asyncio.TimeoutError:
            return ProbeResult(endpoint=endpoint, status="timeout")

    def _icmp_probe_sync(self, endpoint: Endpoint) -> ProbeResult:
        start = time.perf_counter()
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", "1000", endpoint.host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", endpoint.host]
            res = subprocess.run(cmd, capture_output=True, timeout=5)
            rtt_ms = (time.perf_counter() - start) * 1000.0
            if res.returncode == 0:
                return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
            return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)
        except Exception as exc:
            return ProbeResult(endpoint=endpoint, status="error", error=str(exc))

    # ── Scan pass ─────────────────────────────────────────────────────────────

    async def discovery_pass(
        self,
        endpoints: list[Endpoint],
        per_probe_callback: Callable[[ProbeResult, bool], None] | None = None,
    ) -> DiscoveryOutput:
        if not endpoints:
            return DiscoveryOutput(
                open_endpoints=[],
                all_results=[],
                stats=DiscoveryStats(total_count=0, final_rate=self.controller.rate),
            )

        # ── Pre-flight: warn if calibration endpoint is unreachable ──────────
        # A single quick probe on startup prevents a silent failure where the
        # controller never receives any calibration RTT samples and stays at
        # initial_rate for the entire scan.
        calib_test = await self._probe(
            Endpoint(host=self.cfg.calibration_host, port=self.cfg.calibration_port)
        )
        # We don't abort on failure — some calibration endpoints respond with
        # RST (status="closed") which still gives a valid RTT.  Only a true
        # timeout with no RTT suggests the path is broken.
        if calib_test.status == "timeout" and calib_test.rtt_ms is None:
            import warnings
            warnings.warn(
                f"Calibration endpoint {self.cfg.calibration_host}:{self.cfg.calibration_port} "
                "is unreachable (timeout).  The rate controller will have no RTT signal; "
                "the scan rate will remain fixed at initial_rate.",
                RuntimeWarning,
                stacklevel=2,
            )
        elif calib_test.rtt_ms is not None:
            # Seed the EWMA with this first real sample so the controller starts
            # with a meaningful baseline instead of waking up blind.
            self.controller.calibration_update(calib_test.rtt_ms)

        results: list[ProbeResult] = []
        queue = deque(endpoints)
        in_flight: dict[asyncio.Task[ProbeResult], bool] = {}
        calibration_counter = 0
        last_control = time.monotonic()

        while queue or in_flight:
            while queue and len(in_flight) < max(1, int(self.controller.rate // self._CONCURRENCY_SCALING_FACTOR)):
                endpoint = queue.popleft()
                in_flight[asyncio.create_task(self._probe(endpoint))] = False
                calibration_counter += 1

                if calibration_counter % self.cfg.calibration_ratio == 0:
                    calib_ep = Endpoint(host=self.cfg.calibration_host, port=self.cfg.calibration_port)
                    in_flight[asyncio.create_task(self._probe(calib_ep))] = True

                await asyncio.sleep(max(0.0, 1.0 / max(self.controller.rate, 1.0)))

            if in_flight:
                done, pending = await asyncio.wait(
                    set(in_flight),
                    timeout=0.05,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    result = task.result()
                    is_calibration_task = in_flight.pop(task, False)
                    if per_probe_callback is not None:
                        per_probe_callback(result, is_calibration_task)
                    if is_calibration_task:
                        if result.status in ("open", "closed") and result.rtt_ms is not None:
                            # Accept RST (closed) replies as valid RTT samples.  Some
                            # calibration endpoints sit behind a firewall that returns
                            # an immediate RST instead of a SYN-ACK, but the round-trip
                            # time is still a valid congestion signal.
                            self.controller.calibration_update(result.rtt_ms)
                        elif result.status == "timeout":
                            # Only calibration-probe timeouts are a reliable
                            # congestion signal — register them as loss events.
                            self.controller.register_timeout()
                    else:
                        results.append(result)
                pending_map = {task: in_flight[task] for task in pending}
                in_flight.clear()
                in_flight.update(pending_map)

            now = time.monotonic()
            if now - last_control >= self.cfg.control_interval_s:
                self.controller.control_update()
                last_control = now

        open_eps = [r.endpoint for r in results if r.status == "open"]
        stats = DiscoveryStats(
            open_count=sum(1 for r in results if r.status == "open"),
            timeout_count=sum(1 for r in results if r.status == "timeout"),
            closed_count=sum(1 for r in results if r.status == "closed"),
            error_count=sum(1 for r in results if r.status == "error"),
            total_count=len(results),
            final_rate=self.controller.rate,
            calibration_rtt_base_ms=self.controller.base_rtt_ms,
            calibration_rtt_filtered_ms=self.controller.filtered_rtt_ms,
        )
        return DiscoveryOutput(open_endpoints=open_eps, all_results=results, stats=stats)

    async def deep_enumeration_handoff(self, discovery: DiscoveryOutput) -> dict[str, list[int]]:
        handoff: dict[str, list[int]] = {}
        for ep in discovery.open_endpoints:
            handoff.setdefault(ep.host, []).append(ep.port)
        for host in handoff:
            handoff[host].sort()
        return handoff

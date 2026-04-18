from __future__ import annotations

import asyncio
import contextlib
import time
from collections import deque

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

    def calibration_update(self, rtt_ms: float) -> None:
        if self._rtt_filtered is None:
            self._rtt_filtered = rtt_ms
        else:
            self._rtt_filtered = (1 - self.cfg.ewma_alpha) * self._rtt_filtered + self.cfg.ewma_alpha * rtt_ms

        if self._rtt_base is None:
            self._rtt_base = self._rtt_filtered
        else:
            self._rtt_base = min(self._rtt_base, self._rtt_filtered)

    def register_timeout(self) -> None:
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

        rtt_target = self._rtt_base + self.cfg.target_delta_ms
        e_t = rtt_target - self._rtt_filtered
        delta_u = (
            self.cfg.kp * (e_t - self._e_prev)
            + self.cfg.ki * e_t
            + self.cfg.kd * (e_t - 2 * self._e_prev + self._e_prev2)
        )

        self.rate = max(self.cfg.r_min, min(self.cfg.r_max, self.rate + delta_u))

        if len(self._timeout_events) >= self.cfg.loss_threshold:
            self.rate = max(self.cfg.r_min, self.cfg.aimd_beta * self.rate)
            self._timeout_events.clear()

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
    _RATE_TO_CONCURRENCY_DIVISOR = 10

    def __init__(self, cfg: DiscoveryConfig | None = None) -> None:
        self.cfg = cfg or DiscoveryConfig()
        self.controller = AdaptiveRateController(self.cfg)

    async def _probe(self, endpoint: Endpoint) -> ProbeResult:
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
            self.controller.register_timeout()
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

    async def discovery_pass(self, endpoints: list[Endpoint]) -> DiscoveryOutput:
        if not endpoints:
            return DiscoveryOutput(
                open_endpoints=[],
                all_results=[],
                stats=DiscoveryStats(total_count=0, final_rate=self.controller.rate),
            )

        results: list[ProbeResult] = []
        queue = deque(endpoints)
        in_flight: dict[asyncio.Task[ProbeResult], bool] = {}
        calibration_counter = 0
        last_control = time.monotonic()

        while queue or in_flight:
            while queue and len(in_flight) < max(1, int(self.controller.rate // self._RATE_TO_CONCURRENCY_DIVISOR)):
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
                    if is_calibration_task and result.status == "open" and result.rtt_ms is not None:
                        self.controller.calibration_update(result.rtt_ms)
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

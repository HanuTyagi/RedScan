from __future__ import annotations

import json
import os
import time
from collections.abc import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse

from .history import ScanHistoryStore
from .models import ScanHistoryEntry, ScanRequest, ScanResponse
from .orchestrator import RedScanOrchestrator

app = FastAPI(title="RedScan", version="2.0.0")

# Module-level history store (file-backed, thread-safe).
_history_store = ScanHistoryStore()

# ── Optional API key auth ─────────────────────────────────────────────────────
# Set the REDSCAN_API_KEY environment variable to enable.  When the variable is
# absent every request is permitted (suitable for local use).

_API_KEY_ENV = "REDSCAN_API_KEY"


def _require_api_key(request: Request) -> None:
    required = os.environ.get(_API_KEY_ENV)
    if not required:
        return  # Auth not configured — allow all
    if request.headers.get("X-API-Key", "") != required:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


# ── Simple per-IP rate limiter ────────────────────────────────────────────────
# Set REDSCAN_RATE_LIMIT to the maximum number of scan requests per client per
# minute.  Set to 0 to disable.  Defaults to 10.
#
# The limit is re-read from the environment on every call so that operators can
# reconfigure it without restarting the server (e.g. via a process supervisor
# that updates the environment).  Previously it was evaluated once at import
# time, making runtime changes impossible.

_RATE_LIMIT_WINDOW_S = 60.0
# _rate_buckets maps client IP -> list of request timestamps within the window.
# Using a plain dict (not defaultdict) so we can delete empty entries and
# prevent the mapping from growing unboundedly across unique client IPs.
_rate_buckets: dict[str, list[float]] = {}


def _check_rate_limit(request: Request) -> None:
    # Read the limit fresh on every call so environment changes take effect
    # without a restart.
    rate_limit_max = int(os.environ.get("REDSCAN_RATE_LIMIT", "10"))
    if rate_limit_max <= 0:
        return  # Disabled
    # Prefer X-Forwarded-For so deployments behind a reverse proxy use the real
    # client IP rather than the proxy's address.  Take only the first (leftmost)
    # value which represents the originating client.
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        client_ip = (request.client.host if request.client else "unknown")
    now = time.monotonic()
    window_start = now - _RATE_LIMIT_WINDOW_S
    times = _rate_buckets.get(client_ip, [])
    # Prune entries outside the rolling window
    while times and times[0] < window_start:
        times.pop(0)
    if len(times) >= rate_limit_max:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {rate_limit_max} requests per {int(_RATE_LIMIT_WINDOW_S)}s",
        )
    times.append(now)
    # Store back (handles both new and existing clients) or discard if now empty.
    if times:
        _rate_buckets[client_ip] = times
    elif client_ip in _rate_buckets:
        # Bucket became empty after pruning and before the new entry – clean up.
        del _rate_buckets[client_ip]


# Shared dependency list applied to all mutating endpoints.
_guards = [Depends(_require_api_key), Depends(_check_rate_limit)]


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse, dependencies=_guards)
async def scan(request: ScanRequest) -> ScanResponse:
    # Create a fresh orchestrator per request so concurrent calls don't share
    # controller state or mutate in-flight SmartScanModule instances.
    orchestrator = RedScanOrchestrator()
    response = await orchestrator.run(request)
    _history_store.record(request, response)
    return response


@app.get("/history", response_model=list[ScanHistoryEntry], dependencies=[Depends(_require_api_key)])
async def get_history(limit: int = 50) -> list[ScanHistoryEntry]:
    """Return the most recent scan history entries (newest-last)."""
    return _history_store.list_entries(limit=min(limit, 200))


@app.delete("/history", dependencies=_guards)
async def clear_history() -> dict[str, str]:
    """Delete all persisted scan history."""
    _history_store.clear()
    return {"status": "cleared"}


@app.post("/scan/stream", dependencies=_guards)
async def scan_stream(request: ScanRequest) -> StreamingResponse:
    """
    True streaming endpoint: yields one NDJSON line per discovered open port
    as the adaptive controller processes batches, then a final summary line.

    Line schemas:
      {"type": "open",  "host": "…", "port": N, "rtt_ms": …}
      {"type": "stats", "total": N, "open": N, "timeout": N, "rate": …}
      {"type": "done",  "command": "nmap …"}
    """
    async def event_stream() -> AsyncIterator[bytes]:
        from .models import Endpoint
        from .smart_scan import SmartScanModule

        orchestrator = RedScanOrchestrator()
        cfg = orchestrator.smart_scan.cfg.model_copy(
            update={
                "calibration_host": request.calibration_endpoint.host,
                "calibration_port": request.calibration_endpoint.port,
            }
        )
        module = SmartScanModule(cfg)

        endpoints = [Endpoint(host=h, port=p) for h in request.target_hosts for p in request.ports]

        batch_size = 50
        cumulative_open = 0
        cumulative_total = 0
        cumulative_timeout = 0

        for i in range(0, len(endpoints), batch_size):
            batch = endpoints[i : i + batch_size]
            output = await module.discovery_pass(batch)
            cumulative_total += output.stats.total_count
            cumulative_timeout += output.stats.timeout_count

            for ep in output.open_endpoints:
                cumulative_open += 1
                rtt_result = next(
                    (r for r in output.all_results if r.endpoint == ep and r.rtt_ms), None
                )
                yield (json.dumps({
                    "type": "open",
                    "host": ep.host,
                    "port": ep.port,
                    "rtt_ms": rtt_result.rtt_ms if rtt_result else None,
                }) + "\n").encode()

            yield (json.dumps({
                "type": "stats",
                "total": cumulative_total,
                "open": cumulative_open,
                "timeout": cumulative_timeout,
                "rate": output.stats.final_rate,
            }) + "\n").encode()

        # Final enumeration command
        preset = orchestrator.presets.resolve_conflicts(orchestrator.presets.get(request.preset_key))
        from .models import CommandBuildRequest as CBR
        enumeration_target = request.target_hosts[0] if request.target_hosts else ""
        cmd = orchestrator.factory.build(CBR(
            target=enumeration_target, preset=preset, ports=request.ports, timing="-T4"
        )) if enumeration_target else None

        yield (json.dumps({
            "type": "done",
            "command": cmd.command_str if cmd else "",
        }) + "\n").encode()

    return StreamingResponse(event_stream(), media_type="application/x-ndjson")

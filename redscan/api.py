from __future__ import annotations

import json
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from .models import ScanRequest, ScanResponse
from .orchestrator import RedScanOrchestrator

app = FastAPI(title="RedScan", version="2.0.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    # Create a fresh orchestrator per request so concurrent calls don't share
    # controller state or mutate in-flight SmartScanModule instances.
    orchestrator = RedScanOrchestrator()
    return await orchestrator.run(request)


@app.post("/scan/stream")
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
                line = json.dumps({
                    "type": "open",
                    "host": ep.host,
                    "port": ep.port,
                    "rtt_ms": rtt_result.rtt_ms if rtt_result else None,
                })
                yield (line + "\n").encode()

            stats_line = json.dumps({
                "type": "stats",
                "total": cumulative_total,
                "open": cumulative_open,
                "timeout": cumulative_timeout,
                "rate": output.stats.final_rate,
            })
            yield (stats_line + "\n").encode()

        # Final enumeration command
        preset = orchestrator.presets.resolve_conflicts(orchestrator.presets.get(request.preset_key))
        from .models import CommandBuildRequest as CBR
        enumeration_target = request.target_hosts[0] if request.target_hosts else ""
        cmd = orchestrator.factory.build(CBR(
            target=enumeration_target, preset=preset, ports=request.ports, timing="-T4"
        )) if enumeration_target else None

        done_line = json.dumps({
            "type": "done",
            "command": cmd.command_str if cmd else "",
        })
        yield (done_line + "\n").encode()

    return StreamingResponse(event_stream(), media_type="application/x-ndjson")

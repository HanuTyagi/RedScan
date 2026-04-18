from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from .models import ScanRequest, ScanResponse
from .orchestrator import RedScanOrchestrator

app = FastAPI(title="RedScan", version="2.0.0")
orchestrator = RedScanOrchestrator()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    return await orchestrator.run(request)


@app.post("/scan/stream")
async def scan_stream(request: ScanRequest) -> StreamingResponse:
    async def event_stream() -> AsyncIterator[bytes]:
        result = await orchestrator.run(request)
        yield (result.model_dump_json() + "\n").encode()

    return StreamingResponse(event_stream(), media_type="application/x-ndjson")

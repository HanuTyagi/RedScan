import asyncio

import pytest

from redscan.models import DiscoveryConfig, Endpoint
from redscan.smart_scan import SmartScanModule


async def start_test_server() -> tuple[asyncio.base_events.Server, int]:
    server = await asyncio.start_server(lambda r, w: w.close(), host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_smart_scan_discovers_open_port_and_handoff() -> None:
    server, open_port = await start_test_server()
    try:
        cfg = DiscoveryConfig(
            calibration_host="127.0.0.1",
            calibration_port=open_port,
            calibration_ratio=1,
            connect_timeout_s=0.2,
            control_interval_s=0.1,
            r_min=5,
            r_max=100,
            initial_rate=20,
            loss_threshold=2,
        )
        module = SmartScanModule(cfg)
        endpoints = [Endpoint(host="127.0.0.1", port=open_port), Endpoint(host="127.0.0.1", port=open_port + 1)]
        out = await module.discovery_pass(endpoints)
        assert any(ep.port == open_port for ep in out.open_endpoints)
        handoff = await module.deep_enumeration_handoff(out)
        assert open_port in handoff.get("127.0.0.1", [])
        assert out.stats.total_count == 2
    finally:
        server.close()
        await server.wait_closed()

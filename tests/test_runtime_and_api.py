import asyncio

from fastapi.testclient import TestClient

from redscan.api import app
from redscan.runtime_parser import RealTimeDataParser


def test_runtime_parser_incremental_open_port_event() -> None:
    parser = RealTimeDataParser()

    async def _collect() -> list[str]:
        cmd = [
            "python",
            "-c",
            "print('80/tcp open http')\nprint('done')",
        ]
        kinds = []
        async for event in parser.stream_command(cmd):
            kinds.append(event.kind)
        return kinds

    kinds = asyncio.run(_collect())
    assert "line" in kinds
    assert "open_port" in kinds
    assert kinds[-1] == "done"


def test_api_scan_happy_path() -> None:
    client = TestClient(app)
    health_response = client.get("/health")
    assert health_response.status_code == 200

    resp = client.post(
        "/scan",
        json={
            "target_hosts": ["127.0.0.1"],
            "ports": [1],
            "calibration_endpoint": {"host": "127.0.0.1", "port": 1},
            "preset_key": "safe_discovery",
        },
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert "discovery" in payload
    assert "analysis" in payload

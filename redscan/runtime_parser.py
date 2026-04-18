from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator

from .models import ParsedRuntimeEvent

OPEN_PORT_RE = re.compile(r"(?P<port>\d+)/tcp\s+open\s+(?P<service>\S+)")


class RealTimeDataParser:
    """Non-blocking async command runner with incremental parsing."""

    async def stream_command(self, command: list[str]) -> AsyncIterator[ParsedRuntimeEvent]:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        assert process.stdout is not None
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            yield ParsedRuntimeEvent(kind="line", raw=text)
            match = OPEN_PORT_RE.search(text)
            if match:
                yield ParsedRuntimeEvent(
                    kind="open_port",
                    raw=text,
                    data={
                        "port": int(match.group("port")),
                        "service": match.group("service"),
                    },
                )

        await process.wait()
        yield ParsedRuntimeEvent(kind="done", data={"returncode": process.returncode})

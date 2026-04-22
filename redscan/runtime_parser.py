from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator

from .models import ParsedRuntimeEvent

# Nmap text output line format (normal/verbose):
#   80/tcp   open  http    nginx 1.18.0
#   22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
# The version field is everything after the service name (optional).
OPEN_PORT_RE = re.compile(
    r"(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<version>.+))?"
)


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
                        "proto": match.group("proto"),
                        "service": match.group("service"),
                        "version": (match.group("version") or "").strip(),
                    },
                )

        await process.wait()
        yield ParsedRuntimeEvent(kind="done", data={"returncode": process.returncode})

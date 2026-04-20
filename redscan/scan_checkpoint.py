"""
Scan-progress checkpoint helpers.

A checkpoint is a JSON file written periodically during a discovery pass so
that the scan can be resumed after a crash or manual abort without restarting
from scratch.

Schema (list of objects):
    [{"host": "10.0.0.1", "port": 22, "status": "open"}, ...]

Usage:
    from redscan.scan_checkpoint import ScanCheckpoint

    ck = ScanCheckpoint("/tmp/scan.ckpt")
    ck.save(results)          # write / overwrite
    prior = ck.load()         # list[dict] | None
    ck.clear()                # delete file on clean completion
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class ScanCheckpoint:
    """Persist and restore scan progress to/from a JSON file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    # ── Public API ────────────────────────────────────────────────────────────

    def save(self, results: list[dict[str, Any]]) -> None:
        """Overwrite the checkpoint file with *results* (serialisable dicts)."""
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(results, indent=2))
            tmp.replace(self._path)
        except OSError:
            pass  # Checkpoint is best-effort; don't crash the scan

    def load(self) -> list[dict[str, Any]] | None:
        """Return the previously saved results, or *None* if file not found."""
        if not self._path.exists():
            return None
        try:
            data = json.loads(self._path.read_text())
            if isinstance(data, list):
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def clear(self) -> None:
        """Remove the checkpoint file (called on clean scan completion)."""
        try:
            os.unlink(self._path)
        except OSError:
            pass

    @property
    def exists(self) -> bool:
        return self._path.exists()

    @property
    def path(self) -> Path:
        return self._path

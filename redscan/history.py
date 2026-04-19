"""
Persistent, thread-safe scan history store.

History is written to ~/.redscan_history.json (configurable).  Only the most
recent _MAX_ENTRIES records are kept; older entries are pruned on write.
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanHistoryEntry, ScanRequest, ScanResponse


class ScanHistoryStore:
    """Appends ScanHistoryEntry records to a JSON file on disk."""

    _DEFAULT_PATH = Path.home() / ".redscan_history.json"
    _MAX_ENTRIES = 500

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or self._DEFAULT_PATH
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, request: ScanRequest, response: ScanResponse) -> ScanHistoryEntry:
        """Create a history entry for a completed scan and persist it."""
        entry = ScanHistoryEntry(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            target_hosts=list(request.target_hosts),
            preset_key=request.preset_key,
            open_count=len(response.discovery.open_endpoints),
            command_str=response.command.command_str,
            risk_level=response.analysis.risk_level,
        )
        self._append(entry)
        return entry

    def list_entries(self, limit: int = 100) -> list[ScanHistoryEntry]:
        """Return the *limit* most recent history entries (oldest-first)."""
        if limit <= 0:
            return []
        entries = self._load()
        return entries[-limit:]

    def clear(self) -> None:
        """Delete all history entries."""
        with self._lock:
            self._path.write_text("[]")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _append(self, entry: ScanHistoryEntry) -> None:
        with self._lock:
            raw = self._load_raw()
            raw.append(entry.model_dump())
            if len(raw) > self._MAX_ENTRIES:
                raw = raw[-self._MAX_ENTRIES:]
            try:
                self._path.write_text(json.dumps(raw, indent=2))
            except OSError:
                pass  # Non-fatal; history is a best-effort feature

    def _load(self) -> list[ScanHistoryEntry]:
        result: list[ScanHistoryEntry] = []
        for item in self._load_raw():
            try:
                result.append(ScanHistoryEntry.model_validate(item))
            except Exception:
                pass
        return result

    def _load_raw(self) -> list[dict]:
        if not self._path.exists():
            return []
        try:
            return json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError):
            return []

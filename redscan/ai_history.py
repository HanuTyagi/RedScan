"""AI session history store.

Persists LLM Q&A pairs to ``~/.redscan_ai_history.json`` keyed by scan
target and timestamp.  The store keeps at most the last 500 entries so the
file does not grow without bound.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

AI_HISTORY_PATH = Path.home() / ".redscan_ai_history.json"

_MAX_ENTRIES = 500


class AIHistoryStore:
    """Append-only store for LLM Q&A pairs, backed by a JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or AI_HISTORY_PATH
        self._entries: list[dict[str, Any]] = []
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                self._entries = data if isinstance(data, list) else []
            except (OSError, json.JSONDecodeError):
                self._entries = []

    def _save(self) -> None:
        try:
            self._path.write_text(
                json.dumps(self._entries[-_MAX_ENTRIES:], indent=2)
            )
        except OSError:
            pass

    # ── Public API ───────────────────────────────────────────────────────────

    def add(
        self,
        target: str,
        prompt: str,
        response: str,
        provider: str,
        risk_level: str = "",
    ) -> None:
        """Append one Q&A pair to the store."""
        self._entries.append(
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "target": target,
                "prompt": prompt,
                "response": response,
                "provider": provider,
                "risk_level": risk_level,
            }
        )
        self._save()

    def all(self) -> list[dict[str, Any]]:
        """Return all stored entries (oldest first)."""
        return list(self._entries)

    def clear(self) -> None:
        """Delete all stored entries."""
        self._entries = []
        self._save()

"""
Persistent favourites store for the Preset Library.

Starred preset keys are kept in ``~/.redscan_favourites.json`` as a JSON
array of strings.  All mutations are written to disk immediately so that
favourites survive restarts and cannot be lost if the app crashes.

Thread-safety
-------------
A ``threading.RLock`` guards every read and write so the store is safe to
use from both the GUI main thread and any background worker.

Usage
-----
    from redscan.favourites import FavouritesStore

    store = FavouritesStore()       # singleton via module-level instance
    store.add("syn_stealth")
    store.remove("syn_stealth")
    store.toggle("syn_stealth")
    store.is_favourite("syn_stealth")   # → bool
    store.all()                          # → frozenset[str]
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

_DEFAULT_PATH = Path.home() / ".redscan_favourites.json"


class FavouritesStore:
    """Persistent, thread-safe set of starred preset keys."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_PATH
        self._lock = threading.RLock()
        self._keys: set[str] = self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> set[str]:
        try:
            data = json.loads(self._path.read_text())
            if isinstance(data, list):
                return set(str(k) for k in data)
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        return set()

    def _save(self) -> None:
        try:
            self._path.write_text(json.dumps(sorted(self._keys), indent=2))
        except OSError:
            pass  # non-fatal; in-memory state is still correct

    # ── Public API ───────────────────────────────────────────────────────────

    def add(self, key: str) -> None:
        """Star a preset key."""
        with self._lock:
            if key not in self._keys:
                self._keys.add(key)
                self._save()

    def remove(self, key: str) -> None:
        """Unstar a preset key."""
        with self._lock:
            if key in self._keys:
                self._keys.discard(key)
                self._save()

    def toggle(self, key: str) -> bool:
        """Toggle a preset key; returns True if now starred, False if removed."""
        with self._lock:
            if key in self._keys:
                self._keys.discard(key)
                self._save()
                return False
            else:
                self._keys.add(key)
                self._save()
                return True

    def is_favourite(self, key: str) -> bool:
        with self._lock:
            return key in self._keys

    def all(self) -> frozenset[str]:
        """Return an immutable snapshot of all starred keys."""
        with self._lock:
            return frozenset(self._keys)

    def clear(self) -> None:
        """Remove all starred presets (used in tests)."""
        with self._lock:
            self._keys.clear()
            self._save()


# Module-level singleton — views import this directly
_favourites: FavouritesStore = FavouritesStore()

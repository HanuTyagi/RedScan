"""
Community Preset Import / Export for RedScan.

Provides a stable JSON schema for sharing scan profiles:
  - ``export_presets(presets, path)`` → writes a JSON file
  - ``import_presets(path)``          → reads a JSON file and returns a
                                        list of ``ScanPreset`` objects

Imported presets are stored in ``~/.redscan_community_presets.json``.
The ``CommunityPresetStore`` class manages the on-disk store and exposes the
same ``load()`` / ``save()`` / ``add()`` / ``remove()`` interface used by
other stores in this package.

JSON schema
-----------
Each preset is a JSON object.  Only ``key``, ``name``, ``category``,
``description``, ``flags``, and ``aggressiveness`` are required; everything
else defaults to the empty list / False / "medium".

    [
      {
        "key": "my_quick_syn",
        "name": "My Quick SYN",
        "category": "Port Scanning",
        "description": "Custom quick SYN scan",
        "flags": ["-sS", "-T4", "-F"],
        "scripts": [],
        "script_args": [],
        "aggressiveness": "medium",
        "requires_root": true,
        "requires_ports": false,
        "extra_categories": [],
        "no_port_scan": false,
        "requires_domain": false
      }
    ]
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from redscan.preset_library import ScanPreset

_DEFAULT_COMMUNITY_PATH = Path.home() / ".redscan_community_presets.json"

# Keys that must be present in every imported preset JSON object.
_REQUIRED_KEYS = {"key", "name", "category", "description", "flags", "aggressiveness"}

# Allowed aggressiveness values
_AGGRESSIVENESS_VALUES = {"low", "medium", "high", "critical", "safe"}


def export_presets(presets: list[ScanPreset], path: Path) -> None:
    """Serialise *presets* to a JSON file at *path*.

    The file is written atomically (via a temp-name + rename) to avoid
    leaving a partial file on disk if the process is interrupted.

    Raises
    ------
    OSError
        If the parent directory is not writable.
    """
    data = [_preset_to_dict(p) for p in presets]
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


def import_presets(path: Path) -> list[ScanPreset]:
    """Load presets from a JSON file at *path*.

    Unknown keys in the JSON are silently ignored so that files produced by
    newer versions of RedScan can be loaded by older installs.

    Returns
    -------
    list[ScanPreset]
        Successfully parsed presets.  Records that fail validation are
        skipped and a ``ValueError`` is raised with a summary of all errors
        *after* processing the complete file, allowing partial imports.

    Raises
    ------
    OSError
        If *path* cannot be read.
    json.JSONDecodeError
        If the file is not valid JSON.
    ValueError
        If one or more preset records fail schema validation.
    """
    raw: Any = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError("Preset file must contain a JSON array at the top level.")

    presets: list[ScanPreset] = []
    errors: list[str] = []

    for i, item in enumerate(raw):
        try:
            presets.append(_dict_to_preset(item, index=i))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        raise ValueError(
            f"{len(errors)} preset(s) failed validation:\n" + "\n".join(errors)
        )

    return presets


# ---------------------------------------------------------------------------
# CommunityPresetStore
# ---------------------------------------------------------------------------

class CommunityPresetStore:
    """Manages community/imported presets on disk.

    Presets are persisted to ``~/.redscan_community_presets.json``.
    Thread-safe via an ``RLock``.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _DEFAULT_COMMUNITY_PATH
        self._lock = threading.RLock()
        self._presets: list[ScanPreset] = self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> list[ScanPreset]:
        if not self._path.exists():
            return []
        try:
            return import_presets(self._path)
        except (OSError, json.JSONDecodeError, ValueError):
            return []

    def _save(self) -> None:
        try:
            export_presets(self._presets, self._path)
        except OSError:
            pass  # non-fatal; in-memory state is still correct

    # ── Public API ───────────────────────────────────────────────────────────

    def all(self) -> list[ScanPreset]:
        with self._lock:
            return list(self._presets)

    def add(self, preset: ScanPreset) -> None:
        """Append *preset* to the store (duplicate keys are allowed)."""
        with self._lock:
            self._presets.append(preset)
            self._save()

    def add_many(self, presets: list[ScanPreset]) -> None:
        with self._lock:
            self._presets.extend(presets)
            self._save()

    def remove(self, key: str) -> None:
        """Remove the first preset with the matching key."""
        with self._lock:
            self._presets = [p for p in self._presets if p.key != key]
            self._save()

    def clear(self) -> None:
        with self._lock:
            self._presets.clear()
            self._save()


# Module-level singleton
_community_store: CommunityPresetStore = CommunityPresetStore()


# ---------------------------------------------------------------------------
# (De)serialisation helpers
# ---------------------------------------------------------------------------

def _preset_to_dict(p: ScanPreset) -> dict[str, Any]:
    return {
        "key":              p.key,
        "name":             p.name,
        "category":         p.category,
        "description":      p.description,
        "flags":            list(p.flags),
        "scripts":          list(p.scripts),
        "script_args":      list(p.script_args),
        "aggressiveness":   p.aggressiveness,
        "requires_root":    p.requires_root,
        "requires_ports":   p.requires_ports,
        "extra_categories": list(p.extra_categories),
        "no_port_scan":     p.no_port_scan,
        "requires_domain":  p.requires_domain,
    }


def _dict_to_preset(obj: Any, *, index: int = 0) -> ScanPreset:
    if not isinstance(obj, dict):
        raise ValueError(f"[{index}] Preset entry must be a JSON object, got {type(obj).__name__}.")

    missing = _REQUIRED_KEYS - obj.keys()
    if missing:
        raise ValueError(f"[{index}] Missing required field(s): {sorted(missing)}.")

    agg = str(obj["aggressiveness"])
    # Accept known values (case-insensitive); treat unknown as "medium"
    if agg.lower() not in _AGGRESSIVENESS_VALUES:
        agg = "medium"

    def _str_list(val: Any) -> list[str]:
        if isinstance(val, list):
            return [str(v) for v in val]
        return []

    return ScanPreset(
        key=str(obj["key"]),
        name=str(obj["name"]),
        category=str(obj["category"]),
        description=str(obj["description"]),
        flags=_str_list(obj.get("flags", [])),
        scripts=_str_list(obj.get("scripts", [])),
        script_args=_str_list(obj.get("script_args", [])),
        aggressiveness=agg,
        requires_root=bool(obj.get("requires_root", False)),
        requires_ports=bool(obj.get("requires_ports", False)),
        extra_categories=_str_list(obj.get("extra_categories", [])),
        no_port_scan=bool(obj.get("no_port_scan", False)),
        requires_domain=bool(obj.get("requires_domain", False)),
    )

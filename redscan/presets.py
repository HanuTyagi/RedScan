from __future__ import annotations

from pydantic import BaseModel, Field

from .models import PresetScanConfig
from .preset_library import PRESET_CATALOGUE


def _extract_timing_level(flag: str) -> int:
    if not flag.startswith("-T") or len(flag) <= 2:
        return 0
    suffix = flag[2:]
    return int(suffix) if suffix.isdigit() else 0


class PresetCollection(BaseModel):
    presets: dict[str, PresetScanConfig] = Field(default_factory=dict)


def _catalogue_to_collection() -> PresetCollection:
    """Build a PresetCollection from the full 29-preset PRESET_CATALOGUE.

    Also injects two legacy alias keys that pre-existing tests and the API's
    default ScanRequest.preset_key reference.  They map to semantically
    equivalent entries in the catalogue:
      'safe_discovery'   → full_connect (-sT -Pn)
      'deep_enumeration' → version_scan (-sV -sC)
    """
    presets: dict[str, PresetScanConfig] = {}
    for p in PRESET_CATALOGUE:
        presets[p.key] = PresetScanConfig(
            name=p.name,
            description=p.description,
            flags=list(p.flags),
            scripts=list(p.scripts),
            script_args=list(p.script_args),
            requires_ports=p.requires_ports,
        )

    # Compatibility aliases ─────────────────────────────────────────────────
    # These keys are referenced by the API default (ScanRequest.preset_key)
    # and by pre-existing tests.  They mirror real catalogue entries so callers
    # can use either form without breaking.
    presets.setdefault(
        "safe_discovery",
        PresetScanConfig(
            name="Safe Discovery",
            description="Full TCP connect scan suitable for demo environments (alias → full_connect)",
            flags=["-sT", "-Pn", "-T4"],
            scripts=[],
            script_args=[],
            requires_ports=True,
        ),
    )
    presets.setdefault(
        "deep_enumeration",
        PresetScanConfig(
            name="Deep Enumeration",
            description="Version and script enumeration for discovered services (alias → version_scan)",
            flags=["-sV", "-Pn", "-T4"],
            scripts=["default"],
            script_args=[],
            requires_ports=True,
        ),
    )
    return PresetCollection(presets=presets)


class PresetManager:
    """Wraps expert presets and resolves conflicts safely."""

    def __init__(self) -> None:
        self._collection = _catalogue_to_collection()

    def get(self, key: str) -> PresetScanConfig:
        if key not in self._collection.presets:
            raise KeyError(f"Unknown preset '{key}'")
        return self._collection.presets[key].model_copy(deep=True)

    def resolve_conflicts(self, preset: PresetScanConfig, extra_flags: list[str] | None = None) -> PresetScanConfig:
        combined = list(dict.fromkeys(preset.flags + (extra_flags or [])))

        if "-sS" in combined and "-sT" in combined:
            combined = [f for f in combined if f != "-sS"]

        # -sn: host-discovery only, no port-scan phase — silently drop -p* flags
        if "-sn" in combined:
            combined = [f for f in combined if not f.startswith("-p")]

        valid_timings = [f for f in combined if _extract_timing_level(f) > 0]
        if valid_timings:
            combined = [f for f in combined if not (f.startswith("-T") and _extract_timing_level(f) > 0)]
            combined.append(max(valid_timings, key=_extract_timing_level))

        return preset.model_copy(update={"flags": combined})

from __future__ import annotations

from pydantic import BaseModel, Field

from .models import PresetScanConfig


class PresetCollection(BaseModel):
    presets: dict[str, PresetScanConfig] = Field(default_factory=dict)


class PresetManager:
    """Wraps expert presets and resolves conflicts safely."""

    def __init__(self) -> None:
        self._collection = PresetCollection(
            presets={
                "safe_discovery": PresetScanConfig(
                    name="Safe Discovery",
                    description="Fast connect scan suitable for demo environments",
                    flags=["-sT", "-Pn"],
                    scripts=[],
                    requires_ports=True,
                ),
                "deep_enumeration": PresetScanConfig(
                    name="Deep Enumeration",
                    description="Version and script enumeration for discovered open services",
                    flags=["-sV", "-Pn"],
                    scripts=["default"],
                    requires_ports=True,
                ),
            }
        )

    def get(self, key: str) -> PresetScanConfig:
        if key not in self._collection.presets:
            raise KeyError(f"Unknown preset '{key}'")
        return self._collection.presets[key].model_copy(deep=True)

    def resolve_conflicts(self, preset: PresetScanConfig, extra_flags: list[str] | None = None) -> PresetScanConfig:
        combined = list(dict.fromkeys(preset.flags + (extra_flags or [])))

        if "-sS" in combined and "-sT" in combined:
            combined = [f for f in combined if f != "-sS"]

        if "-sn" in combined and any(flag.startswith("-p") for flag in combined):
            combined = [f for f in combined if f != "-sn"]

        timings = [f for f in combined if f.startswith("-T")]
        if len(timings) > 1:
            highest = max(timings, key=lambda t: int(t.replace("-T", "") or 0))
            combined = [f for f in combined if not f.startswith("-T")] + [highest]

        return preset.model_copy(update={"flags": combined})

"""
Tests for FavouritesStore and preset import/export (preset_io).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from redscan.favourites import FavouritesStore
from redscan.preset_io import (
    CommunityPresetStore,
    export_presets,
    import_presets,
    _dict_to_preset,
    _preset_to_dict,
)
from redscan.preset_library import PRESET_CATALOGUE


# ---------------------------------------------------------------------------
# FavouritesStore
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_fav(tmp_path: Path) -> FavouritesStore:
    return FavouritesStore(path=tmp_path / "favourites.json")


def test_favourites_empty_by_default(tmp_fav: FavouritesStore) -> None:
    assert len(tmp_fav.all()) == 0


def test_favourites_add(tmp_fav: FavouritesStore) -> None:
    tmp_fav.add("syn_stealth")
    assert tmp_fav.is_favourite("syn_stealth")


def test_favourites_remove(tmp_fav: FavouritesStore) -> None:
    tmp_fav.add("syn_stealth")
    tmp_fav.remove("syn_stealth")
    assert not tmp_fav.is_favourite("syn_stealth")


def test_favourites_toggle_returns_state(tmp_fav: FavouritesStore) -> None:
    assert tmp_fav.toggle("ping_sweep") is True   # now starred
    assert tmp_fav.toggle("ping_sweep") is False  # now un-starred
    assert not tmp_fav.is_favourite("ping_sweep")


def test_favourites_duplicate_add_no_duplicate_in_all(tmp_fav: FavouritesStore) -> None:
    tmp_fav.add("syn_stealth")
    tmp_fav.add("syn_stealth")
    assert len([k for k in tmp_fav.all() if k == "syn_stealth"]) == 1


def test_favourites_persisted_to_disk(tmp_path: Path) -> None:
    path = tmp_path / "fav.json"
    s1 = FavouritesStore(path=path)
    s1.add("version_scan")
    # New store instance reads from same file
    s2 = FavouritesStore(path=path)
    assert s2.is_favourite("version_scan")


def test_favourites_clear(tmp_fav: FavouritesStore) -> None:
    tmp_fav.add("ping_sweep")
    tmp_fav.add("version_scan")
    tmp_fav.clear()
    assert len(tmp_fav.all()) == 0


def test_favourites_all_is_immutable_snapshot(tmp_fav: FavouritesStore) -> None:
    tmp_fav.add("ping_sweep")
    snapshot = tmp_fav.all()
    tmp_fav.add("version_scan")
    # The snapshot taken before the second add should not include version_scan
    assert "version_scan" not in snapshot


def test_favourites_remove_nonexistent_is_safe(tmp_fav: FavouritesStore) -> None:
    # Should not raise
    tmp_fav.remove("key_that_does_not_exist")


# ---------------------------------------------------------------------------
# Preset I/O: _preset_to_dict / _dict_to_preset round-trip
# ---------------------------------------------------------------------------

def test_preset_roundtrip_identity() -> None:
    for preset in PRESET_CATALOGUE[:5]:
        d = _preset_to_dict(preset)
        p2 = _dict_to_preset(d)
        assert p2.key == preset.key
        assert p2.flags == list(preset.flags)
        assert p2.scripts == list(preset.scripts)
        assert p2.aggressiveness == preset.aggressiveness


def test_dict_to_preset_requires_mandatory_keys() -> None:
    with pytest.raises(ValueError, match="Missing required field"):
        _dict_to_preset({"key": "x"})  # missing name, category, etc.


def test_dict_to_preset_unknown_aggressiveness_defaults_to_medium() -> None:
    minimal = {
        "key": "test", "name": "Test", "category": "Port Scanning",
        "description": "desc", "flags": ["-sT"], "aggressiveness": "ultra",
    }
    p = _dict_to_preset(minimal)
    assert p.aggressiveness == "medium"


def test_dict_to_preset_non_dict_raises() -> None:
    with pytest.raises(ValueError, match="must be a JSON object"):
        _dict_to_preset("not a dict")


# ---------------------------------------------------------------------------
# export_presets / import_presets
# ---------------------------------------------------------------------------

def test_export_then_import_roundtrip(tmp_path: Path) -> None:
    src = list(PRESET_CATALOGUE[:3])
    out = tmp_path / "presets.json"
    export_presets(src, out)
    loaded = import_presets(out)
    assert len(loaded) == len(src)
    assert loaded[0].key == src[0].key


def test_import_partial_invalid_raises_value_error(tmp_path: Path) -> None:
    data = [
        {"key": "ok", "name": "OK", "category": "Port Scanning",
         "description": "d", "flags": ["-sT"], "aggressiveness": "medium"},
        "not a dict",  # invalid
    ]
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="failed validation"):
        import_presets(p)


def test_import_non_list_top_level_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"key": "x"}))
    with pytest.raises(ValueError, match="JSON array"):
        import_presets(p)


def test_import_ignores_unknown_keys(tmp_path: Path) -> None:
    data = [{
        "key": "custom_scan",
        "name": "Custom",
        "category": "Port Scanning",
        "description": "test",
        "flags": ["-sT"],
        "aggressiveness": "low",
        "future_field_unknown": "ignored",
    }]
    p = tmp_path / "custom.json"
    p.write_text(json.dumps(data))
    presets = import_presets(p)
    assert len(presets) == 1
    assert presets[0].key == "custom_scan"


def test_export_creates_valid_json(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    export_presets(list(PRESET_CATALOGUE[:2]), out)
    parsed = json.loads(out.read_text())
    assert isinstance(parsed, list)
    assert len(parsed) == 2


# ---------------------------------------------------------------------------
# CommunityPresetStore
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_store(tmp_path: Path) -> CommunityPresetStore:
    return CommunityPresetStore(path=tmp_path / "community.json")


def test_community_store_empty_initially(tmp_store: CommunityPresetStore) -> None:
    assert tmp_store.all() == []


def test_community_store_add_and_retrieve(tmp_store: CommunityPresetStore) -> None:
    p = PRESET_CATALOGUE[0]
    tmp_store.add(p)
    assert len(tmp_store.all()) == 1
    assert tmp_store.all()[0].key == p.key


def test_community_store_persists(tmp_path: Path) -> None:
    path = tmp_path / "community.json"
    s1 = CommunityPresetStore(path=path)
    s1.add(PRESET_CATALOGUE[0])
    s2 = CommunityPresetStore(path=path)
    assert len(s2.all()) == 1


def test_community_store_remove(tmp_store: CommunityPresetStore) -> None:
    p = PRESET_CATALOGUE[0]
    tmp_store.add(p)
    tmp_store.remove(p.key)
    assert tmp_store.all() == []


def test_community_store_clear(tmp_store: CommunityPresetStore) -> None:
    tmp_store.add_many(list(PRESET_CATALOGUE[:3]))
    tmp_store.clear()
    assert tmp_store.all() == []

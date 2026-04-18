"""Tests for the expanded preset library and command factory conflict logic."""
from __future__ import annotations

import pytest

from redscan.preset_library import (
    AGGRESSIVENESS_COLOR,
    PRESET_CATALOGUE,
    ScanPreset,
    get_by_category,
    get_by_key,
)


class TestPresetCatalogue:
    def test_minimum_preset_count(self) -> None:
        assert len(PRESET_CATALOGUE) >= 20

    def test_all_presets_have_required_fields(self) -> None:
        for p in PRESET_CATALOGUE:
            assert p.key, f"Preset missing key: {p}"
            assert p.name, f"Preset missing name: {p.key}"
            assert p.category, f"Preset missing category: {p.key}"
            assert p.description, f"Preset missing description: {p.key}"

    def test_unique_keys(self) -> None:
        keys = [p.key for p in PRESET_CATALOGUE]
        assert len(keys) == len(set(keys)), "Duplicate preset keys found"

    def test_flags_are_lists_of_strings(self) -> None:
        for p in PRESET_CATALOGUE:
            assert isinstance(p.flags, list)
            for f in p.flags:
                assert isinstance(f, str), f"Non-string flag in {p.key}: {f!r}"

    def test_aggressiveness_values(self) -> None:
        valid = {"Low", "Medium", "High", "Extreme"}
        for p in PRESET_CATALOGUE:
            assert p.aggressiveness in valid, f"{p.key} has bad aggressiveness '{p.aggressiveness}'"

    def test_get_by_key_returns_correct_preset(self) -> None:
        p = get_by_key("ping_sweep")
        assert p is not None
        assert p.name == "Ping Sweep"
        assert "-sn" in p.flags

    def test_get_by_key_unknown_returns_none(self) -> None:
        assert get_by_key("no_such_preset") is None

    def test_get_by_category_groups_correctly(self) -> None:
        groups = get_by_category()
        assert isinstance(groups, dict)
        # Every preset must appear in exactly one category
        all_keys_in_groups = [p.key for presets in groups.values() for p in presets]
        all_keys_in_catalogue = [p.key for p in PRESET_CATALOGUE]
        assert sorted(all_keys_in_groups) == sorted(all_keys_in_catalogue)

    def test_known_categories_present(self) -> None:
        groups = get_by_category()
        for expected in ("Host Discovery", "Port Scanning", "Service Enumeration",
                         "Vulnerability Scanning", "Stealth & Evasion", "Service-Specific"):
            assert expected in groups, f"Category '{expected}' missing"

    def test_as_scan_data_structure(self) -> None:
        p = get_by_key("syn_stealth")
        assert p is not None
        data = p.as_scan_data()
        assert "flags" in data
        assert "scripts" in data
        assert "output_xml" in data
        assert data["output_xml"].endswith(".xml")


class TestAggressivenessColors:
    def test_all_levels_have_colors(self) -> None:
        for level in ("Low", "Medium", "High", "Extreme"):
            assert level in AGGRESSIVENESS_COLOR
            assert AGGRESSIVENESS_COLOR[level].startswith("#")


class TestSpecificPresets:
    @pytest.mark.parametrize("key,expected_flag", [
        ("ping_sweep",    "-sn"),
        ("syn_stealth",   "-sS"),
        ("full_connect",  "-sT"),
        ("udp_scan",      "-sU"),
        ("xmas_scan",     "-sX"),
        ("null_scan",     "-sN"),
        ("all_ports",     "-p-"),
        ("top100",        "-F"),
        ("kitchen_sink",   "-A"),
        ("frag_mtu",      "-f"),
        ("decoy_scan",    "-D"),
    ])
    def test_preset_contains_expected_flag(self, key: str, expected_flag: str) -> None:
        p = get_by_key(key)
        assert p is not None, f"Preset '{key}' not found"
        assert expected_flag in p.flags or any(
            expected_flag in tok for tok in p.flags
        ), f"'{expected_flag}' not in {key} flags: {p.flags}"

    def test_root_required_presets_are_marked(self) -> None:
        # Scans needing raw sockets must be flagged requires_root=True
        for key in ("syn_stealth", "arp_discovery", "frag_mtu", "decoy_scan"):
            p = get_by_key(key)
            assert p is not None
            assert p.requires_root, f"{key} should require root"

    def test_connect_scan_does_not_require_root(self) -> None:
        p = get_by_key("full_connect")
        assert p is not None
        assert not p.requires_root

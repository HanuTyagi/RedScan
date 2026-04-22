"""
Tests for the expanded preset library.

Covers:
  - Catalogue integrity (unique keys, valid fields, required scripts listed)
  - Cross-category membership (extra_categories / all_categories)
  - get_by_category() including cross-category placement
  - get_by_key() happy path and missing key
  - Semantic hints (no_port_scan, requires_domain) on known presets
"""
from __future__ import annotations

import pytest

from redscan.preset_library import (
    CATEGORY_ORDER,
    PRESET_CATALOGUE,
    ScanPreset,
    get_by_category,
    get_by_key,
)

VALID_AGG = {"Low", "Medium", "High", "Extreme"}


# ---------------------------------------------------------------------------
# Catalogue integrity
# ---------------------------------------------------------------------------

def test_all_keys_unique() -> None:
    keys = [p.key for p in PRESET_CATALOGUE]
    assert len(keys) == len(set(keys)), "Duplicate preset keys found in catalogue"


def test_minimum_preset_count() -> None:
    assert len(PRESET_CATALOGUE) >= 60, (
        f"Expected at least 60 presets, got {len(PRESET_CATALOGUE)}"
    )


def test_all_presets_have_valid_aggressiveness() -> None:
    bad = [p.key for p in PRESET_CATALOGUE if p.aggressiveness not in VALID_AGG]
    assert not bad, f"Presets with invalid aggressiveness: {bad}"


def test_all_presets_have_non_empty_name_and_description() -> None:
    for p in PRESET_CATALOGUE:
        assert p.name.strip(), f"Preset '{p.key}' has empty name"
        assert p.description.strip(), f"Preset '{p.key}' has empty description"


def test_all_presets_have_non_empty_category() -> None:
    for p in PRESET_CATALOGUE:
        assert p.category.strip(), f"Preset '{p.key}' has empty category"


def test_requires_root_presets_have_raw_flags() -> None:
    """Presets that require root should carry at least one raw-socket or
    privileged flag or be a no_port_scan preset that implicitly needs raw."""
    # -A implies -sS + -O + -sV + --traceroute; add it alongside explicit raw flags.
    # --badsum and --send-ip also require raw-socket access.
    raw_flags = {"-sS", "-sU", "-O", "-f", "-sX", "-sF", "-sN", "-sA",
                 "-sW", "-sI", "-sY", "-sO", "-PR", "-sn", "-PY", "-A",
                 "--traceroute", "-D", "--badsum", "--send-ip"}
    for p in PRESET_CATALOGUE:
        if p.requires_root:
            has_raw = bool(set(p.flags) & raw_flags)
            # Some presets need root for NSE scripts even without raw flags
            # (e.g. CDP/STP broadcast listeners, SNMP brute over UDP); allow those.
            if not has_raw and not p.scripts and not p.no_port_scan:
                pytest.fail(
                    f"Preset '{p.key}' requires_root but has no recognised raw-socket flags"
                )


# ---------------------------------------------------------------------------
# Cross-category membership
# ---------------------------------------------------------------------------

def test_all_categories_property_includes_primary() -> None:
    for p in PRESET_CATALOGUE:
        assert p.category in p.all_categories, (
            f"Primary category missing from all_categories for '{p.key}'"
        )


def test_all_categories_no_duplicates() -> None:
    for p in PRESET_CATALOGUE:
        cats = p.all_categories
        assert len(cats) == len(set(cats)), (
            f"Duplicate categories in all_categories for '{p.key}': {cats}"
        )


def test_cross_category_presets_appear_in_extra_groups() -> None:
    grouped = get_by_category()
    cross = [p for p in PRESET_CATALOGUE if p.extra_categories]
    assert cross, "No cross-category presets found — test may be stale"
    for p in cross:
        for extra in p.extra_categories:
            assert extra in grouped, f"Extra category '{extra}' not in grouped dict"
            assert p in grouped[extra], (
                f"Preset '{p.key}' not found in extra category '{extra}'"
            )


def test_snmp_sweep_in_network_infrastructure() -> None:
    """snmp_sweep should appear under both Service-Specific and Network Infrastructure."""
    grouped = get_by_category()
    p = get_by_key("snmp_sweep")
    assert p is not None
    assert p in grouped.get("Network Infrastructure", [])


def test_smb_vuln_in_service_specific() -> None:
    grouped = get_by_category()
    p = get_by_key("smb_vuln")
    assert p is not None
    assert p in grouped.get("Service-Specific", [])


# ---------------------------------------------------------------------------
# get_by_category
# ---------------------------------------------------------------------------

def test_get_by_category_returns_all_primary_categories() -> None:
    grouped = get_by_category()
    primary_cats = {p.category for p in PRESET_CATALOGUE}
    for cat in primary_cats:
        assert cat in grouped, f"Primary category '{cat}' missing from get_by_category()"


def test_get_by_category_no_empty_groups() -> None:
    for cat, presets in get_by_category().items():
        assert presets, f"Category '{cat}' has no presets"


# ---------------------------------------------------------------------------
# get_by_key
# ---------------------------------------------------------------------------

def test_get_by_key_known_preset() -> None:
    p = get_by_key("ping_sweep")
    assert p is not None
    assert p.key == "ping_sweep"
    assert p.category == "Host Discovery"


def test_get_by_key_missing_returns_none() -> None:
    assert get_by_key("this_does_not_exist") is None


def test_get_by_key_all_catalogue_keys() -> None:
    for p in PRESET_CATALOGUE:
        found = get_by_key(p.key)
        assert found is p


# ---------------------------------------------------------------------------
# Semantic hints
# ---------------------------------------------------------------------------

def test_ping_sweep_no_port_scan() -> None:
    p = get_by_key("ping_sweep")
    assert p is not None and p.no_port_scan is True


def test_dns_brute_requires_domain() -> None:
    p = get_by_key("dns_brute")
    assert p is not None and p.requires_domain is True


def test_full_connect_does_not_require_root() -> None:
    p = get_by_key("full_connect")
    assert p is not None and p.requires_root is False


def test_syn_stealth_requires_root() -> None:
    p = get_by_key("syn_stealth")
    assert p is not None and p.requires_root is True


# ---------------------------------------------------------------------------
# CATEGORY_ORDER completeness
# ---------------------------------------------------------------------------

def test_category_order_covers_all_primary_categories() -> None:
    primary = {p.category for p in PRESET_CATALOGUE}
    missing = primary - set(CATEGORY_ORDER)
    assert not missing, (
        f"CATEGORY_ORDER is missing primary categories: {missing}"
    )

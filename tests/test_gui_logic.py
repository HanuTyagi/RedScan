"""Tests for GUI-layer logic that does not require a display."""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Import guard: skip all tests when no display is available
# ---------------------------------------------------------------------------

def _gui_available() -> bool:
    import os
    import sys
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return False
    try:
        import tkinter as tk
        r = tk.Tk()
        r.destroy()
        return True
    except Exception:
        return False


_SKIP_GUI = pytest.mark.skipif(not _gui_available(), reason="No display available")


# Skip this entire module when tkinter is not installed.  The non-GUI logic
# tests (conflict checking, HostRecord serialisation, LLM helpers) all live
# in files that still import tkinter/customtkinter at the module level, so
# the import below would raise ModuleNotFoundError before pytest can apply
# the per-test skip marks.
try:
    import tkinter as _tk  # noqa: F401
except ModuleNotFoundError:
    pytest.skip("tkinter not available – skipping GUI logic tests", allow_module_level=True)


# ---------------------------------------------------------------------------
# Tests for command_factory conflict logic (pure Python, no GUI needed)
# ---------------------------------------------------------------------------

from gui.views.command_factory import _FLAG_DEFS, _FlagPieceData, _check_hard_conflict


class TestCommandFactoryConflicts:
    def test_sn_disables_port_scope(self) -> None:
        placed = {"-sn"}
        disabled = _check_hard_conflict(placed)
        assert "port_scope" in disabled

    def test_no_conflict_for_normal_syn(self) -> None:
        placed = {"-sS"}
        disabled = _check_hard_conflict(placed)
        assert "port_scope" not in disabled
        assert not any("sT" in k for k in disabled)

    def test_fragmentation_blocks_st(self) -> None:
        placed = {"-f"}
        disabled = _check_hard_conflict(placed)
        # Should block the -sT flag specifically
        assert any("sT" in k for k in disabled)

    def test_st_blocks_fragmentation(self) -> None:
        placed = {"-sT"}
        disabled = _check_hard_conflict(placed)
        assert any("f" in k for k in disabled)

    def test_empty_placed_no_conflict(self) -> None:
        disabled = _check_hard_conflict(set())
        assert disabled == set()

    def test_flag_defs_all_have_required_structure(self) -> None:
        for tokens, label, category, desc in _FLAG_DEFS:
            assert isinstance(tokens, list)
            assert len(tokens) >= 1
            assert tokens[0].startswith("-")
            assert isinstance(label, str) and label
            assert isinstance(category, str) and category
            assert isinstance(desc, str) and desc

    def test_single_select_categories_present(self) -> None:
        cats = {d[2] for d in _FLAG_DEFS}
        for cat in ("scan_type", "timing", "port_scope"):
            assert cat in cats

    def test_flag_piece_data_attributes(self) -> None:
        tokens = ["-T4"]
        fd = _FlagPieceData(tokens, "-T4  Aggressive", "timing", "Fast on good networks")
        assert fd.first_token == "-T4"
        assert fd.category == "timing"


# ---------------------------------------------------------------------------
# Tests for preset_browser logic (no GUI)
# ---------------------------------------------------------------------------

from redscan.preset_library import PRESET_CATALOGUE, get_by_category, get_by_key


class TestPresetBrowserData:
    def test_filter_by_name(self) -> None:
        query = "stealth"
        matches = [p for p in PRESET_CATALOGUE if query.lower() in p.name.lower()]
        assert len(matches) >= 1

    def test_filter_by_category(self) -> None:
        groups = get_by_category()
        assert "Host Discovery" in groups
        assert len(groups["Host Discovery"]) >= 3

    def test_preset_card_loads_from_key(self) -> None:
        p = get_by_key("syn_stealth")
        assert p is not None
        # Simulate what the card widget does
        flag_str = " ".join(p.flags)
        assert "-sS" in flag_str


# ---------------------------------------------------------------------------
# Tests for LLM panel helpers (no API calls)
# ---------------------------------------------------------------------------

from gui.views.llm_panel import _build_prompt, _parse_llm_response, _sanitize_findings
from redscan.models import Endpoint, LLMAnalysisRequest


class TestLLMPanelHelpers:
    def _make_request(self) -> LLMAnalysisRequest:
        return LLMAnalysisRequest(
            target="10.0.0.1",
            open_endpoints=[Endpoint(host="10.0.0.1", port=80), Endpoint(host="10.0.0.1", port=443)],
            runtime_findings=[{"service": "http", "version": "nginx 1.18"}],
        )

    def test_sanitize_findings_basic(self) -> None:
        hosts = [{"host": "10.0.0.1", "os_guess": "Linux", "ports": [{"port": "22", "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9"}]}]
        out = _sanitize_findings(hosts)
        assert "10.0.0.1" in out
        assert "22" in out
        assert "ssh" in out

    def test_sanitize_no_hosts(self) -> None:
        out = _sanitize_findings([])
        assert out == "(no findings)"

    def test_build_prompt_insights_contains_target(self) -> None:
        req = self._make_request()
        prompt = _build_prompt(req, context="insights")
        assert "10.0.0.1" in prompt
        assert "risk" in prompt.lower()

    def test_build_prompt_next_steps(self) -> None:
        req = self._make_request()
        prompt = _build_prompt(req, context="next_steps")
        assert "next" in prompt.lower() or "follow" in prompt.lower() or "technique" in prompt.lower()

    def test_parse_llm_response_high_risk(self) -> None:
        raw = "This system has HIGH RISK exposure. 1. Patch immediately. 2. Disable FTP."
        result = _parse_llm_response(raw, "mock")
        assert result.risk_level == "high"
        assert len(result.recommendations) >= 1

    def test_parse_llm_response_low_risk(self) -> None:
        raw = "LOW RISK - no critical services found. 1. Monitor access logs."
        result = _parse_llm_response(raw, "mock")
        assert result.risk_level == "low"

    def test_parse_llm_response_default_medium(self) -> None:
        raw = "Some services detected. Further investigation recommended."
        result = _parse_llm_response(raw, "mock")
        assert result.risk_level == "medium"

    def test_parse_llm_response_recommendations_list(self) -> None:
        # LLMs typically put each recommendation on its own line
        raw = "Medium risk.\n1. Update services.\n2. Restrict ports.\n3. Enable logging."
        result = _parse_llm_response(raw, "mock")
        assert len(result.recommendations) >= 2


# ---------------------------------------------------------------------------
# Tests for dashboard host record serialization
# ---------------------------------------------------------------------------

from gui.views.dashboard import HostRecord


class TestHostRecord:
    def test_round_trip_serialization(self) -> None:
        r = HostRecord("192.168.1.1")
        r.ports = [{"port": "22", "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9"}]
        r.os_guess = "Linux"
        d = r.to_dict()
        r2 = HostRecord.from_dict(d)
        assert r2.host == r.host
        assert r2.ports == r.ports
        assert r2.os_guess == r.os_guess

    def test_default_status(self) -> None:
        r = HostRecord("10.0.0.1")
        assert r.status == "up"

    def test_empty_ports(self) -> None:
        r = HostRecord("10.0.0.1")
        assert r.ports == []
        d = r.to_dict()
        assert d["ports"] == []

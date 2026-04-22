"""
Tests for the dynamic ConflictManager.

Each test verifies either:
  - that a specific rule fires and produces the expected severity / keyword
  - that an auto-fix rule correctly mutates the command
  - that no false-positive is raised when there is no conflict
"""
from __future__ import annotations

import pytest

from redscan.conflict_manager import ConflictManager, DEFAULT_RULES


# Shared manager instance (stateless)
cm = ConflictManager()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _msgs(messages):
    return [text for _, text in messages]


def _severities(messages):
    return [sev for sev, _ in messages]


# ---------------------------------------------------------------------------
# Auto-fix: host discovery drops ports
# ---------------------------------------------------------------------------

def test_sn_with_ports_auto_fix_logs_advisory() -> None:
    cmd = ["nmap", "-sn", "-T4", "192.168.1.0/24"]
    _, msgs = cm.apply(cmd, "192.168.1.0/24", "1-1024", is_root=True)
    assert any("host_discovery" in m or "port specification" in m.lower() or "-sn" in m
               for m in _msgs(msgs))


def test_sn_without_ports_no_advisory() -> None:
    cmd = ["nmap", "-sn", "-T4", "192.168.1.0/24"]
    _, msgs = cm.apply(cmd, "192.168.1.0/24", "", is_root=True)
    sn_msgs = [m for m in _msgs(msgs) if "sn" in m and "port" in m.lower()]
    assert not sn_msgs


# ---------------------------------------------------------------------------
# Auto-fix: -sn + -sV incompatibility
# ---------------------------------------------------------------------------

def test_sn_plus_sv_removed() -> None:
    cmd = ["nmap", "-sn", "-sV", "-T4", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert "-sV" not in clean
    assert any("sV" in m or "version" in m.lower() for m in _msgs(msgs))


def test_sn_plus_sv_severity_is_auto_fix() -> None:
    cmd = ["nmap", "-sn", "-sV", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any(s == "auto_fix" for s in _severities(msgs))


# ---------------------------------------------------------------------------
# Auto-fix: -sn + -sC incompatibility
# ---------------------------------------------------------------------------

def test_sn_plus_sc_removed() -> None:
    cmd = ["nmap", "-sn", "-sC", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert "-sC" not in clean
    assert any("sC" in m or "script" in m.lower() for m in _msgs(msgs))


# ---------------------------------------------------------------------------
# Auto-fix: fragmentation + connect scan
# ---------------------------------------------------------------------------

def test_frag_with_sT_removes_frag() -> None:
    cmd = ["nmap", "-f", "--mtu", "24", "-sT", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert "-f" not in clean
    assert any("fragment" in m.lower() or "mtu" in m.lower() for m in _msgs(msgs))


def test_frag_with_sS_no_conflict() -> None:
    cmd = ["nmap", "-f", "-sS", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    frag_msgs = [m for m in _msgs(msgs) if "fragment" in m.lower()]
    assert not frag_msgs  # No conflict — -sS is compatible with -f


# ---------------------------------------------------------------------------
# Auto-fix: conflicting scan types -sS + -sT
# ---------------------------------------------------------------------------

def test_ss_and_st_sT_removed() -> None:
    cmd = ["nmap", "-sS", "-sT", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert "-sT" not in clean
    assert "-sS" in clean
    assert any("sT" in m or "connect" in m.lower() for m in _msgs(msgs))


# ---------------------------------------------------------------------------
# Warn: dns-brute with IP target
# ---------------------------------------------------------------------------

def test_dns_brute_with_ip_warns() -> None:
    cmd = ["nmap", "--script", "dns-brute", "192.168.1.1"]
    _, msgs = cm.apply(cmd, "192.168.1.1", "", is_root=True)
    assert any("dns-brute" in m for m in _msgs(msgs))


def test_dns_brute_with_domain_no_warn() -> None:
    cmd = ["nmap", "--script", "dns-brute", "example.com"]
    _, msgs = cm.apply(cmd, "example.com", "", is_root=True)
    dns_msgs = [m for m in _msgs(msgs) if "dns-brute" in m]
    assert not dns_msgs


def test_dns_brute_with_localhost_warns() -> None:
    cmd = ["nmap", "--script", "dns-brute", "localhost"]
    _, msgs = cm.apply(cmd, "localhost", "", is_root=True)
    assert any("dns-brute" in m for m in _msgs(msgs))


# ---------------------------------------------------------------------------
# Warn: raw-socket flags without root
# ---------------------------------------------------------------------------

def test_raw_socket_without_root_warns() -> None:
    cmd = ["nmap", "-sS", "-T4", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=False)
    assert any("root" in m.lower() or "privilege" in m.lower() for m in _msgs(msgs))


def test_raw_socket_with_root_no_warn() -> None:
    cmd = ["nmap", "-sS", "-T4", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    priv_msgs = [m for m in _msgs(msgs) if "privilege" in m.lower() or "root" in m.lower()]
    assert not priv_msgs


def test_connect_scan_without_root_no_warn() -> None:
    """TCP connect scan (-sT) does NOT need root."""
    cmd = ["nmap", "-sT", "-T4", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=False)
    priv_msgs = [m for m in _msgs(msgs) if "privilege" in m.lower()]
    assert not priv_msgs


# ---------------------------------------------------------------------------
# Warn: UDP all-ports is very slow
# ---------------------------------------------------------------------------

def test_udp_all_ports_warns() -> None:
    cmd = ["nmap", "-sU", "-p-", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any("slow" in m.lower() or "performance" in m.lower() for m in _msgs(msgs))


def test_udp_limited_ports_no_warn() -> None:
    cmd = ["nmap", "-sU", "-p", "161,53,123", "target"]
    _, msgs = cm.apply(cmd, "target", "161,53,123", is_root=True)
    slow_msgs = [m for m in _msgs(msgs) if "performance" in m.lower()]
    assert not slow_msgs


# ---------------------------------------------------------------------------
# Warn: stealth + T5 timing defeats evasion
# ---------------------------------------------------------------------------

def test_stealth_with_T5_warns() -> None:
    cmd = ["nmap", "-sX", "-T5", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any("evasion" in m.lower() or "T5" in m for m in _msgs(msgs))


def test_stealth_with_T2_no_warn() -> None:
    cmd = ["nmap", "-sX", "-T2", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    evasion_msgs = [m for m in _msgs(msgs) if "evasion" in m.lower() and "T5" in m]
    assert not evasion_msgs


# ---------------------------------------------------------------------------
# Warn: -O without root
# ---------------------------------------------------------------------------

def test_os_detect_without_root_warns() -> None:
    cmd = ["nmap", "-O", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=False)
    assert any("-O" in m or "os" in m.lower() for m in _msgs(msgs))


def test_os_detect_with_root_no_warn() -> None:
    cmd = ["nmap", "-O", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    os_msgs = [m for m in _msgs(msgs) if "-O" in m]
    assert not os_msgs


# ---------------------------------------------------------------------------
# Warn: decoy with connect scan
# ---------------------------------------------------------------------------

def test_decoy_with_connect_scan_warns() -> None:
    cmd = ["nmap", "-D", "RND:10", "-sT", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=False)
    assert any("decoy" in m.lower() or "-D" in m for m in _msgs(msgs))


# ---------------------------------------------------------------------------
# Command immutability: original list is not mutated
# ---------------------------------------------------------------------------

def test_original_cmd_not_mutated() -> None:
    original = ["nmap", "-sn", "-sV", "target"]
    copy = list(original)
    cm.apply(original, "target", "", is_root=True)
    assert original == copy, "apply() mutated the original command list"


# ---------------------------------------------------------------------------
# Multiple rules can fire in one call
# ---------------------------------------------------------------------------

def test_multiple_rules_fire_simultaneously() -> None:
    # -sn + -sV (auto-fix) AND dns-brute + IP (warn)
    cmd = ["nmap", "-sn", "-sV", "--script", "dns-brute", "127.0.0.1"]
    clean, msgs = cm.apply(cmd, "127.0.0.1", "", is_root=True)
    assert "-sV" not in clean
    severities = _severities(msgs)
    assert "auto_fix" in severities
    assert "warning" in severities


# ---------------------------------------------------------------------------
# Custom rule list
# ---------------------------------------------------------------------------

def test_custom_rules_override_defaults() -> None:
    """Passing an empty rule list produces no messages regardless of cmd."""
    custom_cm = ConflictManager(rules=[])
    cmd = ["nmap", "-sn", "-sV", "--script", "dns-brute", "127.0.0.1"]
    clean, msgs = custom_cm.apply(cmd, "127.0.0.1", "1-1024", is_root=False)
    assert msgs == []
    assert clean == cmd


# ---------------------------------------------------------------------------
# Error severity: idle scan placeholder zombie host
# ---------------------------------------------------------------------------

def test_idle_scan_with_placeholder_zombie_is_error() -> None:
    cmd = ["nmap", "-sI", "zombie_host", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any(sev == "error" for sev, _ in msgs)
    error_texts = [text for sev, text in msgs if sev == "error"]
    assert any("zombie" in t.lower() or "placeholder" in t.lower() for t in error_texts)


def test_idle_scan_with_real_zombie_no_error() -> None:
    cmd = ["nmap", "-sI", "192.168.1.50", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert not any(sev == "error" for sev, _ in msgs)


# ---------------------------------------------------------------------------
# Error severity: brute-force on localhost with aggressive timing
# ---------------------------------------------------------------------------

def test_brute_force_localhost_t4_is_error() -> None:
    cmd = ["nmap", "--script", "ssh-brute", "-T4", "127.0.0.1"]
    _, msgs = cm.apply(cmd, "127.0.0.1", "", is_root=True)
    assert any(sev == "error" for sev, _ in msgs)


def test_brute_force_localhost_t3_not_error() -> None:
    # -T3 is acceptable
    cmd = ["nmap", "--script", "ssh-brute", "-T3", "127.0.0.1"]
    _, msgs = cm.apply(cmd, "127.0.0.1", "", is_root=True)
    assert not any(sev == "error" for sev, _ in msgs)


def test_brute_force_remote_t4_not_error() -> None:
    # remote target — not an error (only a warning from aggressive_timing_with_brute)
    cmd = ["nmap", "--script", "ssh-brute", "-T4", "192.168.1.1"]
    _, msgs = cm.apply(cmd, "192.168.1.1", "", is_root=True)
    assert not any(sev == "error" for sev, _ in msgs)


# ---------------------------------------------------------------------------
# ConflictManager.has_errors helper
# ---------------------------------------------------------------------------

def test_has_errors_true_when_error_present() -> None:
    cmd = ["nmap", "-sI", "zombie_host", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert ConflictManager.has_errors(msgs)


def test_has_errors_false_when_only_warnings() -> None:
    cmd = ["nmap", "-sS", "-T4", "192.168.1.1"]
    _, msgs = cm.apply(cmd, "192.168.1.1", "", is_root=False)
    assert not ConflictManager.has_errors(msgs)


def test_has_errors_false_on_empty_messages() -> None:
    assert not ConflictManager.has_errors([])


# ---------------------------------------------------------------------------
# New auto-fix: --top-ports with explicit -p conflicts
# ---------------------------------------------------------------------------

def test_top_ports_with_p_flag_removes_top_ports() -> None:
    cmd = ["nmap", "--top-ports", "1000", "-p", "80,443", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert "--top-ports" not in clean
    assert any("top-ports" in m.lower() for m in _msgs(msgs))


def test_top_ports_alone_no_conflict() -> None:
    cmd = ["nmap", "--top-ports", "1000", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    tp_msgs = [m for m in _msgs(msgs) if "top-ports" in m.lower() and "auto" in m.lower()]
    assert not tp_msgs


# ---------------------------------------------------------------------------
# New auto-fix: -Pn + -sn contradiction
# ---------------------------------------------------------------------------

def test_pn_with_sn_removes_pn() -> None:
    cmd = ["nmap", "-Pn", "-sn", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert "-Pn" not in clean
    assert any("-Pn" in m or "contradictory" in m.lower() for m in _msgs(msgs))


def test_pn_without_sn_no_conflict() -> None:
    cmd = ["nmap", "-Pn", "-sS", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    pn_msgs = [m for m in _msgs(msgs) if "-Pn" in m and "auto" in m.lower()]
    assert not pn_msgs


# ---------------------------------------------------------------------------
# New auto-fix: -A subsumes -sV / -sC / -O
# ---------------------------------------------------------------------------

def test_aggressive_removes_sv_sc_o() -> None:
    cmd = ["nmap", "-A", "-sV", "-sC", "-O", "target"]
    clean, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert "-sV" not in clean
    assert "-sC" not in clean
    assert "-O"  not in clean
    assert any("auto_fix" in sev for sev in _severities(msgs))


def test_aggressive_alone_no_subsume_conflict() -> None:
    cmd = ["nmap", "-A", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    # The subsume rule should NOT fire if -sV/-sC/-O aren't also present
    subsume_msgs = [m for m in _msgs(msgs) if "redundant" in m.lower()]
    assert not subsume_msgs


# ---------------------------------------------------------------------------
# New warn: UDP + TCP combined is slow
# ---------------------------------------------------------------------------

def test_udp_plus_tcp_combined_warns() -> None:
    cmd = ["nmap", "-sU", "-sS", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any("slow" in m.lower() or "2×" in m for m in _msgs(msgs))


# ---------------------------------------------------------------------------
# New warn: service scripts need port scan, not -sn
# ---------------------------------------------------------------------------

def test_http_script_with_sn_warns() -> None:
    cmd = ["nmap", "-sn", "--script", "http-title", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any("http" in m.lower() or "service-level" in m.lower() for m in _msgs(msgs))


def test_http_script_without_sn_no_warn() -> None:
    cmd = ["nmap", "--script", "http-title", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    sn_service_msgs = [m for m in _msgs(msgs) if "service-level" in m.lower()]
    assert not sn_service_msgs


# ---------------------------------------------------------------------------
# New warn: brute script needs port scan
# ---------------------------------------------------------------------------

def test_brute_script_with_sn_warns() -> None:
    cmd = ["nmap", "-sn", "--script", "ftp-brute", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any("brute" in m.lower() and "port" in m.lower() for m in _msgs(msgs))


# ---------------------------------------------------------------------------
# New warn: --version-intensity without -sV or -A
# ---------------------------------------------------------------------------

def test_version_intensity_without_sv_warns() -> None:
    cmd = ["nmap", "--version-intensity", "9", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    assert any("version-intensity" in m.lower() for m in _msgs(msgs))


def test_version_intensity_with_sv_no_warn() -> None:
    cmd = ["nmap", "-sV", "--version-intensity", "9", "target"]
    _, msgs = cm.apply(cmd, "target", "", is_root=True)
    vi_msgs = [m for m in _msgs(msgs) if "version-intensity" in m.lower()]
    assert not vi_msgs


# ---------------------------------------------------------------------------
# needs_ports_input static helper
# ---------------------------------------------------------------------------

def test_needs_ports_input_bare_nmap() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "target"]) is True


def test_needs_ports_input_sn_disables() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "-sn", "target"]) is False


def test_needs_ports_input_p_minus_disables() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "-p-", "target"]) is False


def test_needs_ports_input_F_disables() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "-F", "target"]) is False


def test_needs_ports_input_top_ports_disables() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "--top-ports", "1000", "target"]) is False


def test_needs_ports_input_sS_T4_enabled() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "-sS", "-T4", "target"]) is True


def test_needs_ports_input_sV_enabled() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "-sV", "-p", "80,443", "target"]) is True



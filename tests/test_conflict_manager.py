from redscan.conflict_manager import ConflictManager


def test_needs_ports_input_for_ping_and_self_porting_flags() -> None:
    assert ConflictManager.needs_ports_input(["nmap", "-sn"]) is False
    assert ConflictManager.needs_ports_input(["nmap", "-F"]) is False
    assert ConflictManager.needs_ports_input(["nmap", "--top-ports", "200"]) is False
    assert ConflictManager.needs_ports_input(["nmap", "-sT"]) is True


def test_raw_socket_without_root_is_blocking_error() -> None:
    mgr = ConflictManager()
    _, msgs = mgr.apply(["nmap", "-sS", "127.0.0.1"], "127.0.0.1", "", is_root=False)
    assert any(sev == "error" and "require root" in text for sev, text in msgs)


def test_host_discovery_removes_embedded_port_flags() -> None:
    mgr = ConflictManager()
    clean, _ = mgr.apply(
        ["nmap", "-sn", "-p", "1-1024", "-F", "--top-ports", "200", "127.0.0.1"],
        "127.0.0.1",
        "",
        is_root=True,
    )
    assert "-p" not in clean
    assert "-F" not in clean
    assert "--top-ports" not in clean


def test_strict_mode_escalates_warning_to_error() -> None:
    mgr = ConflictManager(strict=True)
    _, msgs = mgr.apply(["nmap", "--script", "dns-brute"], "127.0.0.1", "", is_root=True)
    assert any(sev == "error" for sev, _ in msgs)


def test_rule_telemetry_counts_hits() -> None:
    mgr = ConflictManager()
    mgr.apply(["nmap", "-sn", "-p", "80"], "127.0.0.1", "80", is_root=True)
    counts = mgr.rule_hit_counts()
    assert counts.get("host_discovery_drops_ports", 0) >= 1

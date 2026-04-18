from redscan.command_factory import CommandFactoryEngine
from redscan.models import CommandBuildRequest
from redscan.presets import PresetManager


def test_preset_conflict_resolution_prefers_st_and_single_timing() -> None:
    manager = PresetManager()
    preset = manager.get("safe_discovery")
    resolved = manager.resolve_conflicts(preset, extra_flags=["-sS", "-T3", "-T5"])
    assert "-sS" not in resolved.flags
    assert "-sT" in resolved.flags
    assert resolved.flags.count("-T5") == 1


def test_command_factory_graph_builds_expected_order() -> None:
    manager = PresetManager()
    preset = manager.resolve_conflicts(manager.get("deep_enumeration"))
    factory = CommandFactoryEngine()
    result = factory.build(CommandBuildRequest(target="127.0.0.1", preset=preset, ports=[443, 80], timing="-T4"))
    assert result.command[0] == "nmap"
    assert result.command[-1] == "127.0.0.1"
    assert "-p" in result.command
    assert "80,443" in result.command
    assert result.graph_nodes[0] == "binary"

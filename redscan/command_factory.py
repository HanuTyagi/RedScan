from __future__ import annotations

import shlex

import networkx as nx

from .models import CommandBuildRequest, CommandBuildResult


class CommandFactoryEngine:
    """Node/graph-based command constructor."""

    def build(self, request: CommandBuildRequest) -> CommandBuildResult:
        graph = nx.DiGraph()
        graph.add_node("binary", args=["nmap"])
        graph.add_node("preset_flags", args=request.preset.flags)
        # Connect binary → preset_flags so topological_sort always places
        # "nmap" first.  Without this edge the isolated node could appear
        # anywhere in the sorted output.
        graph.add_edge("binary", "preset_flags")

        if request.timing:
            graph.add_node("timing", args=[request.timing])
        else:
            graph.add_node("timing", args=[])
        graph.add_edge("preset_flags", "timing")

        ports = sorted(set(request.ports))
        if ports:
            graph.add_node("ports", args=["-p", ",".join(str(p) for p in ports)])
        else:
            graph.add_node("ports", args=[])
        graph.add_edge("timing", "ports")

        if request.preset.scripts:
            graph.add_node("scripts", args=["--script", ",".join(request.preset.scripts)])
        else:
            graph.add_node("scripts", args=[])
        graph.add_edge("ports", "scripts")

        graph.add_node("target", args=[request.target])
        graph.add_edge("scripts", "target")

        ordered_nodes = list(nx.topological_sort(graph))
        command: list[str] = []
        for node in ordered_nodes:
            command.extend(graph.nodes[node]["args"])

        command_str = " ".join(shlex.quote(part) for part in command)
        return CommandBuildResult(command=command, command_str=command_str, graph_nodes=ordered_nodes)

from __future__ import annotations

from .command_factory import CommandFactoryEngine
from .llm import LLMAnalysisPipeline
from .models import (
    CommandBuildRequest,
    CommandBuildResult,
    Endpoint,
    LLMAnalysisRequest,
    ScanRequest,
    ScanResponse,
)
from .presets import PresetManager
from .smart_scan import SmartScanModule


class RedScanOrchestrator:
    def __init__(self) -> None:
        self.presets = PresetManager()
        self.factory = CommandFactoryEngine()
        self.smart_scan = SmartScanModule()
        self.llm = LLMAnalysisPipeline()

    async def run(self, request: ScanRequest) -> ScanResponse:
        cfg = self.smart_scan.cfg.model_copy(
            update={
                "calibration_host": request.calibration_endpoint.host,
                "calibration_port": request.calibration_endpoint.port,
            }
        )
        self.smart_scan = SmartScanModule(cfg)

        endpoints = [Endpoint(host=h, port=p) for h in request.target_hosts for p in request.ports]
        discovery = await self.smart_scan.discovery_pass(endpoints)
        handoff = await self.smart_scan.deep_enumeration_handoff(discovery)

        preset = self.presets.resolve_conflicts(self.presets.get(request.preset_key))

        # Build an enumeration command for *every* discovered host so that the
        # response reflects the full scan scope, not just the first target.
        # The ScanResponse carries a single CommandBuildResult, so we pick the
        # command for the host that has the most open ports (the most informative
        # choice for further enumeration).
        if request.target_hosts:
            enumeration_target = max(
                request.target_hosts,
                key=lambda h: len(handoff.get(h, [])),
            )
        else:
            enumeration_target = ""

        command = self.factory.build(
            CommandBuildRequest(
                target=enumeration_target,
                preset=preset,
                ports=handoff.get(enumeration_target, []),
                timing="-T4",
            )
        ) if enumeration_target else CommandBuildResult(command=[], command_str="", graph_nodes=[])

        analysis = await self.llm.run(
            LLMAnalysisRequest(
                target=enumeration_target,
                open_endpoints=discovery.open_endpoints,
                runtime_findings=[],
                nmap_command=command.command_str if enumeration_target else "",
            )
        )

        return ScanResponse(discovery=discovery, command=command, analysis=analysis)

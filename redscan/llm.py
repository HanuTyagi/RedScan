from __future__ import annotations

from abc import ABC, abstractmethod

from .models import LLMAnalysisRequest, LLMAnalysisResult


class LLMProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def analyze(self, request: LLMAnalysisRequest) -> LLMAnalysisResult: ...


class MockLLMProvider(LLMProvider):
    @property
    def name(self) -> str:
        return "mock"

    async def analyze(self, request: LLMAnalysisRequest) -> LLMAnalysisResult:
        high_risk_ports = {21, 23, 445, 3389}
        open_ports = {endpoint.port for endpoint in request.open_endpoints}
        risky = sorted(open_ports & high_risk_ports)

        if risky:
            risk = "high"
            summary = f"High-risk exposed services detected on ports: {', '.join(map(str, risky))}."
            recs = [
                "Restrict exposure with firewall rules.",
                "Enforce strong authentication and patch management.",
            ]
        elif open_ports:
            risk = "medium"
            summary = "Reachable services discovered; investigate versions and hardening posture."
            recs = ["Validate service versions.", "Review least-privilege network access."]
        else:
            risk = "low"
            summary = "No open ports discovered in current scan scope."
            recs = ["Expand scan scope if appropriate.", "Re-run periodically for drift detection."]

        return LLMAnalysisResult(
            provider=self.name,
            summary=summary,
            risk_level=risk,
            recommendations=recs,
        )


class LLMAnalysisPipeline:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider or MockLLMProvider()

    async def run(self, request: LLMAnalysisRequest) -> LLMAnalysisResult:
        return await self.provider.analyze(request)

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from .models import LLMAnalysisRequest, LLMAnalysisResult

# Callback type for streaming tokens: receives one text chunk at a time.
TokenCallback = Callable[[str], None] | None


class LLMProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def analyze(self, request: LLMAnalysisRequest, context: str = "insights") -> LLMAnalysisResult: ...

    async def analyze_raw(self, prompt: str) -> LLMAnalysisResult:
        """Send *prompt* verbatim to the LLM and return a parsed result.

        Default implementation falls back to a plain mock so subclasses only
        need to override when they support raw-text submission.
        """
        return LLMAnalysisResult(
            provider=self.name,
            summary="(Raw prompt mode not supported by this provider.)",
            risk_level="low",
            recommendations=[],
        )

    async def stream_raw(
        self,
        prompt: str,
        history: list[dict[str, str]] | None = None,
        on_token: TokenCallback = None,
        system_prompt: str = "",
    ) -> LLMAnalysisResult:
        """Stream *prompt* to the LLM, calling *on_token* for each chunk.

        Default falls back to non-streaming ``analyze_raw`` so subclasses only
        need to override when they support real streaming.
        """
        result = await self.analyze_raw(prompt)
        if on_token is not None:
            on_token(result.summary)
        return result


class MockLLMProvider(LLMProvider):
    @property
    def name(self) -> str:
        return "mock"

    async def stream_raw(
        self,
        prompt: str,
        history: list[dict[str, str]] | None = None,
        on_token: TokenCallback = None,
        system_prompt: str = "",
    ) -> LLMAnalysisResult:
        """Return a mock result for any raw prompt, simulating a stream."""
        is_next_steps = "follow-up" in prompt.lower() or "what" in prompt.lower()
        if is_next_steps:
            result = LLMAnalysisResult(
                provider=self.name,
                summary="Mock next-steps: deepen service enumeration and check for default credentials.",
                risk_level="medium",
                recommendations=[
                    "Run nmap -sV -sC -p <open_ports> <target> for service fingerprinting.",
                    "Use searchsploit or Metasploit to look up CVEs for detected service versions.",
                    "Check for default credentials on exposed management services.",
                ],
            )
        else:
            result = LLMAnalysisResult(
                provider=self.name,
                summary="Mock analysis: review the prompt above and configure a real provider for live results.\nConfidence: 42",
                risk_level="medium",
                recommendations=[
                    "Configure OpenAI or Gemini in ⚙ Settings for real analysis.",
                    "Validate service versions detected in the scan.",
                    "Review least-privilege network access policies.",
                ],
            )
        if on_token is not None:
            on_token(result.summary + "\n\n")
            for i, rec in enumerate(result.recommendations, 1):
                on_token(f"{i}. {rec}\n")
            on_token("\nConfidence: 42")
        return result

    async def analyze(self, request: LLMAnalysisRequest, context: str = "insights") -> LLMAnalysisResult:
        high_risk_ports = {21, 23, 445, 3389}
        open_ports = {endpoint.port for endpoint in request.open_endpoints}
        risky = sorted(open_ports & high_risk_ports)

        # Include the nmap command in the summary so the LLM response (and any
        # real provider that reads request.nmap_command) can reference it.
        cmd_info = (
            f" (command: `{request.nmap_command}`)" if request.nmap_command else ""
        )

        if context == "next_steps":
            summary = (
                f"Based on open ports{cmd_info}, consider: deeper service enumeration "
                "with -sV, script scanning with -sC, and targeted exploit checks."
            )
            return LLMAnalysisResult(
                provider=self.name,
                summary=summary,
                risk_level="medium",
                recommendations=[
                    "Run nmap -sV -sC -p <open_ports> <target> for service fingerprinting.",
                    "Use searchsploit or Metasploit to look up CVEs for detected service versions.",
                    "Check for default credentials on exposed management services.",
                ],
            )

        if risky:
            risk = "high"
            summary = (
                f"High-risk exposed services detected on ports: {', '.join(map(str, risky))}{cmd_info}."
            )
            recs = [
                "Restrict exposure with firewall rules.",
                "Enforce strong authentication and patch management.",
            ]
        elif open_ports:
            risk = "medium"
            summary = (
                f"Reachable services discovered{cmd_info}; investigate versions and hardening posture."
            )
            recs = ["Validate service versions.", "Review least-privilege network access."]
        else:
            risk = "low"
            summary = f"No open ports discovered in current scan scope{cmd_info}."
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

    async def run(self, request: LLMAnalysisRequest, context: str = "insights") -> LLMAnalysisResult:
        return await self.provider.analyze(request, context=context)

    async def run_raw(self, prompt: str) -> LLMAnalysisResult:
        """Send *prompt* verbatim to the configured provider."""
        return await self.provider.analyze_raw(prompt)

    async def stream_raw(
        self,
        prompt: str,
        history: list[dict[str, str]] | None = None,
        on_token: TokenCallback = None,
        system_prompt: str = "",
    ) -> LLMAnalysisResult:
        """Stream *prompt* through the configured provider."""
        return await self.provider.stream_raw(
            prompt,
            history=history,
            on_token=on_token,
            system_prompt=system_prompt,
        )

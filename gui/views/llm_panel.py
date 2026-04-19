"""
LLM / AI Insights panel.

Features:
  • Provider selector: OpenAI, Gemini, Mock
  • API key input with show/hide toggle
  • "AI Insights" button – sanitises scan findings and sends to LLM
  • "What's Next?" button – asks the LLM for recommended follow-up steps
  • Result display with risk badge and recommendation list
"""
from __future__ import annotations

import asyncio
import json
import tkinter as tk
from pathlib import Path
from typing import Any

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, AGG_COLORS, BG_CARD, BG_SECONDARY, BTN_CORNER,
    CARD_CORNER, FONT_BODY, FONT_H1, FONT_H2, FONT_MONO_SM, FONT_SMALL,
    PAD, PAD_S, TEXT_MUTED, TEXT_PRIMARY,
)
from redscan.llm import LLMAnalysisPipeline, LLMProvider, MockLLMProvider
from redscan.models import Endpoint, LLMAnalysisRequest, LLMAnalysisResult


# ---------------------------------------------------------------------------
# Real provider stubs (real calls only if API keys provided)
# ---------------------------------------------------------------------------

class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gpt-4o") -> None:
        self._key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return f"openai/{self._model}"

    async def analyze(self, request: LLMAnalysisRequest, context: str = "insights") -> LLMAnalysisResult:
        try:
            import openai  # type: ignore[import]
            client = openai.AsyncOpenAI(api_key=self._key)
            prompt = _build_prompt(request, context=context)
            resp = await client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=600,
            )
            raw = resp.choices[0].message.content or ""
            return _parse_llm_response(raw, self.name)
        except Exception as exc:
            return LLMAnalysisResult(
                provider=self.name,
                summary=f"[OpenAI error] {exc}",
                risk_level="low",
                recommendations=[],
            )


class GeminiProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "gemini-1.5-flash") -> None:
        self._key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return f"gemini/{self._model}"

    async def analyze(self, request: LLMAnalysisRequest, context: str = "insights") -> LLMAnalysisResult:
        try:
            import google.generativeai as genai  # type: ignore[import]
            genai.configure(api_key=self._key)
            model = genai.GenerativeModel(self._model)
            prompt = _build_prompt(request, context=context)
            # Run the synchronous SDK call in a thread pool so we don't block
            # the event loop.  asyncio.to_thread is available in Python 3.9+.
            resp = await asyncio.to_thread(model.generate_content, prompt)
            raw = resp.text or ""
            return _parse_llm_response(raw, self.name)
        except Exception as exc:
            return LLMAnalysisResult(
                provider=self.name,
                summary=f"[Gemini error] {exc}",
                risk_level="low",
                recommendations=[],
            )


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def _sanitize_findings(hosts: list[dict[str, Any]]) -> str:
    """Convert raw host records to a compact text representation."""
    lines: list[str] = []
    for h in hosts:
        lines.append(f"Host: {h['host']}  OS: {h.get('os_guess', 'Unknown')}")
        for p in h.get("ports", []):
            lines.append(f"  {p['port']}/{p['proto']}  {p['service']}  {p.get('version', '')}")
    return "\n".join(lines) or "(no findings)"


def _build_prompt(request: LLMAnalysisRequest, context: str = "insights") -> str:
    findings_text = "\n".join(
        f"  {e.host}:{e.port}" for e in request.open_endpoints
    ) or "(none)"

    if context == "next_steps":
        return (
            f"You are a penetration testing assistant.\n"
            f"The following Nmap scan was run against target '{request.target}':\n\n"
            f"Open endpoints discovered:\n{findings_text}\n\n"
            f"Additional findings:\n{json.dumps(request.runtime_findings, indent=2)}\n\n"
            "Suggest 3-5 specific follow-up commands or techniques to deepen the assessment. "
            "Be concise and practical. Format as a numbered list."
        )

    return (
        f"You are a network security analyst.\n"
        f"Analyse the following Nmap results for target '{request.target}':\n\n"
        f"Open endpoints:\n{findings_text}\n\n"
        f"Additional findings:\n{json.dumps(request.runtime_findings, indent=2)}\n\n"
        "Provide:\n"
        "1. A one-paragraph executive summary (risk: low/medium/high).\n"
        "2. The risk level as exactly one word: low, medium, or high.\n"
        "3. Three specific remediation recommendations as a numbered list.\n"
        "Respond in plain text."
    )


def _parse_llm_response(raw: str, provider: str) -> LLMAnalysisResult:
    import re as _re

    # Heuristic extraction: look for risk keyword and bullet points
    lower = raw.lower()
    risk: str = "medium"
    if "high risk" in lower or "risk level: high" in lower or "risk: high" in lower:
        risk = "high"
    elif "low risk" in lower or "risk level: low" in lower or "risk: low" in lower:
        risk = "low"
    # Guard: Pydantic's Literal["low","medium","high"] will raise at runtime if an
    # unexpected value slips through.
    if risk not in {"low", "medium", "high"}:
        risk = "medium"

    # Match numbered list items.  Pattern captures the text after "N. " up to a
    # sentence boundary, supporting both single-line ("1. foo. 2. bar.") and
    # multi-line ("\n1. foo\n2. bar") LLM output formats.
    recs = _re.findall(r"\d+\.\s+([^.]+(?:\.[^.0-9][^.]*)?)", raw)
    if not recs:
        # Fall back to bullet lines
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped and stripped.startswith("-"):
                recs.append(stripped.lstrip("-) ").strip())
    if not recs:
        recs = [raw[:200]]

    # Truncate summary at the last sentence boundary before 500 chars so the
    # displayed text is never cut mid-sentence.
    if len(raw) > 500:
        # Find the last period/exclamation/question that ends a sentence within
        # the first 500 characters.
        boundary = _re.search(r"[.!?][^.!?]*$", raw[:500])
        summary = raw[:boundary.end()].rstrip() if boundary else raw[:500]
    else:
        summary = raw

    return LLMAnalysisResult(
        provider=provider,
        summary=summary,
        risk_level=risk,  # type: ignore[arg-type]
        recommendations=recs[:5],
    )


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path.home() / ".redscan_config.json"


class LLMInsightsView(ctk.CTkFrame):
    """LLM configuration and AI insights panel."""

    def __init__(
        self,
        master: ctk.CTk | ctk.CTkFrame,
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._hosts_data: list[dict[str, Any]] = []
        self._command_used = ""
        self._pipeline = LLMAnalysisPipeline()
        self._build()
        # Defer config loading until the main event loop is running.
        self.after(100, self._load_config)

    # ── Build ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(0, weight=0, minsize=320)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # ── Left: settings ───────────────────────────────────────────────────
        settings = ctk.CTkScrollableFrame(
            self,
            fg_color=BG_SECONDARY,
            corner_radius=CARD_CORNER,
            label_text="LLM Configuration",
        )
        settings.grid(row=0, column=0, sticky="nsew", padx=(PAD, PAD_S), pady=PAD)

        ctk.CTkLabel(settings, text="Provider", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD_S, pady=(PAD, 0)
        )
        self._provider_var = tk.StringVar(value="Mock (offline)")
        ctk.CTkComboBox(
            settings,
            values=["Mock (offline)", "OpenAI", "Gemini"],
            variable=self._provider_var,
            font=FONT_SMALL,
            command=self._on_provider_change,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD))

        ctk.CTkLabel(settings, text="API Key", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD_S
        )
        key_row = ctk.CTkFrame(settings, fg_color="transparent")
        key_row.pack(fill="x", padx=PAD_S, pady=(0, PAD))

        self._key_var = tk.StringVar()
        self._key_entry = ctk.CTkEntry(
            key_row, textvariable=self._key_var, show="•", font=FONT_SMALL
        )
        self._key_entry.pack(side="left", fill="x", expand=True, padx=(0, PAD_S))

        ctk.CTkButton(
            key_row,
            text="👁",
            width=30,
            command=self._toggle_key_visibility,
        ).pack(side="right")

        ctk.CTkLabel(settings, text="Model (optional)", font=FONT_SMALL, anchor="w").pack(
            fill="x", padx=PAD_S
        )
        self._model_var = tk.StringVar(value="")
        ctk.CTkEntry(settings, textvariable=self._model_var, placeholder_text="gpt-4o / gemini-1.5-flash", font=FONT_SMALL).pack(
            fill="x", padx=PAD_S, pady=(0, PAD)
        )

        ctk.CTkButton(
            settings,
            text="✅  Apply Configuration",
            fg_color="#1a4a1a",
            hover_color="#2a6a2a",
            corner_radius=BTN_CORNER,
            command=self._apply_config,
        ).pack(fill="x", padx=PAD_S, pady=PAD)

        ctk.CTkFrame(settings, height=1, fg_color="#2a4a2a").pack(fill="x", padx=PAD_S, pady=PAD)

        # Context display
        ctk.CTkLabel(settings, text="Scan Context", font=FONT_H2, anchor="w").pack(
            fill="x", padx=PAD_S, pady=(0, PAD_S)
        )
        self._ctx_label = ctk.CTkLabel(
            settings,
            text="No scan data loaded.\nRun a scan in the Dashboard first.",
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            wraplength=280,
            justify="left",
            anchor="w",
        )
        self._ctx_label.pack(fill="x", padx=PAD_S)

        ctk.CTkFrame(settings, height=1, fg_color="#2a4a2a").pack(fill="x", padx=PAD_S, pady=PAD)

        ctk.CTkButton(
            settings,
            text="🔍  AI Insights",
            fg_color="#4a1a6a",
            hover_color="#6a2a8a",
            corner_radius=BTN_CORNER,
            command=self._run_insights,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD_S))

        ctk.CTkButton(
            settings,
            text="🗺  What's Next?",
            fg_color="#1a3a5a",
            hover_color="#2a5a7a",
            corner_radius=BTN_CORNER,
            command=self._run_next_steps,
        ).pack(fill="x", padx=PAD_S, pady=(0, PAD))

        # ── Right: results ────────────────────────────────────────────────────
        results_pane = ctk.CTkFrame(self, fg_color="transparent")
        results_pane.grid(row=0, column=1, sticky="nsew", padx=(0, PAD), pady=PAD)
        results_pane.rowconfigure(0, weight=0)
        results_pane.rowconfigure(1, weight=0)
        results_pane.rowconfigure(2, weight=1)
        results_pane.columnconfigure(0, weight=1)

        ctk.CTkLabel(results_pane, text="AI Analysis", font=FONT_H1, anchor="w").grid(
            row=0, column=0, sticky="w", pady=(0, PAD_S)
        )

        # Risk banner
        self._risk_frame = ctk.CTkFrame(
            results_pane, fg_color=BG_CARD, corner_radius=CARD_CORNER
        )
        self._risk_frame.grid(row=1, column=0, sticky="ew", pady=(0, PAD))

        risk_inner = ctk.CTkFrame(self._risk_frame, fg_color="transparent")
        risk_inner.pack(fill="x", padx=PAD, pady=PAD_S)

        ctk.CTkLabel(risk_inner, text="Risk Level", font=FONT_SMALL, text_color=TEXT_MUTED).pack(
            side="left"
        )
        self._risk_badge = ctk.CTkLabel(
            risk_inner,
            text="  UNKNOWN  ",
            font=("Segoe UI", 13, "bold"),
            text_color="#fff",
            fg_color="#444",
            corner_radius=4,
        )
        self._risk_badge.pack(side="left", padx=PAD)

        ctk.CTkLabel(risk_inner, text="Provider:", font=FONT_SMALL, text_color=TEXT_MUTED).pack(
            side="left", padx=(PAD, 0)
        )
        self._provider_label = ctk.CTkLabel(risk_inner, text="—", font=FONT_SMALL)
        self._provider_label.pack(side="left")

        # Summary text
        summary_frame = ctk.CTkFrame(results_pane, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        summary_frame.grid(row=2, column=0, sticky="nsew")
        summary_frame.rowconfigure(1, weight=1)
        summary_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(summary_frame, text="Summary & Recommendations", font=FONT_H2, anchor="w").grid(
            row=0, column=0, padx=PAD, pady=PAD_S, sticky="w"
        )
        self._result_text = ctk.CTkTextbox(
            summary_frame,
            font=FONT_BODY,
            fg_color="#0a1020",
            text_color="#ddddee",
        )
        self._result_text.grid(row=1, column=0, sticky="nsew", padx=PAD_S, pady=(0, PAD_S))

        self._status_var = tk.StringVar(value="Configure a provider and run a scan first.")
        ctk.CTkLabel(
            self,
            textvariable=self._status_var,
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=PAD, pady=(0, PAD))

    # ── Config ────────────────────────────────────────────────────────────────

    def _on_provider_change(self, _: str) -> None:
        is_api = self._provider_var.get() != "Mock (offline)"
        self._key_entry.configure(state="normal" if is_api else "disabled")

    def _toggle_key_visibility(self) -> None:
        cur = self._key_entry.cget("show")
        self._key_entry.configure(show="" if cur == "•" else "•")

    def _apply_config(self) -> None:
        provider_name = self._provider_var.get()
        key = self._key_var.get().strip()
        model = self._model_var.get().strip()

        if provider_name == "OpenAI":
            prov: LLMProvider = OpenAIProvider(key, model or "gpt-4o")
        elif provider_name == "Gemini":
            prov = GeminiProvider(key, model or "gemini-1.5-flash")
        else:
            prov = MockLLMProvider()

        self._pipeline = LLMAnalysisPipeline(prov)
        self._status_var.set(f"Provider set: {prov.name}")
        self._save_config(provider_name, key, model)

    def _load_config(self) -> None:
        """Load saved provider / API key / model from ~/.redscan_config.json."""
        if not _CONFIG_PATH.exists():
            return
        try:
            cfg: dict[str, Any] = json.loads(_CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return
        provider = cfg.get("provider", "")
        key = cfg.get("api_key", "")
        model = cfg.get("model", "")
        if provider in ("OpenAI", "Gemini", "Mock (offline)"):
            self._provider_var.set(provider)
            self._on_provider_change(provider)
        if key:
            self._key_var.set(key)
        if model:
            self._model_var.set(model)

    def _save_config(self, provider: str, key: str, model: str) -> None:
        """Persist provider / API key / model to ~/.redscan_config.json."""
        try:
            _CONFIG_PATH.write_text(
                json.dumps({"provider": provider, "api_key": key, "model": model}, indent=2)
            )
        except OSError:
            pass  # Non-fatal

    # ── Context loading ──────────────────────────────────────────────────────

    def load_context(self, hosts: list[Any], command: str) -> None:
        """Called by the dashboard after a scan completes."""
        self._hosts_data = [h.to_dict() if hasattr(h, "to_dict") else h for h in hosts]
        self._command_used = command
        summary = f"{len(hosts)} host(s) loaded.\nCommand: {command[:80]}"
        self._ctx_label.configure(text=summary)
        self._status_var.set("Context loaded — click AI Insights or What's Next?")

    # ── Analysis ─────────────────────────────────────────────────────────────

    def _build_request(self) -> LLMAnalysisRequest:
        endpoints: list[Endpoint] = []
        findings: list[dict[str, Any]] = []
        for h in self._hosts_data:
            for p in h.get("ports", []):
                try:
                    endpoints.append(Endpoint(host=h["host"], port=int(p["port"])))
                    findings.append({
                        "host": h["host"],
                        "port": p["port"],
                        "service": p.get("service", ""),
                        "version": p.get("version", ""),
                    })
                except Exception:
                    pass
        target = self._hosts_data[0]["host"] if self._hosts_data else "unknown"
        return LLMAnalysisRequest(
            target=target,
            open_endpoints=endpoints,
            runtime_findings=findings,
            nmap_command=self._command_used,
        )

    def _run_insights(self) -> None:
        if not self._hosts_data:
            self._status_var.set("No scan data – run a scan from the Dashboard first.")
            return
        self._status_var.set("Analysing…")
        req = self._build_request()
        import threading
        threading.Thread(target=self._async_insights, args=(req, "insights"), daemon=True).start()

    def _run_next_steps(self) -> None:
        if not self._hosts_data:
            self._status_var.set("No scan data – run a scan from the Dashboard first.")
            return
        self._status_var.set("Generating next-steps guidance…")
        req = self._build_request()
        import threading
        threading.Thread(target=self._async_insights, args=(req, "next_steps"), daemon=True).start()

    def _async_insights(self, req: LLMAnalysisRequest, context: str) -> None:
        loop = asyncio.new_event_loop()
        try:
            # Pass context all the way to the provider so it receives the
            # correct prompt.  Previously the next-steps prompt was built but
            # never forwarded; the pipeline always received the default
            # "insights" context, so "What's Next?" never worked.
            result = loop.run_until_complete(self._pipeline.run(req, context=context))
        finally:
            loop.close()
        self.after(0, self._display_result, result)

    def _display_result(self, result: LLMAnalysisResult) -> None:
        risk_colors = {
            "low":    AGG_COLORS["Low"],
            "medium": AGG_COLORS["Medium"],
            "high":   AGG_COLORS["High"],
        }
        color = risk_colors.get(result.risk_level, "#888")
        self._risk_badge.configure(
            text=f"  {result.risk_level.upper()}  ",
            fg_color=color,
        )
        self._provider_label.configure(text=result.provider)

        self._result_text.delete("1.0", "end")
        self._result_text.insert("end", "SUMMARY\n" + "─" * 60 + "\n")
        self._result_text.insert("end", result.summary + "\n\n")
        self._result_text.insert("end", "RECOMMENDATIONS\n" + "─" * 60 + "\n")
        for i, rec in enumerate(result.recommendations, 1):
            self._result_text.insert("end", f"{i}. {rec}\n")

        self._status_var.set(f"Analysis complete — provider: {result.provider}")

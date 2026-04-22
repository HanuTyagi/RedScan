"""
LLM / AI Insights panel — enhanced with streaming, conversation threading,
prompt templates, copy/export, multi-provider comparison, history, inline port
cross-reference, system prompt customisation, severity tagging, and confidence
indicator.

Layout (simplified)
───────────────────
┌─ 🤖 AI Insights ─────────────────── [📜 History]  [⚙ Settings] ─┐
│  ┌─ Review Prompt ──────────────── Template: [Executive Summary ▾] │
│  │  [editable prompt textbox]                                      │
│  └────────────────────────────────── [▶ Submit Analysis]           │
│  ┌─ Risk Level ──────────────── Confidence: — ────────────────┐   │
│  │  [■ UNKNOWN]  Provider: —                                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─ Summary & Recommendations ─ [📋 Copy] [💾 Export] [⚖ Compare] │
│  │  Severity: [CVE-…] [CVSS …]  Ports: [🔗 Jump to Dashboard]     │
│  │  [result text…]                                                  │
│  └──────────────────────────────── [🗺 What's Next?]               │
│  status bar                                                         │
└─────────────────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import asyncio
import json
import re
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any, Callable

import customtkinter as ctk

from gui.styles import (
    ACCENT, ACCENT_HOVER, AGG_COLORS, BG_CARD, BG_SECONDARY, BTN_CORNER,
    CARD_CORNER, FONT_BODY, FONT_H1, FONT_H2, FONT_MONO_SM, FONT_SMALL,
    PAD, PAD_S, TEXT_MUTED, TEXT_PRIMARY,
)
from redscan.ai_history import AIHistoryStore
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
        prompt = _build_prompt(request, context=context)
        return await self.analyze_raw(prompt)

    async def analyze_raw(self, prompt: str) -> LLMAnalysisResult:
        try:
            import openai  # type: ignore[import]
            client = openai.AsyncOpenAI(api_key=self._key)
            resp = await client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=800,
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

    async def stream_raw(
        self,
        prompt: str,
        history: list[dict[str, str]] | None = None,
        on_token: "TokenCallback" = None,
        system_prompt: str = "",
    ) -> LLMAnalysisResult:
        try:
            import openai  # type: ignore[import]
            client = openai.AsyncOpenAI(api_key=self._key)
            messages: list[dict[str, str]] = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            if history:
                messages.extend(history)
            messages.append({"role": "user", "content": prompt})
            full_text = ""
            stream = await client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_tokens=800,
                stream=True,
            )
            async for chunk in stream:
                delta = chunk.choices[0].delta.content or ""
                if delta:
                    full_text += delta
                    if on_token is not None:
                        on_token(delta)
            return _parse_llm_response(full_text, self.name)
        except Exception as exc:
            err = f"[OpenAI streaming error] {exc}"
            if on_token is not None:
                on_token(err)
            return LLMAnalysisResult(
                provider=self.name,
                summary=err,
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
        prompt = _build_prompt(request, context=context)
        return await self.analyze_raw(prompt)

    async def analyze_raw(self, prompt: str) -> LLMAnalysisResult:
        try:
            import google.generativeai as genai  # type: ignore[import]
            genai.configure(api_key=self._key)
            model = genai.GenerativeModel(self._model)
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

    async def stream_raw(
        self,
        prompt: str,
        history: list[dict[str, str]] | None = None,
        on_token: "TokenCallback" = None,
        system_prompt: str = "",
    ) -> LLMAnalysisResult:
        try:
            import google.generativeai as genai  # type: ignore[import]
            genai.configure(api_key=self._key)
            model_obj = genai.GenerativeModel(
                self._model,
                system_instruction=system_prompt or None,
            )
            # Build conversation history for Gemini chat format.
            gemini_history = [
                {"role": msg["role"], "parts": [msg["content"]]}
                for msg in (history or [])
            ]
            full_text = ""

            def _run_stream() -> None:
                nonlocal full_text
                chat = model_obj.start_chat(history=gemini_history)
                for chunk in chat.send_message(prompt, stream=True):
                    token = chunk.text or ""
                    full_text += token
                    if on_token is not None and token:
                        on_token(token)

            await asyncio.to_thread(_run_stream)
            return _parse_llm_response(full_text, self.name)
        except Exception as exc:
            err = f"[Gemini streaming error] {exc}"
            if on_token is not None:
                on_token(err)
            return LLMAnalysisResult(
                provider=self.name,
                summary=err,
                risk_level="low",
                recommendations=[],
            )


# ---------------------------------------------------------------------------
# Prompt helpers & template builders
# ---------------------------------------------------------------------------

_CONFIDENCE_SUFFIX = (
    "\n\nAt the very end of your response, on a new line, write exactly: "
    "'Confidence: N' where N is an integer 0-100 indicating your certainty "
    "given the available scan data."
)

# Human-readable template names mapped to context tags used below.
PROMPT_TEMPLATE_NAMES: list[str] = [
    "Current (custom)",
    "Executive Summary",
    "Technical Deep-Dive",
    "CVSS Risk Scoring",
    "Compliance Mapping",
]


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

    # Include the nmap command that generated these results so the LLM has
    # the full context (scan type, scripts used, timing, etc.).
    command_line = f"Nmap command: {request.nmap_command}\n\n" if request.nmap_command else ""

    if context == "next_steps":
        return (
            f"You are a penetration testing assistant.\n"
            f"The following Nmap scan was run against target '{request.target}':\n\n"
            f"{command_line}"
            f"Open endpoints discovered:\n{findings_text}\n\n"
            f"Additional findings:\n{json.dumps(request.runtime_findings, indent=2)}\n\n"
            "Suggest 3-5 specific follow-up commands or techniques to deepen the assessment. "
            "Be concise and practical. Format as a numbered list."
            f"{_CONFIDENCE_SUFFIX}"
        )

    return (
        f"You are a network security analyst.\n"
        f"Analyse the following Nmap results for target '{request.target}':\n\n"
        f"{command_line}"
        f"Open endpoints:\n{findings_text}\n\n"
        f"Additional findings:\n{json.dumps(request.runtime_findings, indent=2)}\n\n"
        "Provide:\n"
        "1. A one-paragraph executive summary (risk: low/medium/high).\n"
        "2. The risk level as exactly one word: low, medium, or high.\n"
        "3. Three specific remediation recommendations as a numbered list.\n"
        "Respond in plain text."
        f"{_CONFIDENCE_SUFFIX}"
    )


def _apply_template(template_name: str, request: LLMAnalysisRequest) -> str:
    """Return the prompt text for the given named template."""
    findings_text = "\n".join(
        f"  {e.host}:{e.port}" for e in request.open_endpoints
    ) or "(none)"
    command_line = f"Nmap command: {request.nmap_command}\n\n" if request.nmap_command else ""
    findings_json = json.dumps(request.runtime_findings, indent=2)
    target = request.target

    if template_name == "Executive Summary":
        return (
            f"You are a CISO briefing executive leadership.\n"
            f"Target: {target}\n\n{command_line}"
            f"Open endpoints:\n{findings_text}\n\n"
            f"Additional findings:\n{findings_json}\n\n"
            "Write a 2-paragraph non-technical executive summary covering:\n"
            "• The overall risk posture (low / medium / high) and what it means for the business.\n"
            "• The top 3 actions leadership should prioritise and their business impact.\n"
            "Keep language clear and avoid jargon."
            f"{_CONFIDENCE_SUFFIX}"
        )
    if template_name == "Technical Deep-Dive":
        return (
            f"You are a senior penetration tester.\n"
            f"Target: {target}\n\n{command_line}"
            f"Open endpoints:\n{findings_text}\n\n"
            f"Additional findings:\n{findings_json}\n\n"
            "Provide a detailed technical analysis:\n"
            "1. Service enumeration observations and potential attack vectors.\n"
            "2. Known CVEs or vulnerability classes associated with detected service versions.\n"
            "3. Specific exploitation techniques or tools applicable here.\n"
            "4. Recommended hardening steps with exact commands where possible.\n"
            "Format with clear headings and numbered lists."
            f"{_CONFIDENCE_SUFFIX}"
        )
    if template_name == "CVSS Risk Scoring":
        return (
            f"You are a vulnerability management analyst.\n"
            f"Target: {target}\n\n{command_line}"
            f"Open endpoints:\n{findings_text}\n\n"
            f"Additional findings:\n{findings_json}\n\n"
            "For each service / finding:\n"
            "1. Identify the most likely vulnerability or risk.\n"
            "2. Estimate a CVSS v3.1 base score (0.0-10.0) and justify the scoring vector.\n"
            "3. Classify severity: None / Low / Medium / High / Critical.\n"
            "Present as a table: Service | Finding | CVSS Score | Severity | Justification."
            f"{_CONFIDENCE_SUFFIX}"
        )
    if template_name == "Compliance Mapping":
        return (
            f"You are a compliance and risk consultant.\n"
            f"Target: {target}\n\n{command_line}"
            f"Open endpoints:\n{findings_text}\n\n"
            f"Additional findings:\n{findings_json}\n\n"
            "Map each finding to the relevant control frameworks:\n"
            "• PCI-DSS 4.0 (e.g., Req 1.x – Network Controls, Req 6.x – Vulnerability Management)\n"
            "• NIST SP 800-53 (e.g., SC-7 Boundary Protection, SI-2 Flaw Remediation)\n"
            "• ISO 27001:2022 Annex A\n"
            "For each non-compliant area, state the specific control violated and the "
            "remediation needed to achieve compliance."
            f"{_CONFIDENCE_SUFFIX}"
        )
    # "Current (custom)" or unknown: caller keeps existing prompt
    return ""


def _parse_llm_response(raw: str, provider: str) -> LLMAnalysisResult:
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
    recs = re.findall(r"\d+\.\s+([^.]+(?:\.[^.0-9][^.]*)?)", raw)
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
        boundary = re.search(r"[.!?][^.!?]*$", raw[:500])
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
# Settings dialog
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path.home() / ".redscan_config.json"


class _SettingsDialog(ctk.CTkToplevel):
    """Modal dialog for LLM provider / API key / model / system prompt config."""

    def __init__(self, parent: ctk.CTkFrame, on_apply: Any) -> None:
        super().__init__(parent)
        self.title("LLM Settings")
        self.geometry("480x560")
        self.resizable(False, False)
        self.grab_set()
        self._on_apply = on_apply
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        pad = PAD

        ctk.CTkLabel(self, text="⚙  LLM Configuration", font=FONT_H2).grid(
            row=0, column=0, sticky="w", padx=pad, pady=(pad, PAD_S)
        )

        # Primary provider
        ctk.CTkLabel(self, text="Primary Provider", font=FONT_SMALL, anchor="w").grid(
            row=1, column=0, sticky="w", padx=pad
        )
        self._provider_var = tk.StringVar(value="Mock (offline)")
        ctk.CTkComboBox(
            self,
            values=["Mock (offline)", "OpenAI", "Gemini"],
            variable=self._provider_var,
            font=FONT_SMALL,
            command=self._on_provider_change,
        ).grid(row=2, column=0, sticky="ew", padx=pad, pady=(0, PAD_S))

        ctk.CTkLabel(self, text="API Key", font=FONT_SMALL, anchor="w").grid(
            row=3, column=0, sticky="w", padx=pad
        )
        key_row = ctk.CTkFrame(self, fg_color="transparent")
        key_row.grid(row=4, column=0, sticky="ew", padx=pad, pady=(0, PAD_S))
        key_row.columnconfigure(0, weight=1)

        self._key_var = tk.StringVar()
        self._key_entry = ctk.CTkEntry(
            key_row, textvariable=self._key_var, show="•", font=FONT_SMALL
        )
        self._key_entry.grid(row=0, column=0, sticky="ew", padx=(0, PAD_S))
        ctk.CTkButton(
            key_row, text="👁", width=34,
            command=self._toggle_key,
        ).grid(row=0, column=1)

        ctk.CTkLabel(self, text="Model  (leave blank for default)", font=FONT_SMALL, anchor="w").grid(
            row=5, column=0, sticky="w", padx=pad
        )
        self._model_var = tk.StringVar(value="")
        ctk.CTkEntry(
            self, textvariable=self._model_var,
            placeholder_text="gpt-4o / gemini-1.5-flash",
            font=FONT_SMALL,
        ).grid(row=6, column=0, sticky="ew", padx=pad, pady=(0, PAD_S))

        # Compare provider
        ctk.CTkLabel(self, text="Compare Provider  (for ⚖ Compare mode)", font=FONT_SMALL, anchor="w").grid(
            row=7, column=0, sticky="w", padx=pad
        )
        self._cmp_provider_var = tk.StringVar(value="Mock (offline)")
        ctk.CTkComboBox(
            self,
            values=["Mock (offline)", "OpenAI", "Gemini"],
            variable=self._cmp_provider_var,
            font=FONT_SMALL,
        ).grid(row=8, column=0, sticky="ew", padx=pad, pady=(0, PAD_S))

        ctk.CTkLabel(self, text="Compare API Key", font=FONT_SMALL, anchor="w").grid(
            row=9, column=0, sticky="w", padx=pad
        )
        cmp_key_row = ctk.CTkFrame(self, fg_color="transparent")
        cmp_key_row.grid(row=10, column=0, sticky="ew", padx=pad, pady=(0, PAD_S))
        cmp_key_row.columnconfigure(0, weight=1)

        self._cmp_key_var = tk.StringVar()
        self._cmp_key_entry = ctk.CTkEntry(
            cmp_key_row, textvariable=self._cmp_key_var, show="•", font=FONT_SMALL
        )
        self._cmp_key_entry.grid(row=0, column=0, sticky="ew", padx=(0, PAD_S))
        ctk.CTkButton(
            cmp_key_row, text="👁", width=34,
            command=self._toggle_cmp_key,
        ).grid(row=0, column=1)

        # System prompt
        ctk.CTkLabel(self, text="System Prompt / Persona", font=FONT_SMALL, anchor="w").grid(
            row=11, column=0, sticky="w", padx=pad
        )
        self._system_prompt_box = ctk.CTkTextbox(
            self, font=FONT_SMALL, height=90, fg_color="#0a1020",
        )
        self._system_prompt_box.grid(row=12, column=0, sticky="ew", padx=pad, pady=(0, PAD))
        self._system_prompt_box.insert(
            "end",
            "You are a network security analyst writing for a corporate security team.",
        )

        ctk.CTkButton(
            self, text="✅  Apply & Save",
            fg_color="#1a4a1a", hover_color="#2a6a2a",
            corner_radius=BTN_CORNER,
            command=self._apply,
        ).grid(row=13, column=0, sticky="ew", padx=pad, pady=(0, pad))

    def _on_provider_change(self, _: str) -> None:
        is_api = self._provider_var.get() != "Mock (offline)"
        self._key_entry.configure(state="normal" if is_api else "disabled")

    def _toggle_key(self) -> None:
        cur = self._key_entry.cget("show")
        self._key_entry.configure(show="" if cur == "•" else "•")

    def _toggle_cmp_key(self) -> None:
        cur = self._cmp_key_entry.cget("show")
        self._cmp_key_entry.configure(show="" if cur == "•" else "•")

    def _apply(self) -> None:
        self._on_apply(
            self._provider_var.get(),
            self._key_var.get().strip(),
            self._model_var.get().strip(),
            self._system_prompt_box.get("1.0", "end").strip(),
            self._cmp_provider_var.get(),
            self._cmp_key_var.get().strip(),
        )
        self.destroy()

    def set_values(
        self,
        provider: str,
        key: str,
        model: str,
        system_prompt: str = "",
        cmp_provider: str = "Mock (offline)",
        cmp_key: str = "",
    ) -> None:
        """Pre-populate fields from saved config."""
        if provider in ("Mock (offline)", "OpenAI", "Gemini"):
            self._provider_var.set(provider)
            self._on_provider_change(provider)
        self._key_var.set(key)
        self._model_var.set(model)
        if system_prompt:
            self._system_prompt_box.delete("1.0", "end")
            self._system_prompt_box.insert("end", system_prompt)
        if cmp_provider in ("Mock (offline)", "OpenAI", "Gemini"):
            self._cmp_provider_var.set(cmp_provider)
        self._cmp_key_var.set(cmp_key)


# ---------------------------------------------------------------------------
# History dialog
# ---------------------------------------------------------------------------

class _HistoryDialog(ctk.CTkToplevel):
    """Browse and reload past LLM Q&A sessions."""

    def __init__(self, parent: ctk.CTkFrame, store: AIHistoryStore, on_load: Callable[[str, str], None]) -> None:
        super().__init__(parent)
        self.title("📜  AI Analysis History")
        self.geometry("700x480")
        self.grab_set()
        self._store = store
        self._on_load = on_load
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=2)
        self.columnconfigure(1, weight=3)
        self.rowconfigure(1, weight=1)

        # Header row
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=PAD, pady=(PAD, PAD_S))
        hdr.columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="📜  History", font=FONT_H2, anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            hdr, text="🗑  Clear All", width=100,
            fg_color="#5a1a1a", hover_color="#8a2a2a",
            corner_radius=BTN_CORNER,
            command=self._clear_all,
        ).grid(row=0, column=1)

        # Left: entry list
        list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        list_frame.grid(row=1, column=0, sticky="nsew", padx=(PAD, PAD_S), pady=(0, PAD))
        self._list_frame = list_frame

        # Right: detail pane
        self._detail = ctk.CTkTextbox(self, font=FONT_SMALL, fg_color="#0a1020", state="disabled")
        self._detail.grid(row=1, column=1, sticky="nsew", padx=(PAD_S, PAD), pady=(0, PAD))

        # Load button
        self._load_btn = ctk.CTkButton(
            self, text="↩  Load into Panel",
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER,
            state="disabled",
            command=self._load_selected,
        )
        self._load_btn.grid(row=2, column=1, sticky="e", padx=PAD, pady=(0, PAD))

        self._selected_entry: dict[str, Any] | None = None
        self._refresh_list()

    def _refresh_list(self) -> None:
        for w in self._list_frame.winfo_children():
            w.destroy()
        entries = list(reversed(self._store.all()))  # newest first
        if not entries:
            ctk.CTkLabel(self._list_frame, text="No history yet.", font=FONT_SMALL,
                         text_color=TEXT_MUTED).pack(anchor="w", padx=PAD_S)
            return
        for entry in entries:
            ts = entry.get("timestamp", "")
            target = entry.get("target", "unknown")
            risk = entry.get("risk_level", "")
            snippet = entry.get("prompt", "")[:50].replace("\n", " ")
            label_text = f"{ts[:16]}  [{target}]  {risk.upper() if risk else ''}\n{snippet}…"
            btn = ctk.CTkButton(
                self._list_frame,
                text=label_text,
                anchor="w",
                font=FONT_SMALL,
                fg_color="transparent",
                hover_color="#2a3a4a",
                corner_radius=6,
                command=lambda e=entry: self._select(e),
            )
            btn.pack(fill="x", pady=1, padx=2)

    def _select(self, entry: dict[str, Any]) -> None:
        self._selected_entry = entry
        text = (
            f"Target: {entry.get('target', 'unknown')}\n"
            f"Timestamp: {entry.get('timestamp', '')}\n"
            f"Provider: {entry.get('provider', '')}\n"
            f"Risk: {entry.get('risk_level', '')}\n"
            f"{'─' * 40}\n"
            f"PROMPT:\n{entry.get('prompt', '')}\n\n"
            f"{'─' * 40}\n"
            f"RESPONSE:\n{entry.get('response', '')}"
        )
        self._detail.configure(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.insert("end", text)
        self._detail.configure(state="disabled")
        self._load_btn.configure(state="normal")

    def _load_selected(self) -> None:
        if self._selected_entry:
            self._on_load(
                self._selected_entry.get("prompt", ""),
                self._selected_entry.get("response", ""),
            )
            self.destroy()

    def _clear_all(self) -> None:
        self._store.clear()
        self._selected_entry = None
        self._detail.configure(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.configure(state="disabled")
        self._load_btn.configure(state="disabled")
        self._refresh_list()


# ---------------------------------------------------------------------------
# Compare dialog
# ---------------------------------------------------------------------------

class _CompareDialog(ctk.CTkToplevel):
    """Run the current prompt through two providers side-by-side."""

    def __init__(
        self,
        parent: ctk.CTkFrame,
        prompt: str,
        primary_name: str,
        primary_key: str,
        primary_model: str,
        history: list[dict[str, str]],
        system_prompt: str,
        cmp_provider_name: str,
        cmp_key: str,
    ) -> None:
        super().__init__(parent)
        self.title("⚖  Multi-Provider Comparison")
        self.geometry("1000x540")
        self.grab_set()
        self._prompt = prompt
        self._history = history
        self._system_prompt = system_prompt
        self._primary_name = primary_name
        self._primary_key = primary_key
        self._primary_model = primary_model
        self._cmp_provider_name = cmp_provider_name
        self._cmp_key = cmp_key
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        # Headers
        ctk.CTkLabel(self, text=f"Provider 1: {self._primary_name}", font=FONT_H2, anchor="w").grid(
            row=0, column=0, sticky="w", padx=PAD, pady=(PAD, PAD_S)
        )
        self._p2_label = ctk.CTkLabel(
            self, text=f"Provider 2: {self._cmp_provider_name}", font=FONT_H2, anchor="w"
        )
        self._p2_label.grid(row=0, column=1, sticky="w", padx=PAD, pady=(PAD, PAD_S))

        # Text boxes
        self._box1 = ctk.CTkTextbox(self, font=FONT_SMALL, fg_color="#0a1020")
        self._box1.grid(row=1, column=0, sticky="nsew", padx=(PAD, PAD_S), pady=(0, PAD_S))
        self._box1.insert("end", "Running…")

        self._box2 = ctk.CTkTextbox(self, font=FONT_SMALL, fg_color="#0a1020")
        self._box2.grid(row=1, column=1, sticky="nsew", padx=(PAD_S, PAD), pady=(0, PAD_S))
        self._box2.insert("end", "Running…")

        # Run compare in background (both providers stream concurrently)
        threading.Thread(target=self._run_compare, daemon=True).start()

    @staticmethod
    def _provider_from_name(name: str, key: str, model: str = "") -> LLMProvider:
        if name == "OpenAI":
            return OpenAIProvider(key, model or "gpt-4o")
        if name == "Gemini":
            return GeminiProvider(key, model or "gemini-1.5-flash")
        return MockLLMProvider()

    def _run_one(self, provider: LLMProvider, box_idx: int) -> None:
        collected: list[str] = []

        def on_token(tok: str) -> None:
            collected.append(tok)
            if box_idx == 1:
                self.after(0, self._append_token_box1, tok)
            else:
                self.after(0, self._append_token, tok)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                provider.stream_raw(
                    self._prompt,
                    history=self._history,
                    on_token=on_token,
                    system_prompt=self._system_prompt,
                )
            )
        finally:
            loop.close()

    def _run_compare(self) -> None:
        primary_provider = self._provider_from_name(
            self._primary_name,
            self._primary_key,
            self._primary_model,
        )
        cmp_provider = self._provider_from_name(self._cmp_provider_name, self._cmp_key)

        t1 = threading.Thread(target=self._run_one, args=(primary_provider, 1), daemon=True)
        t2 = threading.Thread(target=self._run_one, args=(cmp_provider, 2), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        self.after(0, self._compare_done)

    def _append_token_box1(self, tok: str) -> None:
        try:
            self._box1.insert("end", tok)
            self._box1.see("end")
        except Exception:
            pass

    def _append_token(self, tok: str) -> None:
        try:
            self._box2.insert("end", tok)
        except Exception:
            pass

    def _compare_done(self) -> None:
        # Clear placeholder "Running…" if it's still the first content.
        try:
            content = self._box1.get("1.0", "end").strip()
            if content.startswith("Running…"):
                self._box1.delete("1.0", "end")
                self._box1.insert("end", content[len("Running…"):].lstrip())
        except Exception:
            pass
        try:
            content = self._box2.get("1.0", "end").strip()
            if content.startswith("Running…"):
                self._box2.delete("1.0", "end")
                self._box2.insert("end", content[len("Running…"):].lstrip())
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main view
# ---------------------------------------------------------------------------

class LLMInsightsView(ctk.CTkFrame):
    """AI insights panel.

    The main area shows a pre-built, editable prompt (populated when the
    Dashboard sends scan context) and the LLM results.  Provider/key settings
    are tucked away in a ⚙ Settings dialog to keep the main view clean.
    """

    def __init__(
        self,
        master: "ctk.CTk | ctk.CTkFrame",
        on_jump_to_dashboard: "Callable[[list[int]], None] | None" = None,
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._hosts_data: list[dict[str, Any]] = []
        self._command_used = ""
        self._pipeline = LLMAnalysisPipeline()
        self._history_store = AIHistoryStore()
        # Conversation threading: list of {"role": "user"|"assistant", "content": str}
        self._conversation_history: list[dict[str, str]] = []
        # Saved config state (used to pre-populate the settings dialog).
        self._cfg_provider = "Mock (offline)"
        self._cfg_key = ""
        self._cfg_model = ""
        self._cfg_system_prompt = (
            "You are a network security analyst writing for a corporate security team."
        )
        self._cfg_cmp_provider = "Mock (offline)"
        self._cfg_cmp_key = ""
        # Callback to highlight ports in the dashboard (optional)
        self._on_jump_to_dashboard = on_jump_to_dashboard
        # Streaming state
        self._streaming_result: LLMAnalysisResult | None = None
        self._current_target = "unknown"
        self._last_prompt = ""
        self._last_raw_response = ""
        self._build()
        self.after(100, self._load_config)

    # ── Build ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)  # results section

        # ── Row 0: header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=PAD, pady=(PAD, 0))
        hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(hdr, text="🤖  AI Insights", font=FONT_H1, anchor="w").grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkButton(
            hdr, text="📜  History",
            fg_color=BG_SECONDARY, hover_color="#2a3a4a",
            corner_radius=BTN_CORNER,
            command=self._open_history,
        ).grid(row=0, column=1, padx=(0, PAD_S))
        ctk.CTkButton(
            hdr, text="⚙  Settings",
            fg_color=BG_SECONDARY, hover_color="#2a3a4a",
            corner_radius=BTN_CORNER,
            command=self._open_settings,
        ).grid(row=0, column=2)

        # ── Row 1: prompt review area ────────────────────────────────────────
        prompt_frame = ctk.CTkFrame(self, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        prompt_frame.grid(row=1, column=0, sticky="ew", padx=PAD, pady=(PAD_S, 0))
        prompt_frame.columnconfigure(0, weight=1)

        prompt_hdr = ctk.CTkFrame(prompt_frame, fg_color="transparent")
        prompt_hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=PAD_S, pady=(PAD_S, 0))
        prompt_hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            prompt_hdr, text="Review Prompt",
            font=FONT_H2, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        # Template dropdown
        self._template_var = tk.StringVar(value=PROMPT_TEMPLATE_NAMES[0])
        ctk.CTkComboBox(
            prompt_hdr,
            values=PROMPT_TEMPLATE_NAMES,
            variable=self._template_var,
            font=FONT_SMALL,
            width=200,
            command=self._on_template_change,
        ).grid(row=0, column=1)

        ctk.CTkLabel(
            prompt_hdr,
            text="Edit the prompt before submitting — changes are reflected in the LLM call.",
            font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, columnspan=2, sticky="w")

        self._prompt_text = ctk.CTkTextbox(
            prompt_frame,
            font=FONT_MONO_SM,
            fg_color="#0a1020",
            text_color="#aaddaa",
            height=150,
        )
        self._prompt_text.grid(row=1, column=0, sticky="ew", padx=PAD_S, pady=PAD_S)

        self._submit_btn = ctk.CTkButton(
            prompt_frame,
            text="▶  Submit Analysis",
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            corner_radius=BTN_CORNER,
            state="disabled",
            command=self._run_submit,
        )
        self._submit_btn.grid(row=2, column=0, sticky="e", padx=PAD_S, pady=(0, PAD_S))

        # ── Row 2: results ───────────────────────────────────────────────────
        results_outer = ctk.CTkFrame(self, fg_color="transparent")
        results_outer.grid(row=2, column=0, sticky="nsew", padx=PAD, pady=PAD_S)
        results_outer.columnconfigure(0, weight=1)
        results_outer.rowconfigure(1, weight=1)

        # Risk banner
        risk_frame = ctk.CTkFrame(results_outer, fg_color=BG_CARD, corner_radius=CARD_CORNER)
        risk_frame.grid(row=0, column=0, sticky="ew", pady=(0, PAD_S))
        risk_inner = ctk.CTkFrame(risk_frame, fg_color="transparent")
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

        # Confidence indicator
        ctk.CTkLabel(risk_inner, text=" │ ", font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="left")
        ctk.CTkLabel(risk_inner, text="Confidence:", font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="left")
        self._confidence_label = ctk.CTkLabel(risk_inner, text=" — ", font=FONT_SMALL)
        self._confidence_label.pack(side="left", padx=(4, 0))

        # Summary frame
        summary_frame = ctk.CTkFrame(results_outer, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        summary_frame.grid(row=1, column=0, sticky="nsew")
        summary_frame.rowconfigure(2, weight=1)
        summary_frame.columnconfigure(0, weight=1)

        # Summary header with action buttons
        sum_hdr = ctk.CTkFrame(summary_frame, fg_color="transparent")
        sum_hdr.grid(row=0, column=0, sticky="ew", padx=PAD, pady=PAD_S)
        sum_hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            sum_hdr, text="Summary & Recommendations", font=FONT_H2, anchor="w"
        ).grid(row=0, column=0, sticky="w")

        btn_frame = ctk.CTkFrame(sum_hdr, fg_color="transparent")
        btn_frame.grid(row=0, column=1)

        ctk.CTkButton(
            btn_frame, text="📋  Copy",
            fg_color=BG_SECONDARY, hover_color="#2a3a4a",
            corner_radius=BTN_CORNER, width=80,
            command=self._copy_result,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_frame, text="💾  Export Markdown",
            fg_color=BG_SECONDARY, hover_color="#2a3a4a",
            corner_radius=BTN_CORNER, width=140,
            command=self._export_markdown,
        ).pack(side="left", padx=(0, PAD_S))

        ctk.CTkButton(
            btn_frame, text="⚖  Compare",
            fg_color="#1a2a5a", hover_color="#2a3a7a",
            corner_radius=BTN_CORNER, width=90,
            command=self._open_compare,
        ).pack(side="left", padx=(0, PAD_S))

        self._whats_next_btn = ctk.CTkButton(
            btn_frame,
            text="🗺  What's Next?",
            fg_color="#1a3a5a", hover_color="#2a5a7a",
            corner_radius=BTN_CORNER,
            state="disabled",
            command=self._run_next_steps,
        )
        self._whats_next_btn.pack(side="left")

        # Severity badges row (hidden until analysis provides CVE/CVSS data)
        self._badge_frame = ctk.CTkFrame(summary_frame, fg_color="transparent")
        self._badge_frame.grid(row=1, column=0, sticky="ew", padx=PAD, pady=(0, PAD_S))
        self._badge_frame.grid_remove()  # hidden initially

        # Result textbox
        self._result_text = ctk.CTkTextbox(
            summary_frame,
            font=FONT_BODY,
            fg_color="#0a1020",
            text_color="#ddddee",
        )
        self._result_text.grid(row=2, column=0, sticky="nsew", padx=PAD_S, pady=(0, PAD_S))

        # Port cross-reference row (hidden until ports found in analysis)
        self._port_frame = ctk.CTkFrame(summary_frame, fg_color="transparent")
        self._port_frame.grid(row=3, column=0, sticky="ew", padx=PAD, pady=(0, PAD_S))
        self._port_frame.grid_remove()  # hidden initially

        # ── Row 3: status bar ────────────────────────────────────────────────
        self._status_var = tk.StringVar(value="Run a scan in the Dashboard, then click 🤖 AI Insights.")
        ctk.CTkLabel(
            self,
            textvariable=self._status_var,
            font=FONT_SMALL,
            text_color=TEXT_MUTED,
            anchor="w",
        ).grid(row=3, column=0, sticky="ew", padx=PAD, pady=(0, PAD_S))

    # ── Settings ─────────────────────────────────────────────────────────────

    def _open_settings(self) -> None:
        dlg = _SettingsDialog(self, on_apply=self._apply_config)
        dlg.set_values(
            self._cfg_provider, self._cfg_key, self._cfg_model,
            self._cfg_system_prompt, self._cfg_cmp_provider, self._cfg_cmp_key,
        )

    def _apply_config(
        self,
        provider_name: str,
        key: str,
        model: str,
        system_prompt: str = "",
        cmp_provider: str = "Mock (offline)",
        cmp_key: str = "",
    ) -> None:
        self._cfg_provider = provider_name
        self._cfg_key = key
        self._cfg_model = model
        self._cfg_system_prompt = system_prompt
        self._cfg_cmp_provider = cmp_provider
        self._cfg_cmp_key = cmp_key

        if provider_name == "OpenAI":
            prov: LLMProvider = OpenAIProvider(key, model or "gpt-4o")
        elif provider_name == "Gemini":
            prov = GeminiProvider(key, model or "gemini-1.5-flash")
        else:
            prov = MockLLMProvider()

        self._pipeline = LLMAnalysisPipeline(prov)
        self._status_var.set(f"Provider set: {prov.name}")
        self._save_config(provider_name, key, model, system_prompt, cmp_provider, cmp_key)

    def _load_config(self) -> None:
        if not _CONFIG_PATH.exists():
            return
        try:
            cfg: dict[str, Any] = json.loads(_CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return
        provider = cfg.get("provider", "Mock (offline)")
        key = cfg.get("api_key", "")
        model = cfg.get("model", "")
        system_prompt = cfg.get("system_prompt", self._cfg_system_prompt)
        cmp_provider = cfg.get("cmp_provider", "Mock (offline)")
        cmp_key = cfg.get("cmp_key", "")
        self._apply_config(provider, key, model, system_prompt, cmp_provider, cmp_key)

    def _save_config(
        self,
        provider: str,
        key: str,
        model: str,
        system_prompt: str = "",
        cmp_provider: str = "Mock (offline)",
        cmp_key: str = "",
    ) -> None:
        try:
            _CONFIG_PATH.write_text(
                json.dumps(
                    {
                        "provider": provider,
                        "api_key": key,
                        "model": model,
                        "system_prompt": system_prompt,
                        "cmp_provider": cmp_provider,
                        "cmp_key": cmp_key,
                    },
                    indent=2,
                )
            )
        except OSError:
            pass

    # ── History ───────────────────────────────────────────────────────────────

    def _open_history(self) -> None:
        _HistoryDialog(self, self._history_store, on_load=self._load_from_history)

    def _load_from_history(self, prompt: str, response: str) -> None:
        """Re-display a historical Q&A pair."""
        self._prompt_text.configure(state="normal")
        self._prompt_text.delete("1.0", "end")
        self._prompt_text.insert("end", prompt)
        self._result_text.delete("1.0", "end")
        self._result_text.insert("end", response)
        self._status_var.set("Loaded from history.")
        self._submit_btn.configure(state="normal")

    # ── Context loading ──────────────────────────────────────────────────────

    def load_context(self, hosts: list[Any], command: str) -> None:
        """Called by the dashboard after a scan completes (or by the command
        factory to explain a command).  Pre-populates the editable prompt box."""
        self._hosts_data = [h.to_dict() if hasattr(h, "to_dict") else h for h in hosts]
        self._command_used = command
        self._current_target = self._hosts_data[0]["host"] if self._hosts_data else "unknown"
        # New scan → clear conversation history so context doesn't bleed across sessions.
        self._conversation_history = []

        # Build the full prompt and populate the editable textbox.
        if self._hosts_data:
            req = self._build_request()
            prompt_text = _build_prompt(req, context="insights")
        elif command:
            prompt_text = (
                f"You are a network security expert.\n"
                f"Explain the following nmap command in plain English, covering what it does, "
                f"what each flag means, and what the expected output would include:\n\n"
                f"  {command}\n\n"
                "Be clear and concise."
                f"{_CONFIDENCE_SUFFIX}"
            )
        else:
            prompt_text = ""

        self._prompt_text.configure(state="normal")
        self._prompt_text.delete("1.0", "end")
        if prompt_text:
            self._prompt_text.insert("end", prompt_text)
        self._template_var.set(PROMPT_TEMPLATE_NAMES[0])

        self._submit_btn.configure(state="normal" if prompt_text else "disabled")
        self._whats_next_btn.configure(state="disabled")

        ctx_hint = (
            f"{len(hosts)} host(s) loaded — review the prompt and click Submit."
            if hosts
            else "Command loaded — review the prompt and click Submit."
        )
        self._status_var.set(ctx_hint)

    # ── Template dropdown ─────────────────────────────────────────────────────

    def _on_template_change(self, name: str) -> None:
        if name == PROMPT_TEMPLATE_NAMES[0] or not self._hosts_data:
            return
        req = self._build_request()
        new_prompt = _apply_template(name, req)
        if new_prompt:
            self._prompt_text.configure(state="normal")
            self._prompt_text.delete("1.0", "end")
            self._prompt_text.insert("end", new_prompt)

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

    def _run_submit(self) -> None:
        """Read the (possibly edited) prompt and send it to the LLM."""
        prompt = self._prompt_text.get("1.0", "end").strip()
        if not prompt:
            self._status_var.set("Prompt is empty — add scan context first.")
            return
        self._last_prompt = prompt
        self._submit_btn.configure(state="disabled")
        self._whats_next_btn.configure(state="disabled")
        self._status_var.set("Streaming…")
        # Clear result area and start streaming
        self._result_text.delete("1.0", "end")
        self._badge_frame.grid_remove()
        self._port_frame.grid_remove()
        threading.Thread(target=self._async_stream, args=(prompt,), daemon=True).start()

    def _run_next_steps(self) -> None:
        """Build and immediately send a follow-up next-steps prompt."""
        if not self._hosts_data:
            self._status_var.set("No scan data available for follow-up.")
            return
        req = self._build_request()
        prompt = _build_prompt(req, context="next_steps")
        self._last_prompt = prompt
        self._whats_next_btn.configure(state="disabled")
        self._status_var.set("Generating next-steps guidance…")
        self._result_text.delete("1.0", "end")
        threading.Thread(target=self._async_stream, args=(prompt,), daemon=True).start()

    def _async_stream(self, prompt: str) -> None:
        loop = asyncio.new_event_loop()
        collected: list[str] = []

        def on_token(tok: str) -> None:
            collected.append(tok)
            self.after(0, self._append_stream_token, tok)

        try:
            result = loop.run_until_complete(
                self._pipeline.stream_raw(
                    prompt,
                    history=list(self._conversation_history),
                    on_token=on_token,
                    system_prompt=self._cfg_system_prompt,
                )
            )
        finally:
            loop.close()

        self._last_raw_response = "".join(collected)
        self.after(0, self._on_stream_done, result)

    def _append_stream_token(self, tok: str) -> None:
        try:
            self._result_text.insert("end", tok)
            self._result_text.see("end")
        except Exception:
            pass

    def _on_stream_done(self, result: LLMAnalysisResult) -> None:
        # Update conversation history with Q&A pair.
        self._conversation_history.append({"role": "user", "content": self._last_prompt})
        self._conversation_history.append({"role": "assistant", "content": self._last_raw_response})

        # Save to persistent history.
        self._history_store.add(
            target=self._current_target,
            prompt=self._last_prompt,
            response=self._last_raw_response,
            provider=result.provider,
            risk_level=result.risk_level,
        )

        self._display_result(result)

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

        # Parse confidence from raw response.
        conf_text, conf_color = self._parse_confidence(self._last_raw_response)
        self._confidence_label.configure(text=conf_text, text_color=conf_color)

        self._status_var.set(f"Analysis complete — provider: {result.provider}")
        self._submit_btn.configure(state="normal")
        if self._hosts_data:
            self._whats_next_btn.configure(state="normal")

        # Apply severity badges and port cross-reference.
        self._apply_severity_badges(self._last_raw_response)
        self._apply_port_crossref(self._last_raw_response)

    # ── Confidence indicator ──────────────────────────────────────────────────

    @staticmethod
    def _parse_confidence(raw: str) -> tuple[str, str]:
        """Extract 'Confidence: N' from raw text, return (label, color)."""
        m = re.search(r"[Cc]onfidence[:\s]+(\d+)", raw)
        if not m:
            return " — ", TEXT_MUTED
        score = int(m.group(1))
        score = max(0, min(100, score))
        if score >= 70:
            return f" {score}% (High)", "#2ecc71"
        if score >= 40:
            return f" {score}% (Med)", "#f39c12"
        return f" {score}% (Low)", "#e74c3c"

    # ── Severity tagging ──────────────────────────────────────────────────────

    def _apply_severity_badges(self, raw: str) -> None:
        """Parse CVE IDs and CVSS scores and render them as colored badges."""
        for w in self._badge_frame.winfo_children():
            w.destroy()

        badges: list[tuple[str, str]] = []  # (text, colour)

        # CVE IDs
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", raw, re.IGNORECASE):
            badges.append((cve.upper(), "#c0603a"))

        # CVSS scores
        for score_str in re.findall(r"CVSS[v\s:]+(\d+\.?\d*)", raw, re.IGNORECASE):
            score = float(score_str)
            if score >= 9.0:
                col = "#8e44ad"
            elif score >= 7.0:
                col = "#e74c3c"
            elif score >= 4.0:
                col = "#f39c12"
            else:
                col = "#2ecc71"
            badges.append((f"CVSS {score_str}", col))

        # Service names (best-effort extraction from LLM prose)
        common_services = {
            "ssh", "ftp", "telnet", "rdp", "smb", "http", "https", "mysql",
            "postgresql", "postgres", "mongodb", "redis", "smtp", "dns", "snmp",
            "ldap", "kerberos", "vnc", "rpc", "mssql", "ms-sql", "imap", "pop3",
        }
        words = re.findall(r"\b[a-z][a-z0-9\-]{1,20}\b", raw.lower())
        for w in words:
            if w in common_services:
                badges.append((f"SVC {w.upper()}", "#2a6a9a"))

        if not badges:
            return

        # De-duplicate while preserving order.
        seen: set[str] = set()
        unique: list[tuple[str, str]] = []
        for text, col in badges:
            if text not in seen:
                seen.add(text)
                unique.append((text, col))

        for text, col in unique[:10]:  # cap at 10 badges
            ctk.CTkLabel(
                self._badge_frame,
                text=f" {text} ",
                font=("Segoe UI", 10, "bold"),
                text_color="#fff",
                fg_color=col,
                corner_radius=4,
            ).pack(side="left", padx=(0, 4))

        self._badge_frame.grid()  # show the badge row

    # ── Inline port cross-reference ───────────────────────────────────────────

    def _apply_port_crossref(self, raw: str) -> None:
        """Parse port numbers from results and offer a dashboard jump link."""
        for w in self._port_frame.winfo_children():
            w.destroy()

        port_nums: list[int] = []
        seen_ports: set[int] = set()
        for m in re.finditer(r"\bport[s]?\s+(\d+)\b|\b(\d+)/tcp\b|\b(\d+)/udp\b", raw, re.IGNORECASE):
            for grp in m.groups():
                if grp:
                    p = int(grp)
                    if 1 <= p <= 65535 and p not in seen_ports:
                        seen_ports.add(p)
                        port_nums.append(p)

        if not port_nums:
            return

        port_str = ", ".join(str(p) for p in port_nums[:8])
        ctk.CTkLabel(
            self._port_frame,
            text=f"Ports mentioned: {port_str}",
            font=FONT_SMALL, text_color=TEXT_MUTED,
        ).pack(side="left", padx=(0, PAD))

        if self._on_jump_to_dashboard is not None:
            ctk.CTkButton(
                self._port_frame,
                text="🔗  Jump to Dashboard",
                fg_color="#1a3a5a", hover_color="#2a5a7a",
                corner_radius=BTN_CORNER, width=160,
                command=lambda ports=port_nums: self._on_jump_to_dashboard(ports),
            ).pack(side="left")

        self._port_frame.grid()  # show the port row

    # ── Copy / Export ─────────────────────────────────────────────────────────

    def _copy_result(self) -> None:
        text = self._result_text.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._status_var.set("Copied to clipboard.")

    def _export_markdown(self) -> None:
        text = self._result_text.get("1.0", "end").strip()
        if not text:
            self._status_var.set("Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("Text files", "*.txt"), ("All files", "*")],
            initialfile=f"redscan_analysis_{self._current_target}.md",
            title="Export Analysis",
        )
        if not path:
            return
        try:
            md_header = (
                f"# RedScan AI Analysis\n\n"
                f"**Target:** {self._current_target}  \n"
                f"**Provider:** {self._cfg_provider}  \n\n"
                f"---\n\n"
            )
            Path(path).write_text(md_header + text, encoding="utf-8")
            self._status_var.set(f"Exported to {path}")
        except OSError as exc:
            self._status_var.set(f"Export failed: {exc}")

    # ── Compare mode ──────────────────────────────────────────────────────────

    def _open_compare(self) -> None:
        result_text = self._result_text.get("1.0", "end").strip()
        if not result_text:
            self._status_var.set("Run an analysis first, then click Compare.")
            return
        _CompareDialog(
            self,
            prompt=self._last_prompt,
            primary_name=self._cfg_provider,
            primary_key=self._cfg_key,
            primary_model=self._cfg_model,
            history=list(self._conversation_history),
            system_prompt=self._cfg_system_prompt,
            cmp_provider_name=self._cfg_cmp_provider,
            cmp_key=self._cfg_cmp_key,
        )


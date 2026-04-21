"""
LLM / AI Insights panel.

Layout
──────
┌─ 🤖 AI Insights ─────────────────────────────────── ⚙ Settings ─┐
│                                                                    │
│  ┌─ Review Prompt (edit before submitting) ──────────────────┐    │
│  │  [full editable prompt text pre-populated from scan data] │    │
│  └────────────────────────────────────────────────────────────┘   │
│                                        [ ▶ Submit Analysis ]       │
│                                                                    │
│  ┌─ Risk Level ───────────────────────────────────────────────┐   │
│  │  [ UNKNOWN ]  Provider: —                                  │   │
│  └────────────────────────────────────────────────────────────┘   │
│  ┌─ Summary & Recommendations ────────────────────────────────┐   │
│  │  [result text…]                                            │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                        [ 🗺 What's Next? ]         │
│                                                                    │
│  status bar                                                        │
└────────────────────────────────────────────────────────────────────┘

Settings (⚙ button → CTkToplevel dialog):
  Provider selector, API key + show/hide, Model, Apply & Save.
"""
from __future__ import annotations

import asyncio
import json
import threading
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
        prompt = _build_prompt(request, context=context)
        return await self.analyze_raw(prompt)

    async def analyze_raw(self, prompt: str) -> LLMAnalysisResult:
        try:
            import openai  # type: ignore[import]
            client = openai.AsyncOpenAI(api_key=self._key)
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

    # Include the nmap command that generated these results so the LLM has
    # the full context (scan type, scripts used, timing, etc.).  Previously
    # this field was populated in the request object but never forwarded to
    # the prompt, so the model could not reason about what was or wasn't scanned.
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
# Settings dialog
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path.home() / ".redscan_config.json"


class _SettingsDialog(ctk.CTkToplevel):
    """Modal dialog for LLM provider / API key / model configuration."""

    def __init__(self, parent: ctk.CTkFrame, on_apply: Any) -> None:
        super().__init__(parent)
        self.title("LLM Settings")
        self.geometry("420x300")
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

        ctk.CTkLabel(self, text="Provider", font=FONT_SMALL, anchor="w").grid(
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
        ).grid(row=6, column=0, sticky="ew", padx=pad, pady=(0, PAD))

        ctk.CTkButton(
            self, text="✅  Apply & Save",
            fg_color="#1a4a1a", hover_color="#2a6a2a",
            corner_radius=BTN_CORNER,
            command=self._apply,
        ).grid(row=7, column=0, sticky="ew", padx=pad, pady=(0, pad))

    def _on_provider_change(self, _: str) -> None:
        is_api = self._provider_var.get() != "Mock (offline)"
        self._key_entry.configure(state="normal" if is_api else "disabled")

    def _toggle_key(self) -> None:
        cur = self._key_entry.cget("show")
        self._key_entry.configure(show="" if cur == "•" else "•")

    def _apply(self) -> None:
        self._on_apply(
            self._provider_var.get(),
            self._key_var.get().strip(),
            self._model_var.get().strip(),
        )
        self.destroy()

    # Called by LLMInsightsView to pre-populate fields from saved config.
    def set_values(self, provider: str, key: str, model: str) -> None:
        if provider in ("Mock (offline)", "OpenAI", "Gemini"):
            self._provider_var.set(provider)
            self._on_provider_change(provider)
        self._key_var.set(key)
        self._model_var.set(model)


# ---------------------------------------------------------------------------
# Main view
# ---------------------------------------------------------------------------

class LLMInsightsView(ctk.CTkFrame):
    """AI insights panel.

    The main area shows a pre-built, editable prompt (populated when the
    Dashboard sends scan context) and the LLM results.  Provider/key settings
    are tucked away in a ⚙ Settings dialog to keep the main view clean.
    """

    def __init__(self, master: ctk.CTk | ctk.CTkFrame) -> None:
        super().__init__(master, fg_color="transparent")
        self._hosts_data: list[dict[str, Any]] = []
        self._command_used = ""
        self._pipeline = LLMAnalysisPipeline()
        # Saved config state (used to pre-populate the settings dialog).
        self._cfg_provider = "Mock (offline)"
        self._cfg_key = ""
        self._cfg_model = ""
        self._build()
        self.after(100, self._load_config)

    # ── Build ────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=0)  # prompt section
        self.rowconfigure(2, weight=1)  # results section
        self.rowconfigure(3, weight=0)  # status bar

        # ── Row 0: header ────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=PAD, pady=(PAD, 0))
        hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(hdr, text="🤖  AI Insights", font=FONT_H1, anchor="w").grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkButton(
            hdr, text="⚙  Settings",
            fg_color=BG_SECONDARY, hover_color="#2a3a4a",
            corner_radius=BTN_CORNER,
            command=self._open_settings,
        ).grid(row=0, column=1)

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
        ctk.CTkLabel(
            prompt_hdr,
            text="Edit the prompt before submitting — changes are reflected in the LLM call.",
            font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w")

        self._prompt_text = ctk.CTkTextbox(
            prompt_frame,
            font=FONT_MONO_SM,
            fg_color="#0a1020",
            text_color="#aaddaa",
            height=160,
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

        # Summary text
        summary_frame = ctk.CTkFrame(results_outer, fg_color=BG_SECONDARY, corner_radius=CARD_CORNER)
        summary_frame.grid(row=1, column=0, sticky="nsew")
        summary_frame.rowconfigure(1, weight=1)
        summary_frame.columnconfigure(0, weight=1)

        sum_hdr = ctk.CTkFrame(summary_frame, fg_color="transparent")
        sum_hdr.grid(row=0, column=0, sticky="ew", padx=PAD, pady=PAD_S)
        sum_hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            sum_hdr, text="Summary & Recommendations", font=FONT_H2, anchor="w"
        ).grid(row=0, column=0, sticky="w")

        self._whats_next_btn = ctk.CTkButton(
            sum_hdr,
            text="🗺  What's Next?",
            fg_color="#1a3a5a", hover_color="#2a5a7a",
            corner_radius=BTN_CORNER,
            state="disabled",
            command=self._run_next_steps,
        )
        self._whats_next_btn.grid(row=0, column=1)

        self._result_text = ctk.CTkTextbox(
            summary_frame,
            font=FONT_BODY,
            fg_color="#0a1020",
            text_color="#ddddee",
        )
        self._result_text.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=PAD_S, pady=(0, PAD_S))

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
        dlg.set_values(self._cfg_provider, self._cfg_key, self._cfg_model)

    def _apply_config(self, provider_name: str, key: str, model: str) -> None:
        self._cfg_provider = provider_name
        self._cfg_key = key
        self._cfg_model = model

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
        if not _CONFIG_PATH.exists():
            return
        try:
            cfg: dict[str, Any] = json.loads(_CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return
        provider = cfg.get("provider", "Mock (offline)")
        key = cfg.get("api_key", "")
        model = cfg.get("model", "")
        self._apply_config(provider, key, model)

    def _save_config(self, provider: str, key: str, model: str) -> None:
        try:
            _CONFIG_PATH.write_text(
                json.dumps({"provider": provider, "api_key": key, "model": model}, indent=2)
            )
        except OSError:
            pass

    # ── Context loading ──────────────────────────────────────────────────────

    def load_context(self, hosts: list[Any], command: str) -> None:
        """Called by the dashboard after a scan completes (or by the command
        factory to explain a command).  Pre-populates the editable prompt box."""
        self._hosts_data = [h.to_dict() if hasattr(h, "to_dict") else h for h in hosts]
        self._command_used = command

        # Build the full prompt and populate the editable textbox.
        if self._hosts_data:
            req = self._build_request()
            prompt_text = _build_prompt(req, context="insights")
        elif command:
            # Command-factory "Explain" path: no scan data, just explain the command.
            prompt_text = (
                f"You are a network security expert.\n"
                f"Explain the following nmap command in plain English, covering what it does, "
                f"what each flag means, and what the expected output would include:\n\n"
                f"  {command}\n\n"
                "Be clear and concise."
            )
        else:
            prompt_text = ""

        self._prompt_text.configure(state="normal")
        self._prompt_text.delete("1.0", "end")
        if prompt_text:
            self._prompt_text.insert("end", prompt_text)

        # Enable/disable submit based on whether there is something to send.
        self._submit_btn.configure(state="normal" if prompt_text else "disabled")
        # "What's Next?" resets until the user submits and gets a result.
        self._whats_next_btn.configure(state="disabled")

        ctx_hint = (
            f"{len(hosts)} host(s) loaded — review the prompt and click Submit."
            if hosts
            else "Command loaded — review the prompt and click Submit."
        )
        self._status_var.set(ctx_hint)

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
        self._submit_btn.configure(state="disabled")
        self._whats_next_btn.configure(state="disabled")
        self._status_var.set("Analysing…")
        threading.Thread(target=self._async_raw, args=(prompt,), daemon=True).start()

    def _run_next_steps(self) -> None:
        """Build and immediately send a follow-up next-steps prompt."""
        if not self._hosts_data:
            self._status_var.set("No scan data available for follow-up.")
            return
        req = self._build_request()
        prompt = _build_prompt(req, context="next_steps")
        self._whats_next_btn.configure(state="disabled")
        self._status_var.set("Generating next-steps guidance…")
        threading.Thread(target=self._async_raw, args=(prompt,), daemon=True).start()

    def _async_raw(self, prompt: str) -> None:
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self._pipeline.run_raw(prompt))
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
        # Re-enable buttons now that the analysis is done.
        self._submit_btn.configure(state="normal")
        if self._hosts_data:
            self._whats_next_btn.configure(state="normal")


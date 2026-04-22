"""
Dynamic Conflict Manager for RedScan.

Rather than hard-coding per-command checks, this module defines a *rule set*
where each rule is a small data object that knows:

  • how to detect itself in a (cmd, target, ports) triple
  • what severity it has (error / warning / info)
  • what action to take: "auto_fix" (silently mutate the command list and log
    an advisory) or "warn" (log a warning and let the user decide)
  • how to generate a human-readable message

Rules are evaluated in declaration order.  Auto-fix rules run *before*
warn-only rules so that the command handed to nmap is already cleaned up.

Usage
-----
    from redscan.conflict_manager import ConflictManager

    manager = ConflictManager()
    clean_cmd, messages = manager.apply(cmd, target, ports_str, is_root)

    # `clean_cmd`  — possibly mutated list[str] (auto-fixes applied)
    # `messages`   — list of (severity, text) tuples for display

Port-input gating
-----------------
    # Returns True when the active flags already carry their own port range so
    # the external port-entry widget should be disabled.
    ConflictManager.needs_ports_input(cmd) -> bool
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable, Literal

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

Severity = Literal["auto_fix", "error", "warning", "info"]

_CMD  = list[str]
_INFO = tuple[Severity, str]


@dataclass
class ConflictRule:
    """One conflict rule.

    Attributes
    ----------
    name:
        Short identifier (used in tests / logging).
    check:
        Callable(cmd, target, ports_str, is_root) → bool.
        Returns True when the conflict is present.
    severity:
        "auto_fix"  – mutate the command and log an advisory.
        "error"     – do NOT mutate; block the scan and show a blocking dialog.
        "warning"   – log a warning but do not mutate.
        "info"      – log a neutral note.
    fix:
        Callable(cmd) → list[str] that returns the corrected command.
        Required when severity == "auto_fix", ignored otherwise.
    message:
        Callable(cmd, target, ports_str, is_root) → str for log output.
    """
    name: str
    check: Callable[[_CMD, str, str, bool], bool]
    severity: Severity
    message: Callable[[_CMD, str, str, bool], str]
    fix: Callable[[_CMD], _CMD] | None = field(default=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")

# Flags that embed their own port range — external port input must be disabled.
_SELF_PORTING_FLAGS = {"-p-", "-F", "--top-ports"}

# Flags that require raw sockets (need root/admin).
_RAW_SOCKET_FLAGS = {"-sS", "-sU", "-O", "-f", "-sX", "-sF", "-sN", "-sA",
                     "-sW", "-sI", "-sY", "-sO", "-PR"}

# Flags that disable the port-scan phase entirely.
_NO_PORT_SCAN_FLAGS = {"-sn"}


def _is_ip_or_localhost(target: str) -> bool:
    return bool(_IP_RE.match(target)) or target.lower() in ("localhost", "127.0.0.1")


def _flags(cmd: _CMD) -> set[str]:
    """Return the set of flag-like tokens in the command (start with '-')."""
    return {tok for tok in cmd if tok.startswith("-")}


def _has_flag(cmd: _CMD, *flags: str) -> bool:
    f = _flags(cmd)
    return any(fl in f for fl in flags)


def _remove_flags(cmd: _CMD, *to_remove: str) -> _CMD:
    """Return a new command list with the given flags and their immediately
    following non-flag argument removed."""
    result: _CMD = []
    skip_next = False
    for i, tok in enumerate(cmd):
        if skip_next:
            skip_next = False
            continue
        if tok in to_remove:
            # If the next token is the flag's value (not itself a flag), drop it.
            nxt = cmd[i + 1] if i + 1 < len(cmd) else ""
            if nxt and not nxt.startswith("-"):
                skip_next = True
            continue
        result.append(tok)
    return result


def _remove_tokens(cmd: _CMD, *tokens: str) -> _CMD:
    """Remove specific tokens from cmd regardless of whether they are flags."""
    return [t for t in cmd if t not in tokens]


def _has_script(cmd: _CMD, *fragments: str) -> bool:
    """Return True if any --script token contains one of *fragments*."""
    in_script = False
    for tok in cmd:
        if tok == "--script":
            in_script = True
            continue
        if in_script:
            if any(frag in tok for frag in fragments):
                return True
            in_script = False
        # Also handle --script=value syntax
        if tok.startswith("--script="):
            val = tok[len("--script="):]
            if any(frag in val for frag in fragments):
                return True
    return False


# ---------------------------------------------------------------------------
# Rule declarations
# ---------------------------------------------------------------------------
#
# Rules are kept in a single ordered list.  Auto-fix rules come first so the
# cleaned command is available for subsequent warn-only checks.
#
DEFAULT_RULES: list[ConflictRule] = [

    # ── Auto-fix rules ───────────────────────────────────────────────────────

    ConflictRule(
        name="host_discovery_drops_ports",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sn") and bool(ports.strip())
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '-sn' is a host-discovery-only scan — "
            "port specification has been ignored.  Remove ports or choose a "
            "different scan type to perform a port scan."
        ),
        # No mutation needed on cmd; the dashboard already skips -p when -sn
        # is present.  The rule is still logged so the user knows what happened.
        fix=lambda cmd: cmd,
    ),

    ConflictRule(
        name="host_discovery_removes_embedded_port_flags",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sn") and _has_flag(cmd, "-p", "-p-", "-F", "--top-ports")
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '-sn' disables port scanning.  Embedded port-selection "
            "flags ('-p'/'-p-'/'-F'/'--top-ports') were removed."
        ),
        fix=lambda cmd: _remove_tokens(
            _remove_flags(cmd, "-p", "--top-ports"),
            "-p-",
            "-F",
        ),
    ),

    ConflictRule(
        name="sn_plus_sv_incompatible",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sn") and _has_flag(cmd, "-sV")
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '-sV' (version detection) requires a port-scan phase "
            "which '-sn' explicitly disables.  '-sV' has been removed from the command."
        ),
        fix=lambda cmd: _remove_flags(cmd, "-sV"),
    ),

    ConflictRule(
        name="sn_plus_sc_incompatible",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sn") and _has_flag(cmd, "-sC")
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '-sC' (default NSE scripts) requires open ports found "
            "by a port-scan phase, which '-sn' disables.  '-sC' has been removed."
        ),
        fix=lambda cmd: _remove_flags(cmd, "-sC"),
    ),

    ConflictRule(
        name="frag_with_connect_scan",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-f", "--mtu") and _has_flag(cmd, "-sT")
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: Packet fragmentation ('-f' / '--mtu') is incompatible "
            "with TCP Connect scan ('-sT') because connect scans use OS sockets, "
            "not raw packets.  Fragmentation flags have been removed."
        ),
        fix=lambda cmd: _remove_flags(cmd, "-f", "--mtu"),
    ),

    ConflictRule(
        name="conflicting_scan_types",
        # -sS and -sT together: keep the last one nmap would honour (first wins
        # in nmap, so we drop the second).  We detect the pair and drop -sT.
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sS") and _has_flag(cmd, "-sT")
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '-sS' (SYN stealth) and '-sT' (TCP connect) cannot "
            "both be active.  '-sT' has been removed; SYN scan will be used."
        ),
        fix=lambda cmd: _remove_flags(cmd, "-sT"),
    ),

    ConflictRule(
        name="top_ports_with_p_flag",
        # --top-ports N and -p <range> are mutually exclusive; nmap uses the
        # last-specified, but it's almost always a mistake.  Drop --top-ports.
        check=lambda cmd, target, ports, root: (
            "--top-ports" in cmd and _has_flag(cmd, "-p", "-p-", "-F")
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '--top-ports' and an explicit port range ('-p'/'-F'/'-p-') "
            "are mutually exclusive.  '--top-ports' and its value have been removed; "
            "the explicit port range will be used."
        ),
        fix=lambda cmd: _remove_flags(cmd, "--top-ports"),
    ),

    ConflictRule(
        name="no_ping_with_ping_only",
        # -Pn (skip host discovery) combined with -sn (host-discovery only) is
        # contradictory.  Drop -Pn.
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-Pn") and _has_flag(cmd, "-sn")
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '-Pn' (skip host discovery) combined with '-sn' "
            "(host-discovery only scan) is contradictory.  '-Pn' has been removed."
        ),
        fix=lambda cmd: _remove_flags(cmd, "-Pn"),
    ),

    ConflictRule(
        name="aggressive_subsumes_sv_sc_o",
        # -A already implies -sV, -sC, and -O.  Having them separately is
        # harmless but pollutes the command and confuses users.
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-A") and bool(_flags(cmd) & {"-sV", "-sC", "-O"})
        ),
        severity="auto_fix",
        message=lambda cmd, target, ports, root: (
            "[!] AUTO-FIX: '-A' already enables "
            + ", ".join(sorted(_flags(cmd) & {"-sV", "-sC", "-O"}))
            + ".  Redundant flags removed."
        ),
        fix=lambda cmd: _remove_flags(cmd, "-sV", "-sC", "-O"),
    ),

    # ── Warn-only rules (advisory — no mutation) ─────────────────────────────

    ConflictRule(
        name="dns_brute_needs_domain",
        check=lambda cmd, target, ports, root: (
            _has_script(cmd, "dns-brute") and _is_ip_or_localhost(target)
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            f"[!] SCRIPT WARNING: 'dns-brute' enumerates DNS subdomains and "
            f"requires a domain name target, not an IP address or 'localhost' "
            f"(got '{target}').  The script will likely produce no results."
        ),
    ),

    ConflictRule(
        name="raw_socket_without_root",
        check=lambda cmd, target, ports, root: (
            not root and bool(_RAW_SOCKET_FLAGS & _flags(cmd))
        ),
        severity="error",
        message=lambda cmd, target, ports, root: (
            "[✖] ERROR: "
            + ", ".join(sorted(_RAW_SOCKET_FLAGS & _flags(cmd)))
            + " require root / Administrator privileges.  This scan is blocked. "
            "Run RedScan with elevated privileges or choose a non-raw scan profile."
        ),
    ),

    ConflictRule(
        name="udp_allports_very_slow",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sU") and _has_flag(cmd, "-p-")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] PERFORMANCE WARNING: '-sU -p-' (UDP scan of all 65 535 ports) is "
            "extremely slow and may take hours.  Consider limiting to the most "
            "common UDP ports with '--top-ports 200' instead."
        ),
    ),

    ConflictRule(
        name="udp_tcp_combined_slow",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sU") and _has_flag(cmd, "-sS", "-sT", "-sA", "-sW")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] PERFORMANCE WARNING: Combining UDP scan ('-sU') with a TCP scan type "
            "is significantly slower because nmap must run both scan phases.  Expect "
            "the scan to take at least 2× as long."
        ),
    ),

    ConflictRule(
        name="stealth_defeated_by_aggressive_timing",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sX", "-sN", "-sF", "-sI") and _has_flag(cmd, "-T5")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] EVASION WARNING: '-T5' (insane timing) combined with a stealth "
            "scan type ('-sX'/'-sN'/'-sF'/'-sI') sends packets so fast that IDS "
            "systems will easily detect the scan.  Use -T1 or -T2 for real evasion."
        ),
    ),

    ConflictRule(
        name="os_detect_without_root",
        check=lambda cmd, target, ports, root: (
            not root and _has_flag(cmd, "-O")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] PRIVILEGE WARNING: OS fingerprinting ('-O') requires raw-socket "
            "access (root / Administrator).  The option will be silently ignored by nmap."
        ),
    ),

    ConflictRule(
        name="script_with_host_discovery_only",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sn") and "--script" in cmd
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] SCRIPT WARNING: NSE scripts that probe services (e.g. http-*, smb-*) "
            "will not work with '-sn' because there is no port-scan phase to find "
            "open ports.  Only host-level scripts (e.g. 'broadcast-*', 'nbstat') "
            "will run successfully."
        ),
    ),

    ConflictRule(
        name="decoy_with_connect_scan",
        check=lambda cmd, target, ports, root: (
            "-D" in cmd and _has_flag(cmd, "-sT")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] EVASION WARNING: Decoy scanning ('-D') only works with raw-packet "
            "scan types (e.g. -sS).  A TCP Connect scan ('-sT') completes the full "
            "three-way handshake from the real IP — decoys are not used and your IP "
            "will be visible in target logs."
        ),
    ),

    ConflictRule(
        name="script_needs_port_scan",
        # NSE scripts that probe service-level ports (http-*, smb-*, ftp-*, ssh-*)
        # are useless without a port-scan phase.  Warn if -sn is combined with them.
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sn") and _has_script(cmd, "http-", "smb-", "ftp-", "ssh-",
                                                   "mysql-", "ms-sql-", "rdp-", "irc-")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] SCRIPT WARNING: Service-level NSE scripts (http-*, smb-*, ftp-*, …) "
            "require open ports discovered by a port-scan phase.  '-sn' disables port "
            "scanning so these scripts will not run.  Remove '-sn' or switch to a "
            "service-probing scan type."
        ),
    ),

    ConflictRule(
        name="brute_needs_service_port",
        # Brute-force scripts need a target port — if only -sn is set there's
        # nothing to brute-force.
        check=lambda cmd, target, ports, root: (
            _has_script(cmd, "brute") and _has_flag(cmd, "-sn")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] BRUTE-FORCE WARNING: Brute-force NSE scripts need a service port to "
            "connect to.  '-sn' disables port scanning so no ports will be found and "
            "the brute-force scripts will not execute."
        ),
    ),

    ConflictRule(
        name="localhost_vuln_scan",
        check=lambda cmd, target, ports, root: (
            _has_script(cmd, "vuln")
            and target in ("127.0.0.1", "localhost")
        ),
        severity="info",
        message=lambda cmd, target, ports, root: (
            "[i] INFO: Running a 'vuln' category NSE sweep against localhost "
            "(127.0.0.1).  This audits the local machine — ensure you have "
            "permission to run vulnerability checks on this host."
        ),
    ),

    ConflictRule(
        name="aggressive_timing_with_brute",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-T5") and _has_script(cmd, "brute")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] BRUTE-FORCE WARNING: '-T5' with brute-force NSE scripts causes "
            "very rapid login attempts that will almost certainly trigger account "
            "lockouts.  Use -T3 or lower for brute-force operations."
        ),
    ),

    ConflictRule(
        name="version_intensity_without_sv",
        # --version-intensity is only meaningful when -sV is active.
        check=lambda cmd, target, ports, root: (
            "--version-intensity" in cmd and not _has_flag(cmd, "-sV", "-A")
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] CONFIGURATION WARNING: '--version-intensity' has no effect without "
            "'-sV' or '-A'.  Add version detection or remove the flag."
        ),
    ),

    ConflictRule(
        name="min_rate_high_stealth",
        # --min-rate with very high values defeats stealth scan strategies.
        check=lambda cmd, target, ports, root: (
            "--min-rate" in cmd
            and _has_flag(cmd, "-sX", "-sN", "-sF")
            and any(
                tok.isdigit() and int(tok) > 500
                for i, tok in enumerate(cmd)
                if i > 0 and cmd[i - 1] == "--min-rate"
            )
        ),
        severity="warning",
        message=lambda cmd, target, ports, root: (
            "[!] EVASION WARNING: '--min-rate' with a high value defeats the purpose "
            "of stealth scan types (-sX/-sN/-sF) by generating easily detectable "
            "traffic bursts.  Remove '--min-rate' or reduce it below 100 pps."
        ),
    ),

    # ── Error rules (scan is blocked until the user corrects the command) ────

    ConflictRule(
        name="idle_scan_placeholder_zombie",
        check=lambda cmd, target, ports, root: (
            _has_flag(cmd, "-sI") and any(
                t in ("zombie_host", "zombie", "<zombie>", "ZOMBIE_HOST")
                for t in cmd
            )
        ),
        severity="error",
        message=lambda cmd, target, ports, root: (
            "[✖] ERROR: Idle scan ('-sI') requires a real zombie host IP but the "
            "placeholder value was not replaced.  Update the command with a real "
            "zombie host before running."
        ),
    ),

    ConflictRule(
        name="brute_force_on_localhost_lockout_risk",
        check=lambda cmd, target, ports, root: (
            _has_script(cmd, "brute")
            and target in ("127.0.0.1", "localhost")
            and _has_flag(cmd, "-T4", "-T5")
        ),
        severity="error",
        message=lambda cmd, target, ports, root: (
            "[✖] ERROR: Running brute-force NSE scripts against localhost with "
            "aggressive timing (-T4/-T5) is very likely to lock out local system "
            "accounts.  Switch to -T3 or lower, or choose a non-localhost target."
        ),
    ),
]


# ---------------------------------------------------------------------------
# ConflictManager
# ---------------------------------------------------------------------------

class ConflictManager:
    """Evaluates all conflict rules against a proposed nmap command.

    Parameters
    ----------
    rules:
        Rule list to use.  Defaults to ``DEFAULT_RULES``.
    disabled_rules:
        Optional set of rule *names* to skip during evaluation.  Useful for
        the GUI rule editor which lets users temporarily mute specific rules.
    """

    def __init__(
        self,
        rules: list[ConflictRule] | None = None,
        disabled_rules: set[str] | None = None,
    ) -> None:
        self._rules = rules if rules is not None else DEFAULT_RULES
        self._disabled: set[str] = set(disabled_rules) if disabled_rules else set()

    def apply(
        self,
        cmd: list[str],
        target: str,
        ports_str: str,
        is_root: bool | None = None,
    ) -> tuple[list[str], list[_INFO]]:
        """Apply all rules to *cmd*.

        Parameters
        ----------
        cmd:
            The nmap command list (``["nmap", ...]``).  **Will not be mutated**;
            a new list is returned.
        target:
            The scan target string (IP, hostname, or CIDR).
        ports_str:
            The ports field value (e.g. ``"1-1024"`` or ``""``).
        is_root:
            Override the privilege check.  When ``None`` (default) the current
            process effective UID is used (POSIX only).

        Returns
        -------
        clean_cmd:
            Possibly modified command list with auto-fixes applied.
            *Note*: if any ``error``-severity rule fires, the command is
            returned unchanged — callers should inspect the messages and block
            the scan.
        messages:
            List of ``(severity, text)`` tuples for every triggered rule.
        """
        if is_root is None:
            try:
                is_root = os.geteuid() == 0
            except AttributeError:
                is_root = True  # Windows — assume privileged

        clean_cmd: list[str] = list(cmd)
        messages: list[_INFO] = []

        for rule in self._rules:
            if rule.name in self._disabled:
                continue
            if rule.check(clean_cmd, target, ports_str, is_root):
                msg = rule.message(clean_cmd, target, ports_str, is_root)
                messages.append((rule.severity, msg))
                if rule.severity == "auto_fix" and rule.fix is not None:
                    clean_cmd = list(rule.fix(clean_cmd))

        return clean_cmd, messages

    @staticmethod
    def has_errors(messages: list[_INFO]) -> bool:
        """Return True if any *messages* entry has ``severity == "error"``."""
        return any(sev == "error" for sev, _ in messages)

    @staticmethod
    def needs_ports_input(cmd: list[str]) -> bool:
        """Return True when the external port-entry widget should be *enabled*.

        Port input must be **disabled** when:
        - '-sn' (ping-only / no-port-scan) is present — ports are irrelevant.
        - '-p-' is present — all 65 535 ports are already scanned.
        - '-F'  is present — top-100 ports are already fixed.
        - '--top-ports' is present — port count already embedded.

        In all other cases the user should be allowed to specify a port range.
        """
        flags = set(cmd)
        if flags & _NO_PORT_SCAN_FLAGS:
            return False
        if flags & _SELF_PORTING_FLAGS:
            return False
        return True

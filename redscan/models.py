from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    host: str
    port: int = Field(ge=1, le=65535)


ProbeType = Literal["tcp_connect", "udp", "icmp", "tcp_syn"]


class ProbeResult(BaseModel):
    endpoint: Endpoint
    status: Literal["open", "closed", "timeout", "error"]
    rtt_ms: float | None = None
    error: str | None = None


class DiscoveryConfig(BaseModel):
    calibration_host: str = "127.0.0.1"
    calibration_port: int = 22
    calibration_ratio: int = Field(default=256, ge=1)
    connect_timeout_s: float = Field(default=0.6, gt=0)
    control_interval_s: float = Field(default=1.0, gt=0)
    ewma_alpha: float = Field(default=0.2, gt=0, le=1)
    target_delta_ms: float = Field(default=3.0, ge=0)
    kp: float = 0.04
    ki: float = 0.008
    kd: float = 0.01
    r_min: float = Field(default=10.0, gt=0)
    r_max: float = Field(default=2000.0, gt=0)
    initial_rate: float = Field(default=120.0, gt=0)
    loss_window_s: float = Field(default=10.0, gt=0)
    loss_threshold: int = Field(default=2, ge=1)
    aimd_beta: float = Field(default=0.5, gt=0, lt=1)
    # Number of calibration samples collected before RTT_base is locked in.
    # Prevents the first (often elevated) sample from setting an artificially
    # high baseline that allows the scanner to run too fast before it has
    # meaningful RTT data.
    rtt_base_warmup_samples: int = Field(default=5, ge=1)
    # Probe-type selection.  tcp_connect works without root; udp/icmp/tcp_syn
    # require elevated privileges on most operating systems.
    probe_type: ProbeType = "tcp_connect"
    # When True the engine attempts to split probe packets into small IP
    # fragments (evasion technique).  Silently ignored for tcp_connect / icmp
    # probe types and when running without root.
    fragmented: bool = False

    # ── Enhancement features ──────────────────────────────────────────────────

    # Run a fast ICMP ping sweep before port probing to skip offline hosts.
    # This reduces wasted probes against hosts that are simply down.
    host_prefilter: bool = False

    # Reorder ports so those most frequently seen open in past scans are
    # probed first.  Requires redscan.history to have prior scan data.
    adaptive_port_ordering: bool = True

    # Path to write/read a scan-progress checkpoint JSON file.  Set to a
    # non-empty string to enable crash-recovery; the file is removed on clean
    # completion.  Default None = disabled.
    checkpoint_path: str | None = None

    # Optional DNS server (e.g. "1.1.1.1") used when resolving hostnames
    # before probing.  None = use the system resolver.
    dns_server: str | None = None

    # Calibration policy: when True, only SYN-ACK/open calibration replies are
    # accepted as RTT samples (paper-aligned assumption of known-open endpoint).
    # Set False to also accept RST/closed replies in constrained environments.
    calibration_requires_open: bool = True


class DiscoveryStats(BaseModel):
    open_count: int = 0
    timeout_count: int = 0
    closed_count: int = 0
    error_count: int = 0
    total_count: int = 0
    final_rate: float
    calibration_rtt_base_ms: float | None = None
    calibration_rtt_filtered_ms: float | None = None


class DiscoveryOutput(BaseModel):
    open_endpoints: list[Endpoint]
    all_results: list[ProbeResult]
    stats: DiscoveryStats


class PresetScanConfig(BaseModel):
    name: str
    description: str
    flags: list[str] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    script_args: list[str] = Field(default_factory=list)
    requires_ports: bool = False


class CommandBuildRequest(BaseModel):
    target: str
    preset: PresetScanConfig
    ports: list[int] = Field(default_factory=list)
    timing: str | None = None


class CommandBuildResult(BaseModel):
    command: list[str]
    command_str: str
    graph_nodes: list[str]


class ParsedRuntimeEvent(BaseModel):
    kind: Literal["line", "open_port", "done"]
    raw: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class LLMAnalysisRequest(BaseModel):
    target: str
    open_endpoints: list[Endpoint] = Field(default_factory=list)
    runtime_findings: list[dict[str, Any]] = Field(default_factory=list)
    nmap_command: str = ""


class LLMAnalysisResult(BaseModel):
    provider: str
    summary: str
    risk_level: Literal["low", "medium", "high"]
    recommendations: list[str]


class ScanRequest(BaseModel):
    target_hosts: list[str] = Field(min_length=1)
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443])
    calibration_endpoint: Endpoint = Field(default_factory=lambda: Endpoint(host="127.0.0.1", port=22))
    preset_key: str = "safe_discovery"


class ScanResponse(BaseModel):
    discovery: DiscoveryOutput
    command: CommandBuildResult
    analysis: LLMAnalysisResult


class ScanHistoryEntry(BaseModel):
    scan_id: str
    timestamp: str
    target_hosts: list[str]
    preset_key: str
    open_count: int
    command_str: str
    risk_level: str

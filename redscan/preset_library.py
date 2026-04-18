"""
Comprehensive preset library: 25+ named scanning profiles across 6 categories.
Each preset is a dict compatible with the existing PRESETS format in scan.py and
can also be converted to PresetScanConfig for the backend orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScanPreset:
    key: str
    name: str
    category: str
    description: str
    flags: list[str]
    scripts: list[str]
    script_args: list[str]
    aggressiveness: str
    requires_root: bool = False
    requires_ports: bool = False

    def as_scan_data(self, output_xml: str = "temp_scan_results.xml") -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "flags": list(self.flags),
            "scripts": list(self.scripts),
            "script_args": list(self.script_args),
            "aggressiveness": self.aggressiveness,
            "requires_ports": self.requires_ports,
            "output_xml": output_xml,
        }


# ---------------------------------------------------------------------------
# Full preset catalogue
# ---------------------------------------------------------------------------

PRESET_CATALOGUE: list[ScanPreset] = [
    # ── Category 1: Host Discovery ──────────────────────────────────────────
    ScanPreset(
        key="ping_sweep",
        name="Ping Sweep",
        category="Host Discovery",
        description="Identifies live hosts with ICMP echo without port scanning.",
        flags=["-sn", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="arp_discovery",
        name="ARP Local Discovery",
        category="Host Discovery",
        description="ARP-based host discovery on local subnets. Fastest and most reliable for LAN.",
        flags=["-sn", "-PR", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
    ),
    ScanPreset(
        key="tcp_syn_ping",
        name="TCP SYN Ping Discovery",
        category="Host Discovery",
        description="Host discovery via TCP SYN probes to port 80/443.",
        flags=["-sn", "-PS80,443", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
    ),
    ScanPreset(
        key="udp_ping",
        name="UDP Ping Discovery",
        category="Host Discovery",
        description="Host discovery by sending UDP probes to detect ICMP port-unreachable responses.",
        flags=["-sn", "-PU", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
    ),
    ScanPreset(
        key="no_ping_discovery",
        name="No-Ping Scan (Firewall Bypass)",
        category="Host Discovery",
        description="Treats all hosts as live regardless of ping response. Bypasses ICMP-blocking firewalls.",
        flags=["-Pn", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
    ),

    # ── Category 2: Port Scanning ────────────────────────────────────────────
    ScanPreset(
        key="syn_stealth",
        name="SYN Stealth Scan",
        category="Port Scanning",
        description="Half-open TCP scan. Fast and less likely to appear in application logs.",
        flags=["-sS", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="full_connect",
        name="Full TCP Connect Scan",
        category="Port Scanning",
        description="Full three-way handshake. Works without root. More visible in logs.",
        flags=["-sT", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_ports=True,
    ),
    ScanPreset(
        key="udp_scan",
        name="UDP Port Scan",
        category="Port Scanning",
        description="Scans UDP ports. Slower than TCP but discovers DNS, SNMP, DHCP, etc.",
        flags=["-sU", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="High",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="top100",
        name="Top 100 Fast Sweep",
        category="Port Scanning",
        description="Scans the 100 most commonly open ports. Quick high-level surface map.",
        flags=["-F", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="High",
    ),
    ScanPreset(
        key="all_ports",
        name="All 65 535 TCP Ports",
        category="Port Scanning",
        description="Exhaustive TCP scan across the entire port range. Slow but thorough.",
        flags=["-p-", "-T3"],
        scripts=[], script_args=[],
        aggressiveness="High",
    ),

    # ── Category 3: Service & Version Detection ─────────────────────────────
    ScanPreset(
        key="version_detect",
        name="Service Version Detection",
        category="Service Enumeration",
        description="Probes open ports to detect service names and version strings.",
        flags=["-sV", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_ports=True,
    ),
    ScanPreset(
        key="os_detect",
        name="OS Fingerprinting",
        category="Service Enumeration",
        description="Uses TCP/IP stack analysis to guess the remote OS.",
        flags=["-O", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="aggressive_full",
        name="Full TCP Surface Map",
        category="Service Enumeration",
        description="All ports, OS, version, and default scripts. Thorough but loud.",
        flags=["-p-", "-sV", "-O", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="High",
        requires_root=True,
    ),
    ScanPreset(
        key="banner_grab",
        name="Deep Banner Grab",
        category="Service Enumeration",
        description="Maximum version-detection intensity to extract full service banners.",
        flags=["-sV", "--version-intensity", "9", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="High",
        requires_ports=True,
    ),
    ScanPreset(
        key="kitchen_sink",
        name="Kitchen Sink (Aggressive)",
        category="Service Enumeration",
        description="Enables OS, version, scripts, and traceroute in one aggressive sweep.",
        flags=["-A", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Extreme",
        requires_root=True,
        requires_ports=True,
    ),

    # ── Category 4: Vulnerability Scanning ──────────────────────────────────
    ScanPreset(
        key="default_scripts",
        name="Default NSE Scripts",
        category="Vulnerability Scanning",
        description="Runs Nmap's default safe script collection against open ports.",
        flags=["-sC", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_ports=True,
    ),
    ScanPreset(
        key="vuln_scripts",
        name="Vuln Category NSE Sweep",
        category="Vulnerability Scanning",
        description="Runs all scripts in the 'vuln' category. May trigger IDS alerts.",
        flags=["-T4"],
        scripts=["vuln"], script_args=[],
        aggressiveness="High",
        requires_ports=True,
    ),
    ScanPreset(
        key="smb_vuln",
        name="SMB / EternalBlue Audit",
        category="Vulnerability Scanning",
        description="Checks SMB for MS17-010 (EternalBlue) and related protocol weaknesses.",
        flags=["-p", "139,445"],
        scripts=["smb-protocols", "smb-vuln-ms17-010", "smb-vuln-cve-2017-7494"],
        script_args=["unsafe=1"],
        aggressiveness="High",
    ),
    ScanPreset(
        key="http_enum",
        name="HTTP Directory Enumeration",
        category="Vulnerability Scanning",
        description="Brute-forces common web directories on HTTP/HTTPS services.",
        flags=["-p", "80,443,8080,8443"],
        scripts=["http-enum", "http-methods"],
        script_args=[],
        aggressiveness="High",
    ),
    ScanPreset(
        key="cve_vulners",
        name="CPE-to-CVE Fingerprinting",
        category="Vulnerability Scanning",
        description="Forces maximum version detection and queries CVE databases via vulners NSE.",
        flags=["-sV", "--version-all"],
        scripts=["vulners"], script_args=["vulners.mincvss=7.0"],
        aggressiveness="High",
        requires_ports=True,
    ),

    # ── Category 5: Stealth & Evasion ────────────────────────────────────────
    ScanPreset(
        key="frag_mtu",
        name="TCP Fragmentation (MTU)",
        category="Stealth & Evasion",
        description="Fragments TCP headers to evade deep packet inspection and legacy IDS.",
        flags=["-f", "--mtu", "24", "--data-length", "15", "-T2"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="xmas_scan",
        name="Xmas Tree Scan",
        category="Stealth & Evasion",
        description="Sets FIN, PSH, and URG flags. Bypasses stateless firewalls blocking SYN.",
        flags=["-sX", "--reason", "-T2"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="null_scan",
        name="NULL Scan",
        category="Stealth & Evasion",
        description="No TCP flags set. Evades some packet filters; open ports show no response.",
        flags=["-sN", "--reason", "-T2"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="decoy_scan",
        name="Decoy Source Spoof",
        category="Stealth & Evasion",
        description="Mixes real SYN probes with forged decoy IPs to obscure scanner origin.",
        flags=["-sS", "-D", "RND:10", "-T3"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        requires_ports=True,
    ),

    # ── Category 6: Service-Specific ────────────────────────────────────────
    ScanPreset(
        key="dns_brute",
        name="DNS Subdomain Brute-Force",
        category="Service-Specific",
        description="Enumerates DNS subdomains via brute-force. Requires a domain target.",
        flags=["-T4"],
        scripts=["dns-brute"], script_args=["dns-brute.threads=10"],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="ftp_anon",
        name="FTP Anonymous Login Check",
        category="Service-Specific",
        description="Checks FTP for anonymous login and writable directories.",
        flags=["-p", "21"],
        scripts=["ftp-anon", "ftp-bounce", "ftp-syst"],
        script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="database_scan",
        name="Database Port Scan",
        category="Service-Specific",
        description="Scans common database ports: MySQL, PostgreSQL, MSSQL, Oracle.",
        flags=["-p", "3306,5432,1433,1521,27017,6379"],
        scripts=["mysql-info", "ms-sql-info"], script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="ssh_audit",
        name="SSH Audit",
        category="Service-Specific",
        description="Checks SSH host keys, supported algorithms and known weak configurations.",
        flags=["-p", "22"],
        scripts=["ssh-hostkey", "ssh2-enum-algos", "ssh-auth-methods"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="snmp_sweep",
        name="SNMP Community String Sweep",
        category="Service-Specific",
        description="Tests default SNMP community strings ('public', 'private').",
        flags=["-sU", "-p", "161"],
        scripts=["snmp-info", "snmp-brute"],
        script_args=[],
        aggressiveness="High",
        requires_root=True,
    ),
]


def get_by_category() -> dict[str, list[ScanPreset]]:
    """Return presets grouped by category, preserving insertion order."""
    groups: dict[str, list[ScanPreset]] = {}
    for preset in PRESET_CATALOGUE:
        groups.setdefault(preset.category, []).append(preset)
    return groups


def get_by_key(key: str) -> ScanPreset | None:
    for p in PRESET_CATALOGUE:
        if p.key == key:
            return p
    return None


AGGRESSIVENESS_COLOR: dict[str, str] = {
    "Low": "#2ecc71",
    "Medium": "#f39c12",
    "High": "#e74c3c",
    "Extreme": "#8e44ad",
}

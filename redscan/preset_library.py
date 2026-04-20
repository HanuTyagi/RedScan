"""
Comprehensive preset library: 80+ named scanning profiles across 9 categories.

Each preset is a frozen dataclass that:
  - carries a *primary* ``category`` for sorting/display purposes
  - optionally lists *extra* ``extra_categories`` so the same scan can appear
    under more than one category heading (e.g. an SMB vuln scan appears under
    both "Vulnerability Scanning" and "Service-Specific")
  - flags ``requires_root`` / ``no_port_scan`` / ``requires_domain`` to feed
    the dynamic conflict manager in ``redscan.conflict_manager``
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScanPreset:
    key: str
    name: str
    # Primary category (shown first, used for sorting)
    category: str
    description: str
    flags: list[str]
    scripts: list[str]
    script_args: list[str]
    aggressiveness: str
    requires_root: bool = False
    requires_ports: bool = False
    # Extra categories this preset should also appear in (cross-category)
    extra_categories: list[str] = field(default_factory=list)
    # Semantic hints consumed by the conflict manager
    no_port_scan: bool = False      # preset uses -sn / similar (host-discovery only)
    requires_domain: bool = False   # preset needs a DNS domain, not a bare IP

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

    @property
    def all_categories(self) -> list[str]:
        """Primary category first, then any extras (deduplicated, order preserved)."""
        seen: set[str] = set()
        result: list[str] = []
        for cat in [self.category] + list(self.extra_categories):
            if cat not in seen:
                seen.add(cat)
                result.append(cat)
        return result


# ---------------------------------------------------------------------------
# Full preset catalogue
# ---------------------------------------------------------------------------

PRESET_CATALOGUE: list[ScanPreset] = [

    # ════════════════════════════════════════════════════════════════════════
    # Category 1 – Host Discovery
    # ════════════════════════════════════════════════════════════════════════
    ScanPreset(
        key="ping_sweep",
        name="Ping Sweep",
        category="Host Discovery",
        description="Identifies live hosts with ICMP echo without port scanning.",
        flags=["-sn", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        no_port_scan=True,
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
        no_port_scan=True,
    ),
    ScanPreset(
        key="tcp_syn_ping",
        name="TCP SYN Ping Discovery",
        category="Host Discovery",
        description="Host discovery via TCP SYN probes to ports 80 and 443.",
        flags=["-sn", "-PS80,443", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
        no_port_scan=True,
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
        no_port_scan=True,
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
    ScanPreset(
        key="netbios_discovery",
        name="NetBIOS Host Discovery",
        category="Host Discovery",
        description="Discovers Windows hosts on LAN by querying NetBIOS name service.",
        flags=["-sn"],
        scripts=["nbstat"],
        script_args=[],
        aggressiveness="Low",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="broadcast_discovery",
        name="Broadcast Ping Discovery",
        category="Host Discovery",
        description="Sends ICMP echo to broadcast addresses to enumerate all live hosts on segment.",
        flags=["-sn", "--send-ip", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        no_port_scan=True,
    ),
    ScanPreset(
        key="sctp_ping",
        name="SCTP INIT Ping",
        category="Host Discovery",
        description="SCTP INIT packet used for host discovery — useful on telecom networks.",
        flags=["-sn", "-PY80", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
        no_port_scan=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 2 – Port Scanning
    # ════════════════════════════════════════════════════════════════════════
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
    ScanPreset(
        key="top1000_udp",
        name="Top 1000 UDP Ports",
        category="Port Scanning",
        description="Scans the 1 000 most common UDP ports. Balanced UDP surface scan.",
        flags=["--top-ports", "1000", "-sU", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="High",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="fin_scan",
        name="FIN Scan",
        category="Port Scanning",
        description="Sends only TCP FIN packets. Works past simple SYN-based filters.",
        flags=["-sF", "--reason", "-T3"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
        requires_ports=True,
        extra_categories=["Stealth & Evasion"],
    ),
    ScanPreset(
        key="ack_scan",
        name="TCP ACK Scan (Firewall Mapping)",
        category="Port Scanning",
        description="Maps firewall rules by sending ACK probes — does not detect open/closed, only filtered.",
        flags=["-sA", "--reason", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="window_scan",
        name="TCP Window Scan",
        category="Port Scanning",
        description="ACK variant that distinguishes open/closed via TCP window size field.",
        flags=["-sW", "--reason", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="sctp_init_scan",
        name="SCTP INIT Scan",
        category="Port Scanning",
        description="SCTP equivalent of the SYN scan for telecom/SS7 infrastructure.",
        flags=["-sY", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="ip_proto_scan",
        name="IP Protocol Scan",
        category="Port Scanning",
        description="Iterates over IP protocol numbers to discover which protocols the host supports.",
        flags=["-sO", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 3 – Service Enumeration
    # ════════════════════════════════════════════════════════════════════════
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
        description="Enables OS detection, version scanning, default scripts, and traceroute in one sweep.",
        flags=["-A", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="Extreme",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="traceroute_enum",
        name="Traceroute + Service Map",
        category="Service Enumeration",
        description="Combines hop-by-hop traceroute with OS and version detection.",
        flags=["--traceroute", "-sV", "-O", "-T4"],
        scripts=[], script_args=[],
        aggressiveness="High",
        requires_root=True,
    ),
    ScanPreset(
        key="rpc_enum",
        name="RPC Service Enumeration",
        category="Service Enumeration",
        description="Enumerates remote procedure call services via the portmapper.",
        flags=["-sV", "-p", "111"],
        scripts=["rpcinfo"],
        script_args=[],
        aggressiveness="Medium",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="upnp_enum",
        name="UPnP Device Enumeration",
        category="Service Enumeration",
        description="Discovers UPnP devices on the local network and dumps their service descriptions.",
        flags=["-p", "1900"],
        scripts=["upnp-info", "broadcast-upnp-info"],
        script_args=[],
        aggressiveness="Low",
        extra_categories=["Network Infrastructure"],
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 4 – Vulnerability Scanning
    # ════════════════════════════════════════════════════════════════════════
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
        extra_categories=["Service-Specific"],
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
        extra_categories=["Web Application"],
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
    ScanPreset(
        key="ssl_heartbleed",
        name="SSL Heartbleed Test",
        category="Vulnerability Scanning",
        description="Checks for CVE-2014-0160 (Heartbleed) on SSL/TLS services.",
        flags=["-p", "443,8443,465,993,995"],
        scripts=["ssl-heartbleed"],
        script_args=[],
        aggressiveness="High",
        extra_categories=["Web Application"],
    ),
    ScanPreset(
        key="ssl_poodle",
        name="SSL POODLE / DROWN Check",
        category="Vulnerability Scanning",
        description="Checks for SSLv3 POODLE and related SSL downgrade vulnerabilities.",
        flags=["-p", "443,8443"],
        scripts=["ssl-poodle", "ssl-dh-params"],
        script_args=[],
        aggressiveness="Medium",
        extra_categories=["Web Application"],
    ),
    ScanPreset(
        key="ssl_cipher_audit",
        name="TLS Cipher Suite Audit",
        category="Vulnerability Scanning",
        description="Enumerates all accepted TLS versions and cipher suites to identify weak cryptography.",
        flags=["-p", "443,8443,465,993,995"],
        scripts=["ssl-enum-ciphers"],
        script_args=[],
        aggressiveness="Medium",
        extra_categories=["Web Application"],
    ),
    ScanPreset(
        key="ms17_010",
        name="MS17-010 (EternalBlue) Only",
        category="Vulnerability Scanning",
        description="Targeted single-script check for the EternalBlue SMB RCE vulnerability.",
        flags=["-p", "445"],
        scripts=["smb-vuln-ms17-010"],
        script_args=["unsafe=1"],
        aggressiveness="High",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="log4shell_check",
        name="Log4Shell (CVE-2021-44228) Probe",
        category="Vulnerability Scanning",
        description="Probes HTTP services for Log4Shell JNDI injection via NSE.",
        flags=["-p", "80,443,8080,8443,8888"],
        scripts=["http-log4shell"],
        script_args=[],
        aggressiveness="High",
        extra_categories=["Web Application"],
    ),
    ScanPreset(
        key="rdp_vuln",
        name="RDP BlueKeep / DejaBlue Check",
        category="Vulnerability Scanning",
        description="Checks for MS CVE-2019-0708 (BlueKeep) and related RDP pre-auth RCE flaws.",
        flags=["-p", "3389"],
        scripts=["rdp-vuln-ms12-020", "rdp-enum-encryption"],
        script_args=[],
        aggressiveness="High",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="smb_ms08_067",
        name="MS08-067 (Conficker) SMB Check",
        category="Vulnerability Scanning",
        description="Checks for the classic MS08-067 SMB NetAPI vulnerability (used by Conficker worm).",
        flags=["-p", "139,445"],
        scripts=["smb-vuln-ms08-067"],
        script_args=["unsafe=1"],
        aggressiveness="High",
        extra_categories=["Service-Specific"],
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 5 – Stealth & Evasion
    # ════════════════════════════════════════════════════════════════════════
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
    ScanPreset(
        key="idle_zombie",
        name="Idle / Zombie Scan",
        category="Stealth & Evasion",
        description="Uses a zombie host's IP ID sequence to perform a truly blind port scan.",
        flags=["-sI", "zombie_host", "-T2"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="randomize_hosts",
        name="Randomised Host Order",
        category="Stealth & Evasion",
        description="Randomises the target scan order to reduce sequential IDS signature matching.",
        flags=["--randomize-hosts", "-sS", "-T3"],
        scripts=[], script_args=[],
        aggressiveness="Medium",
        requires_root=True,
    ),
    ScanPreset(
        key="timing_paranoid",
        name="Paranoid Timing (T0)",
        category="Stealth & Evasion",
        description="Slowest possible scan — one probe every 5 minutes. Bypasses most rate-based IDS.",
        flags=["-T0", "-sS"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
        requires_ports=True,
    ),
    ScanPreset(
        key="bad_checksum",
        name="Bad TCP/UDP Checksum Probe",
        category="Stealth & Evasion",
        description="Sends packets with invalid checksums to fingerprint how the target handles malformed packets.",
        flags=["--badsum", "-T3"],
        scripts=[], script_args=[],
        aggressiveness="Low",
        requires_root=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 6 – Service-Specific
    # ════════════════════════════════════════════════════════════════════════
    ScanPreset(
        key="dns_brute",
        name="DNS Subdomain Brute-Force",
        category="Service-Specific",
        description="Enumerates DNS subdomains via brute-force. Requires a domain target (not an IP).",
        flags=["-T4"],
        scripts=["dns-brute"], script_args=["dns-brute.threads=10"],
        aggressiveness="Medium",
        requires_domain=True,
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
        description="Scans common database ports: MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB.",
        flags=["-p", "3306,5432,1433,1521,27017,6379"],
        scripts=["mysql-info", "ms-sql-info", "redis-info"],
        script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="ssh_audit",
        name="SSH Audit",
        category="Service-Specific",
        description="Checks SSH host keys, supported algorithms, and known weak configurations.",
        flags=["-p", "22"],
        scripts=["ssh-hostkey", "ssh2-enum-algos", "ssh-auth-methods"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="snmp_sweep",
        name="SNMP Community String Sweep",
        category="Service-Specific",
        description="Tests default SNMP community strings ('public', 'private') via UDP.",
        flags=["-sU", "-p", "161"],
        scripts=["snmp-info", "snmp-brute", "snmp-sysdescr"],
        script_args=[],
        aggressiveness="High",
        requires_root=True,
        extra_categories=["Network Infrastructure"],
    ),
    ScanPreset(
        key="smtp_enum",
        name="SMTP User Enumeration",
        category="Service-Specific",
        description="Checks SMTP VRFY/EXPN/RCPT to enumerate valid email accounts.",
        flags=["-p", "25,465,587"],
        scripts=["smtp-enum-users", "smtp-commands", "smtp-open-relay"],
        script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="ldap_enum",
        name="LDAP / Active Directory Enumeration",
        category="Service-Specific",
        description="Queries LDAP for base DN, supported extensions, and anonymous bind status.",
        flags=["-p", "389,636,3268,3269"],
        scripts=["ldap-rootdse", "ldap-search"],
        script_args=["ldap.base=\"\""],
        aggressiveness="Medium",
        extra_categories=["Authentication & Credentials"],
    ),
    ScanPreset(
        key="rdp_enum",
        name="RDP Enumeration",
        category="Service-Specific",
        description="Collects RDP security settings, NLA status, and supported encryption.",
        flags=["-p", "3389"],
        scripts=["rdp-enum-encryption"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="vnc_check",
        name="VNC Authentication Check",
        category="Service-Specific",
        description="Detects VNC services and checks for no-authentication or weak-auth configs.",
        flags=["-p", "5900,5901,5902"],
        scripts=["vnc-info", "vnc-auth-bypass"],
        script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="imap_pop3",
        name="IMAP / POP3 Audit",
        category="Service-Specific",
        description="Checks IMAP and POP3 for available capabilities and plaintext auth.",
        flags=["-p", "110,143,993,995"],
        scripts=["imap-capabilities", "pop3-capabilities"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="nfs_enum",
        name="NFS Share Enumeration",
        category="Service-Specific",
        description="Lists exported NFS shares and checks for world-readable mounts.",
        flags=["-p", "111,2049"],
        scripts=["rpcinfo", "nfs-ls", "nfs-showmount", "nfs-statfs"],
        script_args=[],
        aggressiveness="Medium",
        extra_categories=["Network Infrastructure"],
    ),
    ScanPreset(
        key="telnet_check",
        name="Telnet Service Detection",
        category="Service-Specific",
        description="Detects Telnet, collects the banner, and flags the use of a plaintext protocol.",
        flags=["-p", "23"],
        scripts=["telnet-ntlm-info", "banner"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="ike_scan",
        name="IPsec / IKE VPN Probe",
        category="Service-Specific",
        description="Discovers IKE/IPsec VPN endpoints and enumerates supported transforms.",
        flags=["-sU", "-p", "500,4500"],
        scripts=["ike-version"],
        script_args=[],
        aggressiveness="Medium",
        requires_root=True,
        extra_categories=["Network Infrastructure"],
    ),
    ScanPreset(
        key="bgp_open",
        name="BGP Router Detection",
        category="Service-Specific",
        description="Checks whether a BGP speaker is open and collects router information.",
        flags=["-p", "179"],
        scripts=["bgp-open"],
        script_args=[],
        aggressiveness="Medium",
        extra_categories=["Network Infrastructure"],
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 7 – Web Application
    # ════════════════════════════════════════════════════════════════════════
    ScanPreset(
        key="http_headers",
        name="HTTP Security Header Audit",
        category="Web Application",
        description="Examines HTTP response headers for missing security controls (CSP, HSTS, X-Frame-Options, etc.).",
        flags=["-p", "80,443,8080,8443"],
        scripts=["http-security-headers"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="http_title",
        name="Web Server Title & Info Grab",
        category="Web Application",
        description="Fetches the web server type, version, and page title from all HTTP/HTTPS ports.",
        flags=["-p", "80,443,8080,8443,8000,8888"],
        scripts=["http-title", "http-server-header"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="http_auth_finder",
        name="HTTP Auth Method Discovery",
        category="Web Application",
        description="Probes HTTP paths to discover authentication schemes (Basic, Digest, NTLM, etc.).",
        flags=["-p", "80,443,8080,8443"],
        scripts=["http-auth-finder", "http-auth"],
        script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="http_robots",
        name="robots.txt Crawler",
        category="Web Application",
        description="Retrieves and analyses robots.txt to find hidden or sensitive directory paths.",
        flags=["-p", "80,443,8080"],
        scripts=["http-robots.txt"],
        script_args=[],
        aggressiveness="Low",
    ),
    ScanPreset(
        key="http_sqli_detect",
        name="SQL Injection Probe",
        category="Web Application",
        description="Uses NSE http-sql-injection to probe for error-based SQLi in GET parameters.",
        flags=["-p", "80,443,8080"],
        scripts=["http-sql-injection"],
        script_args=[],
        aggressiveness="High",
    ),
    ScanPreset(
        key="http_xss_probe",
        name="Cross-Site Scripting (XSS) Probe",
        category="Web Application",
        description="Tests HTML forms for reflected XSS by injecting canary payloads via NSE.",
        flags=["-p", "80,443,8080"],
        scripts=["http-unsafe-output-escaping", "http-xssed"],
        script_args=[],
        aggressiveness="High",
    ),
    ScanPreset(
        key="http_shellshock",
        name="Shellshock (CVE-2014-6271) Test",
        category="Web Application",
        description="Tests CGI endpoints for the Bash Shellshock vulnerability via HTTP headers.",
        flags=["-p", "80,443,8080"],
        scripts=["http-shellshock"],
        script_args=["http-shellshock.uri=/cgi-bin/test.cgi"],
        aggressiveness="High",
        extra_categories=["Vulnerability Scanning"],
    ),
    ScanPreset(
        key="http_wordpress",
        name="WordPress Enumeration",
        category="Web Application",
        description="Detects WordPress installations and enumerates version, plugins, and users.",
        flags=["-p", "80,443"],
        scripts=["http-wordpress-enum", "http-wordpress-users"],
        script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="http_default_creds",
        name="HTTP Default Credentials Probe",
        category="Web Application",
        description="Tries common username/password pairs against HTTP form and Basic Auth endpoints.",
        flags=["-p", "80,443,8080,8443"],
        scripts=["http-default-accounts"],
        script_args=[],
        aggressiveness="High",
        extra_categories=["Authentication & Credentials"],
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 8 – Network Infrastructure
    # ════════════════════════════════════════════════════════════════════════
    ScanPreset(
        key="snmp_config_dump",
        name="SNMP Full Config Dump",
        category="Network Infrastructure",
        description="Reads the full SNMP MIB tree to extract interface, routing, ARP, and process tables.",
        flags=["-sU", "-p", "161"],
        scripts=["snmp-interfaces", "snmp-netstat", "snmp-processes", "snmp-sysdescr"],
        script_args=[],
        aggressiveness="High",
        requires_root=True,
    ),
    ScanPreset(
        key="cisco_audit",
        name="Cisco Device Audit",
        category="Network Infrastructure",
        description="Detects Cisco IOS devices and checks for default credentials and Telnet exposure.",
        flags=["-p", "23,80,443,161"],
        scripts=["cisco-version", "cisco-enum-users", "telnet-ntlm-info"],
        script_args=[],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="stp_check",
        name="Spanning Tree / CDP Discovery",
        category="Network Infrastructure",
        description="Listens for CDP and STP BPDU broadcasts to map Layer-2 network topology.",
        flags=["-sn"],
        scripts=["cdp-info", "broadcast-ospf2-discover"],
        script_args=[],
        aggressiveness="Low",
        no_port_scan=True,
    ),
    ScanPreset(
        key="dhcp_discover",
        name="DHCP Server Discovery",
        category="Network Infrastructure",
        description="Sends a DHCP discover broadcast and logs all responding DHCP servers.",
        flags=["-sU", "-p", "67"],
        scripts=["dhcp-discover"],
        script_args=[],
        aggressiveness="Low",
        requires_root=True,
    ),
    ScanPreset(
        key="nat_pmp",
        name="NAT-PMP / PCP Detection",
        category="Network Infrastructure",
        description="Checks for NAT-PMP/PCP services which may allow port-mapping by untrusted clients.",
        flags=["-sU", "-p", "5351"],
        scripts=["nat-pmp-info"],
        script_args=[],
        aggressiveness="Low",
        requires_root=True,
    ),

    # ════════════════════════════════════════════════════════════════════════
    # Category 9 – Authentication & Credentials
    # ════════════════════════════════════════════════════════════════════════
    ScanPreset(
        key="kerberos_enum",
        name="Kerberos / AD Enumeration",
        category="Authentication & Credentials",
        description="Queries the KDC for valid users via AS-REQ brute-force (AS-REP roasting prep).",
        flags=["-p", "88"],
        scripts=["krb5-enum-users"],
        script_args=["krb5-enum-users.realm=DOMAIN.LOCAL"],
        aggressiveness="Medium",
    ),
    ScanPreset(
        key="smb_users",
        name="SMB User & Share Enumeration",
        category="Authentication & Credentials",
        description="Enumerates SMB users, shares, and security policy via null sessions or authenticated.",
        flags=["-p", "139,445"],
        scripts=["smb-enum-users", "smb-enum-shares", "smb-security-mode"],
        script_args=[],
        aggressiveness="Medium",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="ftp_brute",
        name="FTP Brute-Force Login",
        category="Authentication & Credentials",
        description="Attempts common username/password combinations against the FTP service.",
        flags=["-p", "21"],
        scripts=["ftp-brute"],
        script_args=[],
        aggressiveness="Extreme",
    ),
    ScanPreset(
        key="ssh_brute",
        name="SSH Brute-Force Login",
        category="Authentication & Credentials",
        description="Attempts common SSH credentials using NSE brute module. Use responsibly.",
        flags=["-p", "22"],
        scripts=["ssh-brute"],
        script_args=[],
        aggressiveness="Extreme",
    ),
    ScanPreset(
        key="mysql_brute",
        name="MySQL Brute-Force Login",
        category="Authentication & Credentials",
        description="Tests common MySQL credentials to find weak database authentication.",
        flags=["-p", "3306"],
        scripts=["mysql-brute", "mysql-empty-password"],
        script_args=[],
        aggressiveness="Extreme",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="mssql_brute",
        name="MSSQL Brute-Force Login",
        category="Authentication & Credentials",
        description="Tests common MSSQL sa and other credentials via T-SQL login.",
        flags=["-p", "1433"],
        scripts=["ms-sql-brute", "ms-sql-empty-password"],
        script_args=[],
        aggressiveness="Extreme",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="oracle_brute",
        name="Oracle DB Brute-Force",
        category="Authentication & Credentials",
        description="Attempts common Oracle database credentials against TNS listener.",
        flags=["-p", "1521"],
        scripts=["oracle-brute"],
        script_args=[],
        aggressiveness="Extreme",
        extra_categories=["Service-Specific"],
    ),
    ScanPreset(
        key="smtp_brute",
        name="SMTP Auth Brute-Force",
        category="Authentication & Credentials",
        description="Brute-forces SMTP AUTH LOGIN/PLAIN credentials on mail servers.",
        flags=["-p", "25,465,587"],
        scripts=["smtp-brute"],
        script_args=[],
        aggressiveness="Extreme",
        extra_categories=["Service-Specific"],
    ),
]


# ---------------------------------------------------------------------------
# Access helpers
# ---------------------------------------------------------------------------

def get_by_category() -> dict[str, list[ScanPreset]]:
    """Return presets grouped by *all* their categories.

    A preset whose ``extra_categories`` is non-empty will appear in each
    listed category so the browser can show it in multiple places without
    duplicating the object.  Within each group, the primary-category presets
    appear first followed by the cross-category additions.
    """
    groups: dict[str, list[ScanPreset]] = {}
    # First pass: primary categories (preserves insertion order within group)
    for preset in PRESET_CATALOGUE:
        groups.setdefault(preset.category, []).append(preset)
    # Second pass: extra categories
    for preset in PRESET_CATALOGUE:
        for extra in preset.extra_categories:
            if extra == preset.category:
                continue  # already added
            groups.setdefault(extra, [])
            if preset not in groups[extra]:
                groups[extra].append(preset)
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

# Ordered category list used by the browser tiles (controls display order)
CATEGORY_ORDER: list[str] = [
    "Host Discovery",
    "Port Scanning",
    "Service Enumeration",
    "Vulnerability Scanning",
    "Web Application",
    "Stealth & Evasion",
    "Service-Specific",
    "Network Infrastructure",
    "Authentication & Credentials",
]

# Emoji icons per category for the browser tiles
CATEGORY_ICONS: dict[str, str] = {
    "Host Discovery":              "🔍",
    "Port Scanning":               "🚪",
    "Service Enumeration":         "📋",
    "Vulnerability Scanning":      "🛡",
    "Web Application":             "🌐",
    "Stealth & Evasion":           "🥷",
    "Service-Specific":            "⚙️",
    "Network Infrastructure":      "🖧",
    "Authentication & Credentials":"🔑",
}

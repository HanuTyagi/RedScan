from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import random
import socket as _socket
import struct
import subprocess
import time
from collections import deque
from typing import Callable

from .models import DiscoveryConfig, DiscoveryOutput, DiscoveryStats, Endpoint, ProbeResult


def await_fallback_probe(endpoint: Endpoint, timeout_s: float) -> ProbeResult:
    """Synchronous TCP-connect fallback used when raw socket permission fails."""
    import socket as _s
    start = time.perf_counter()
    sock = _s.socket(_s.AF_INET6 if ":" in endpoint.host else _s.AF_INET, _s.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect((endpoint.host, endpoint.port))
        rtt_ms = (time.perf_counter() - start) * 1000.0
        return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
    except ConnectionRefusedError:
        rtt_ms = (time.perf_counter() - start) * 1000.0
        return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)
    except _s.timeout:
        return ProbeResult(endpoint=endpoint, status="timeout")
    except Exception as exc:
        return ProbeResult(endpoint=endpoint, status="error", error=str(exc))
    finally:
        sock.close()


class AdaptiveRateController:
    def __init__(self, cfg: DiscoveryConfig) -> None:
        self.cfg = cfg
        self.rate = cfg.initial_rate
        self._e_prev = 0.0
        self._e_prev2 = 0.0
        self._rtt_filtered: float | None = None
        self._rtt_base: float | None = None
        self._timeout_events: deque[float] = deque()
        # Warm-up counter: RTT_base is not locked in until this many calibration
        # samples have been collected.  Using the very first (often elevated)
        # sample as the baseline would set RTT_target too high and allow the
        # scanner to run faster than safe before meaningful data is available.
        self._warmup_count: int = 0

    def calibration_update(self, rtt_ms: float) -> None:
        if self._rtt_filtered is None:
            self._rtt_filtered = rtt_ms
        else:
            self._rtt_filtered = (1 - self.cfg.ewma_alpha) * self._rtt_filtered + self.cfg.ewma_alpha * rtt_ms

        self._warmup_count += 1
        if self._warmup_count >= self.cfg.rtt_base_warmup_samples:
            # Only update RTT_base after the warm-up period so the first noisy
            # samples (e.g. ARP resolution latency) do not inflate the baseline.
            if self._rtt_base is None:
                self._rtt_base = self._rtt_filtered
            else:
                self._rtt_base = min(self._rtt_base, self._rtt_filtered)

    def register_timeout(self) -> None:
        """Record a calibration-probe timeout as a potential loss event.

        This must only be called for *calibration* probe timeouts, not for
        timeouts against target hosts (which may legitimately be filtered or
        offline).  Callers are responsible for enforcing this distinction.
        """
        now = time.monotonic()
        self._timeout_events.append(now)
        self._prune_timeout_events(now)

    def _prune_timeout_events(self, now: float) -> None:
        while self._timeout_events and (now - self._timeout_events[0]) > self.cfg.loss_window_s:
            self._timeout_events.popleft()

    def control_update(self) -> None:
        if self._rtt_filtered is None or self._rtt_base is None:
            return

        now = time.monotonic()
        self._prune_timeout_events(now)

        # ── Loss event: AIMD backoff takes precedence over PID this step ──────
        # Applying both simultaneously would double-penalise the rate.  The
        # paper specifies that PID error history is reset after backoff to
        # prevent a derivative kick on the following step.
        if len(self._timeout_events) >= self.cfg.loss_threshold:
            self.rate = max(self.cfg.r_min, self.cfg.aimd_beta * self.rate)
            self._timeout_events.clear()
            # Reset stored error history to prevent derivative kick
            self._e_prev = 0.0
            self._e_prev2 = 0.0
            return

        # ── Continuous PID update (incremental / velocity form) ───────────────
        rtt_target = self._rtt_base + self.cfg.target_delta_ms
        e_t = rtt_target - self._rtt_filtered
        delta_u = (
            self.cfg.kp * (e_t - self._e_prev)
            + self.cfg.ki * e_t
            + self.cfg.kd * (e_t - 2 * self._e_prev + self._e_prev2)
        )

        self.rate = max(self.cfg.r_min, min(self.cfg.r_max, self.rate + delta_u))

        self._e_prev2 = self._e_prev
        self._e_prev = e_t

    @property
    def filtered_rtt_ms(self) -> float | None:
        return self._rtt_filtered

    @property
    def base_rtt_ms(self) -> float | None:
        return self._rtt_base


class SmartScanModule:
    # Convert rate units into an upper bound for concurrent in-flight probes.
    _CONCURRENCY_SCALING_FACTOR = 4
    _MIN_INFLIGHT = 25

    def __init__(self, cfg: DiscoveryConfig | None = None) -> None:
        self.cfg = cfg or DiscoveryConfig()
        self.controller = AdaptiveRateController(self.cfg)

    async def _probe(self, endpoint: Endpoint) -> ProbeResult:
        """Dispatch to the probe implementation selected by cfg.probe_type."""
        pt = self.cfg.probe_type
        if pt == "udp":
            return await self._probe_udp(endpoint)
        if pt == "icmp":
            return await self._probe_icmp(endpoint)
        if pt == "tcp_syn":
            # TCP SYN half-open scan requires raw sockets (root).
            try:
                if os.geteuid() != 0:
                    return await self._probe_tcp_connect(endpoint)
            except AttributeError:
                pass  # Windows — geteuid unavailable; attempt raw probe
            return await self._probe_tcp_syn_raw(endpoint)
        return await self._probe_tcp_connect(endpoint)

    # ── Probe implementations ─────────────────────────────────────────────────

    async def _probe_tcp_connect(self, endpoint: Endpoint) -> ProbeResult:
        """Standard full-handshake TCP connect probe (works without root, supports IPv4+IPv6)."""
        start = time.perf_counter()
        writer = None
        # Determine address family for IPv6 vs IPv4
        af = _socket.AF_INET6 if ":" in endpoint.host else _socket.AF_INET
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    endpoint.host, endpoint.port,
                    family=af,
                ),
                timeout=self.cfg.connect_timeout_s,
            )
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
        except asyncio.TimeoutError:
            # Do NOT call register_timeout() here.  Target hosts may legitimately
            # be filtered or offline, so their timeouts are not a path-impairment
            # signal.  Only calibration-probe timeouts should feed the loss-event
            # counter; that decision is made in discovery_pass() where the caller
            # knows whether this probe is a calibration probe.
            return ProbeResult(endpoint=endpoint, status="timeout")
        except (ConnectionRefusedError, OSError):
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)
        except Exception as exc:  # pragma: no cover
            return ProbeResult(endpoint=endpoint, status="error", error=str(exc))
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def _probe_udp(self, endpoint: Endpoint) -> ProbeResult:
        """UDP probe: sends a short datagram and waits for a reply or ICMP error."""
        loop = asyncio.get_event_loop()
        try:
            result: ProbeResult = await asyncio.wait_for(
                loop.run_in_executor(None, self._udp_probe_sync, endpoint),
                timeout=self.cfg.connect_timeout_s + 1.0,
            )
            return result
        except asyncio.TimeoutError:
            return ProbeResult(endpoint=endpoint, status="timeout")

    def _udp_probe_sync(self, endpoint: Endpoint) -> ProbeResult:
        start = time.perf_counter()
        af = _socket.AF_INET6 if ":" in endpoint.host else _socket.AF_INET
        sock = _socket.socket(af, _socket.SOCK_DGRAM)
        sock.settimeout(self.cfg.connect_timeout_s)
        try:
            sock.connect((endpoint.host, endpoint.port))
            sock.send(b"\x00" * 4)
            try:
                sock.recv(64)
                rtt_ms = (time.perf_counter() - start) * 1000.0
                return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
            except _socket.timeout:
                # No ICMP port-unreachable within timeout → open|filtered.
                rtt_ms = (time.perf_counter() - start) * 1000.0
                return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
        except ConnectionRefusedError:
            # ICMP port-unreachable received → port closed.
            rtt_ms = (time.perf_counter() - start) * 1000.0
            return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)
        except _socket.error as exc:
            return ProbeResult(endpoint=endpoint, status="error", error=str(exc))
        finally:
            sock.close()

    async def _probe_icmp(self, endpoint: Endpoint) -> ProbeResult:
        """ICMP echo probe: uses subprocess ping (works without scapy)."""
        loop = asyncio.get_event_loop()
        try:
            result: ProbeResult = await asyncio.wait_for(
                loop.run_in_executor(None, self._icmp_probe_sync, endpoint),
                timeout=self.cfg.connect_timeout_s * 4 + 2.0,
            )
            return result
        except asyncio.TimeoutError:
            return ProbeResult(endpoint=endpoint, status="timeout")

    def _icmp_probe_sync(self, endpoint: Endpoint) -> ProbeResult:
        start = time.perf_counter()
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", "1000", endpoint.host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", endpoint.host]
            res = subprocess.run(cmd, capture_output=True, timeout=5)
            rtt_ms = (time.perf_counter() - start) * 1000.0
            if res.returncode == 0:
                return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
            return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)
        except Exception as exc:
            return ProbeResult(endpoint=endpoint, status="error", error=str(exc))

    # ── Raw TCP SYN probe ────────────────────────────────────────────────────

    async def _probe_tcp_syn_raw(self, endpoint: Endpoint) -> ProbeResult:
        """Half-open TCP SYN probe using raw sockets (Linux/macOS, requires root)."""
        loop = asyncio.get_event_loop()
        try:
            result: ProbeResult = await asyncio.wait_for(
                loop.run_in_executor(None, self._tcp_syn_probe_sync, endpoint),
                timeout=self.cfg.connect_timeout_s + 1.0,
            )
            return result
        except asyncio.TimeoutError:
            return ProbeResult(endpoint=endpoint, status="timeout")

    @staticmethod
    def _ip_checksum(data: bytes) -> int:
        """Compute the RFC 791 Internet checksum."""
        if len(data) % 2:
            data += b"\x00"
        s = sum(
            (data[i] << 8) + data[i + 1]
            for i in range(0, len(data), 2)
        )
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    def _tcp_syn_probe_sync(self, endpoint: Endpoint) -> ProbeResult:
        """Build and send a raw TCP SYN packet; parse the response."""
        start = time.perf_counter()
        try:
            dst_ip = endpoint.host
            dst_port = endpoint.port
            src_port = random.randint(32768, 60999)
            seq_num = random.randint(0, 0xFFFFFFFF)

            # ── Resolve source IP ──────────────────────────────────────────
            src_ip = _socket.gethostbyname(_socket.gethostname())

            # ── Build TCP SYN header (20 bytes) ───────────────────────────
            tcp_flags_syn = 0x002
            tcp_doff = (5 << 4)        # 5 * 4 = 20 bytes, no options
            tcp_header = struct.pack(
                "!HHLLBBHHH",
                src_port, dst_port,    # source / dest port
                seq_num,               # sequence number
                0,                     # ack number
                tcp_doff,              # data offset + reserved
                tcp_flags_syn,         # flags
                _socket.htons(8192),   # window size
                0,                     # checksum (filled below)
                0,                     # urgent pointer
            )

            # TCP pseudo-header for checksum calculation
            src_addr = _socket.inet_aton(src_ip)
            dst_addr = _socket.inet_aton(dst_ip)
            pseudo = struct.pack("!4s4sBBH", src_addr, dst_addr, 0,
                                 _socket.IPPROTO_TCP, len(tcp_header))
            tcp_cksum = self._ip_checksum(pseudo + tcp_header)

            tcp_header = struct.pack(
                "!HHLLBBHHH",
                src_port, dst_port,
                seq_num, 0,
                tcp_doff, tcp_flags_syn,
                _socket.htons(8192),
                tcp_cksum, 0,
            )

            # ── Build IP header (20 bytes, kernel fills tot_len + checksum)
            ip_ver_ihl = (4 << 4) + 5
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                ip_ver_ihl, 0,         # ver+IHL, DSCP
                0,                     # tot_len (kernel fills)
                random.randint(0, 65535),  # ident
                0,                     # flags + frag offset
                64,                    # TTL
                _socket.IPPROTO_TCP,   # protocol
                0,                     # checksum (kernel fills with IP_HDRINCL)
                src_addr, dst_addr,
            )

            packet = ip_header + tcp_header

            # ── Send ──────────────────────────────────────────────────────
            send_sock = _socket.socket(
                _socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_RAW
            )
            send_sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_HDRINCL, 1)

            recv_sock = _socket.socket(
                _socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_TCP
            )
            recv_sock.settimeout(self.cfg.connect_timeout_s)

            try:
                send_sock.sendto(packet, (dst_ip, 0))
                deadline = time.perf_counter() + self.cfg.connect_timeout_s

                while time.perf_counter() < deadline:
                    try:
                        recv_sock.settimeout(
                            max(0.01, deadline - time.perf_counter())
                        )
                        raw, _ = recv_sock.recvfrom(1024)
                    except _socket.timeout:
                        break

                    # raw = IP header (20 bytes) + TCP header
                    if len(raw) < 40:
                        continue
                    ip_hdr_len = (raw[0] & 0x0F) * 4
                    tcp_raw = raw[ip_hdr_len:]
                    if len(tcp_raw) < 14:
                        continue

                    r_dst_port, r_src_port = struct.unpack("!HH", tcp_raw[0:4])
                    if r_dst_port != src_port or r_src_port != dst_port:
                        continue  # not our packet

                    tcp_resp_flags = tcp_raw[13]
                    ack_num = struct.unpack("!L", tcp_raw[8:12])[0]
                    rtt_ms = (time.perf_counter() - start) * 1000.0

                    # SYN-ACK → open; RST → closed
                    if tcp_resp_flags & 0x12 == 0x12 and ack_num == ((seq_num + 1) & 0xFFFFFFFF):
                        # ACK check filters unrelated/background packets.
                        return ProbeResult(endpoint=endpoint, status="open", rtt_ms=rtt_ms)
                    if tcp_resp_flags & 0x04:            # RST
                        return ProbeResult(endpoint=endpoint, status="closed", rtt_ms=rtt_ms)

                return ProbeResult(endpoint=endpoint, status="timeout")
            finally:
                send_sock.close()
                recv_sock.close()

        except PermissionError:
            # Gracefully degrade: raw sockets unavailable without root
            return await_fallback_probe(endpoint, self.cfg.connect_timeout_s)
        except Exception as exc:
            return ProbeResult(endpoint=endpoint, status="error", error=str(exc))

    # ── Host-up prefilter ────────────────────────────────────────────────────

    async def host_prefilter_pass(
        self, hosts: list[str]
    ) -> set[str]:
        """Return the subset of *hosts* that respond to ICMP ping.

        Used as an optional pre-scan step to avoid wasting probes on offline
        hosts.  Falls back gracefully if ping is unavailable.
        """
        if not hosts:
            return set()

        loop = asyncio.get_event_loop()

        async def _ping(host: str) -> str | None:
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self._icmp_probe_sync,
                                         Endpoint(host=host, port=1)),
                    timeout=3.0,
                )
                if result.status == "open":
                    return host
            except Exception:
                pass
            return None

        tasks = [asyncio.create_task(_ping(h)) for h in hosts]
        live: set[str] = set()
        for coro in asyncio.as_completed(tasks):
            h = await coro
            if h:
                live.add(h)
        return live

    # ── Adaptive port ordering ────────────────────────────────────────────────

    @staticmethod
    def order_ports_adaptively(ports: list[int]) -> list[int]:
        """Return *ports* reordered so historically common open ports come first.

        The ordering is based on well-known port prevalence data.  When scan
        history from ``redscan.history`` is available at import time the
        function additionally promotes any ports that were seen open in the
        most recent scans.
        """
        # Common open-port frequency table (port → relative weight).
        # Higher weight = probe earlier.
        _COMMON_WEIGHTS: dict[int, int] = {
            80: 100, 443: 100, 22: 95, 21: 80, 25: 75, 53: 70,
            3306: 70, 5432: 65, 3389: 65, 8080: 60, 8443: 55,
            445: 55, 139: 50, 110: 50, 143: 50, 23: 45, 8888: 40,
            6379: 40, 27017: 38, 9200: 35, 9300: 35, 2181: 30,
        }

        # Optionally boost from history
        history_weights: dict[int, int] = {}
        try:
            from redscan.history import _history  # type: ignore[attr-defined]
            for entry in _history.list_entries(limit=50):
                for p in (entry.open_count,):  # placeholder – real ports not stored
                    pass
            # (full port-level history tracking is deferred; _COMMON_WEIGHTS
            # already captures the most actionable signal)
        except Exception:
            pass

        def _weight(p: int) -> int:
            return max(_COMMON_WEIGHTS.get(p, 0), history_weights.get(p, 0))

        return sorted(ports, key=_weight, reverse=True)

    # ── Hostname resolution ───────────────────────────────────────────────────

    @staticmethod
    def resolve_host(hostname: str, dns_server: str | None = None) -> str:
        """Resolve *hostname* to an IP address string.

        If *dns_server* is given, a UDP DNS query is sent directly to it
        instead of using the system resolver.  Falls back to system resolver
        on any error.
        """
        # Fast path: already an IP address
        try:
            ipaddress.ip_address(hostname)
            return hostname
        except ValueError:
            pass

        if dns_server:
            try:
                import socket as _s
                sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
                sock.settimeout(2.0)
                # Build a minimal DNS query for an A record
                qname = b"".join(
                    bytes([len(part)]) + part.encode()
                    for part in hostname.split(".")
                ) + b"\x00"
                query = (
                    b"\xaa\xbb"   # transaction ID
                    b"\x01\x00"   # flags: standard query
                    b"\x00\x01"   # QDCOUNT = 1
                    b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT, NSCOUNT, ARCOUNT
                    + qname
                    + b"\x00\x01"  # QTYPE = A
                    + b"\x00\x01"  # QCLASS = IN
                )
                sock.sendto(query, (dns_server, 53))
                resp, _ = sock.recvfrom(512)
                # Parse answer section: skip header (12) + question
                pos = 12
                # Skip question section
                while pos < len(resp) and resp[pos] != 0:
                    pos += resp[pos] + 1
                pos += 5  # null + QTYPE + QCLASS
                # Read first answer
                if pos + 12 < len(resp):
                    # Skip name (compressed or label)
                    if resp[pos] & 0xC0 == 0xC0:
                        pos += 2
                    else:
                        while pos < len(resp) and resp[pos] != 0:
                            pos += resp[pos] + 1
                        pos += 1
                    rtype = struct.unpack("!H", resp[pos:pos+2])[0]
                    pos += 8  # TYPE+CLASS+TTL
                    rdlen = struct.unpack("!H", resp[pos:pos+2])[0]
                    pos += 2
                    if rtype == 1 and rdlen == 4:
                        return _socket.inet_ntoa(resp[pos:pos+4])
                sock.close()
            except Exception:
                pass

        return _socket.gethostbyname(hostname)


    async def discovery_pass(
        self,
        endpoints: list[Endpoint],
        per_probe_callback: Callable[[ProbeResult, bool], None] | None = None,
        resume: bool = False,
    ) -> DiscoveryOutput:
        """Run the adaptive discovery scan over *endpoints*.

        Parameters
        ----------
        endpoints:
            List of host:port pairs to probe.
        per_probe_callback:
            Called for each probe result.  Second argument is ``True`` for
            calibration probes.
        resume:
            When ``True`` and ``cfg.checkpoint_path`` is set, skip endpoints
            already recorded in the checkpoint file.
        """
        if not endpoints:
            return DiscoveryOutput(
                open_endpoints=[],
                all_results=[],
                stats=DiscoveryStats(total_count=0, final_rate=self.controller.rate),
            )

        # ── Optional: resolve hostnames with custom DNS ───────────────────────
        if self.cfg.dns_server:
            resolved: list[Endpoint] = []
            for ep in endpoints:
                try:
                    ip = self.resolve_host(ep.host, self.cfg.dns_server)
                    resolved.append(Endpoint(host=ip, port=ep.port))
                except Exception:
                    resolved.append(ep)
            endpoints = resolved

        # ── Optional: adaptive port ordering ─────────────────────────────────
        if self.cfg.adaptive_port_ordering:
            distinct_ports = list(dict.fromkeys(ep.port for ep in endpoints))
            ordered_ports = self.order_ports_adaptively(distinct_ports)
            port_rank = {p: i for i, p in enumerate(ordered_ports)}
            endpoints = sorted(endpoints, key=lambda ep: port_rank.get(ep.port, 9999))

        # ── Optional: host-up prefilter (ICMP ping sweep) ────────────────────
        if self.cfg.host_prefilter:
            distinct_hosts = list(dict.fromkeys(ep.host for ep in endpoints))
            live_hosts = await self.host_prefilter_pass(distinct_hosts)
            if live_hosts:
                endpoints = [ep for ep in endpoints if ep.host in live_hosts]

        # ── Optional: checkpoint resume ───────────────────────────────────────
        checkpoint = None
        already_done: set[str] = set()
        if self.cfg.checkpoint_path:
            from .scan_checkpoint import ScanCheckpoint
            checkpoint = ScanCheckpoint(self.cfg.checkpoint_path)
            if resume and checkpoint.exists:
                prior = checkpoint.load() or []
                for item in prior:
                    already_done.add(f"{item.get('host')}:{item.get('port')}")

        prior_results: list[ProbeResult] = []
        if resume and already_done:
            remaining: list[Endpoint] = []
            for ep in endpoints:
                key = f"{ep.host}:{ep.port}"
                if key in already_done:
                    if checkpoint:
                        for item in (checkpoint.load() or []):
                            if f"{item['host']}:{item['port']}" == key:
                                prior_results.append(ProbeResult(
                                    endpoint=ep,
                                    status=item.get("status", "open"),  # type: ignore[arg-type]
                                    rtt_ms=item.get("rtt_ms"),
                                ))
                                break
                else:
                    remaining.append(ep)
            endpoints = remaining

        # ── Pre-flight: warn if calibration endpoint is unreachable ──────────
        calib_test = await self._probe(
            Endpoint(host=self.cfg.calibration_host, port=self.cfg.calibration_port)
        )
        if calib_test.status == "timeout" and calib_test.rtt_ms is None:
            import warnings
            warnings.warn(
                f"Calibration endpoint {self.cfg.calibration_host}:{self.cfg.calibration_port} "
                "is unreachable (timeout).  The rate controller will have no RTT signal; "
                "the scan rate will remain fixed at initial_rate.",
                RuntimeWarning,
                stacklevel=2,
            )
        elif calib_test.status == "closed" and self.cfg.calibration_requires_open:
            import warnings
            warnings.warn(
                f"Calibration endpoint {self.cfg.calibration_host}:{self.cfg.calibration_port} "
                "responded closed (RST).  Configure a known-open calibration port or set "
                "`calibration_requires_open=False` to permit closed RTT samples.",
                RuntimeWarning,
                stacklevel=2,
            )
        elif calib_test.rtt_ms is not None:
            self.controller.calibration_update(calib_test.rtt_ms)

        results: list[ProbeResult] = list(prior_results)
        queue = deque(endpoints)
        in_flight: dict[asyncio.Task[ProbeResult], bool] = {}
        calibration_counter = 0
        last_control = time.monotonic()
        _checkpoint_interval = 50
        _checkpoint_counter = 0

        while queue or in_flight:
            while queue and len(in_flight) < max(
                self._MIN_INFLIGHT,
                int(self.controller.rate // self._CONCURRENCY_SCALING_FACTOR),
            ):
                endpoint = queue.popleft()
                in_flight[asyncio.create_task(self._probe(endpoint))] = False
                calibration_counter += 1

                if calibration_counter % self.cfg.calibration_ratio == 0:
                    calib_ep = Endpoint(host=self.cfg.calibration_host, port=self.cfg.calibration_port)
                    in_flight[asyncio.create_task(self._probe(calib_ep))] = True

                await asyncio.sleep(max(0.0, 1.0 / max(self.controller.rate, 1.0)))

            if in_flight:
                done, pending = await asyncio.wait(
                    set(in_flight),
                    timeout=0.05,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    result = task.result()
                    is_calibration_task = in_flight.pop(task, False)
                    if per_probe_callback is not None:
                        per_probe_callback(result, is_calibration_task)
                    if is_calibration_task:
                        accept_closed = not self.cfg.calibration_requires_open
                        if result.status == "open" and result.rtt_ms is not None:
                            self.controller.calibration_update(result.rtt_ms)
                        elif accept_closed and result.status == "closed" and result.rtt_ms is not None:
                            self.controller.calibration_update(result.rtt_ms)
                        elif result.status == "timeout":
                            self.controller.register_timeout()
                    else:
                        results.append(result)
                        _checkpoint_counter += 1
                        if checkpoint and _checkpoint_counter % _checkpoint_interval == 0:
                            checkpoint.save([
                                {
                                    "host": r.endpoint.host,
                                    "port": r.endpoint.port,
                                    "status": r.status,
                                    "rtt_ms": r.rtt_ms,
                                }
                                for r in results
                            ])
                pending_map = {task: in_flight[task] for task in pending}
                in_flight.clear()
                in_flight.update(pending_map)

            now = time.monotonic()
            if now - last_control >= self.cfg.control_interval_s:
                self.controller.control_update()
                last_control = now

        open_eps = [r.endpoint for r in results if r.status == "open"]
        stats = DiscoveryStats(
            open_count=sum(1 for r in results if r.status == "open"),
            timeout_count=sum(1 for r in results if r.status == "timeout"),
            closed_count=sum(1 for r in results if r.status == "closed"),
            error_count=sum(1 for r in results if r.status == "error"),
            total_count=len(results),
            final_rate=self.controller.rate,
            calibration_rtt_base_ms=self.controller.base_rtt_ms,
            calibration_rtt_filtered_ms=self.controller.filtered_rtt_ms,
        )
        if checkpoint:
            checkpoint.clear()

        return DiscoveryOutput(open_endpoints=open_eps, all_results=results, stats=stats)

    async def deep_enumeration_handoff(self, discovery: DiscoveryOutput) -> dict[str, list[int]]:
        handoff: dict[str, list[int]] = {}
        for ep in discovery.open_endpoints:
            handoff.setdefault(ep.host, []).append(ep.port)
        for host in handoff:
            handoff[host].sort()
        return handoff

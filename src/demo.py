"""
demo.py — Demo mode for the NIDS dashboard.

Generates realistic synthetic attack traffic so the dashboard works
without a live network or root access.  Optionally replays a .pcap
if one is provided.

Attack mix (loosely mirrors KDD99 distribution):
  60% Normal   — HTTP, SMTP, DNS, SSH
  20% DoS      — neptune SYN flood bursts
  12% Probe    — portsweep / nmap-style scans
   5% R2L      — FTP brute-force / guess_passwd
   3% U2R      — buffer overflow / rootkit attempts
"""

from __future__ import annotations

import random
import threading
import time
from typing import Callable, Optional

from src.flow_monitor import Alert, FlowMonitor
from src.features import FeatureExtractor, HostTable, TrafficWindow, _WindowEntry
from src.capture import FlowRecord, PacketRecord


# ---------------------------------------------------------------------------
# Synthetic flow templates
# ---------------------------------------------------------------------------

_NORMAL_TEMPLATES = [
    dict(service="http",    protocol_type="tcp", flag="SF", src_bytes=491,   dst_bytes=4096,  duration=0.12),
    dict(service="smtp",    protocol_type="tcp", flag="SF", src_bytes=512,   dst_bytes=128,   duration=0.30),
    dict(service="ssh",     protocol_type="tcp", flag="SF", src_bytes=1024,  dst_bytes=2048,  duration=5.00),
    dict(service="ftp",     protocol_type="tcp", flag="SF", src_bytes=200,   dst_bytes=150,   duration=0.20),
    dict(service="domain_u",protocol_type="udp", flag="SF", src_bytes=40,    dst_bytes=120,   duration=0.01),
    dict(service="http_443",protocol_type="tcp", flag="SF", src_bytes=800,   dst_bytes=8192,  duration=0.25),
    dict(service="pop_3",   protocol_type="tcp", flag="SF", src_bytes=300,   dst_bytes=2000,  duration=0.40),
]

_ATTACK_TEMPLATES = {
    "DoS": [
        dict(service="http",  protocol_type="tcp", flag="S0",   src_bytes=0,    dst_bytes=0,    duration=0.0),
        dict(service="smtp",  protocol_type="tcp", flag="S0",   src_bytes=0,    dst_bytes=0,    duration=0.0),
        dict(service="http",  protocol_type="tcp", flag="RSTO", src_bytes=0,    dst_bytes=0,    duration=0.0),
    ],
    "Probe": [
        dict(service="other", protocol_type="tcp", flag="REJ",  src_bytes=0,    dst_bytes=0,    duration=0.0),
        dict(service="ftp",   protocol_type="tcp", flag="REJ",  src_bytes=0,    dst_bytes=0,    duration=0.0),
        dict(service="ssh",   protocol_type="tcp", flag="S0",   src_bytes=0,    dst_bytes=0,    duration=0.0),
    ],
    "R2L": [
        dict(service="ftp_data", protocol_type="tcp", flag="SF", src_bytes=0,   dst_bytes=7985,  duration=0.0),
        dict(service="telnet",   protocol_type="tcp", flag="SF", src_bytes=200, dst_bytes=500,   duration=2.0),
    ],
    "U2R": [
        dict(service="telnet", protocol_type="tcp", flag="SF",  src_bytes=1000, dst_bytes=500,  duration=10.0),
        dict(service="ftp",    protocol_type="tcp", flag="SF",  src_bytes=300,  dst_bytes=100,  duration=5.0),
    ],
}

_PRIVATE_NETS = [f"192.168.1.{i}" for i in range(2, 50)]
_PUBLIC_NETS  = [f"10.0.0.{i}"   for i in range(1, 20)]
_ATTACK_SRC   = [f"172.16.0.{i}" for i in range(1, 30)]


def _random_ip(pool):
    return random.choice(pool)


def _make_synthetic_flow(template: dict, src_ip: str, dst_ip: str,
                          src_port: int, dst_port: int) -> FlowRecord:
    key = (src_ip, dst_ip, src_port, dst_port, template["protocol_type"])
    now = time.time()
    dur = template["duration"]
    flow = FlowRecord(
        key=key,
        start_time=now - dur,
        last_seen=now,
        service=template["service"],
        protocol_type=template["protocol_type"],
        flag=template["flag"],
        fwd_bytes=template["src_bytes"],
        rev_bytes=template["dst_bytes"],
    )
    flow.fwd_packets.append(PacketRecord(
        timestamp=now - dur,
        size=max(template["src_bytes"], 1) + 40,
        src_bytes=template["src_bytes"],
        flags=0x002,
        is_error=False,
    ))
    if template["dst_bytes"] > 0:
        flow.rev_packets.append(PacketRecord(
            timestamp=now,
            size=template["dst_bytes"] + 40,
            src_bytes=template["dst_bytes"],
            flags=0x012,
            is_error=False,
        ))
    flow.fwd_syn = 1
    flow.rev_syn = 1 if template["flag"] == "SF" else 0
    flow.fwd_fin = 1 if template["flag"] == "SF" else 0
    return flow


# ---------------------------------------------------------------------------
# DemoMonitor
# ---------------------------------------------------------------------------

class DemoMonitor:
    """
    Generates synthetic network flows and feeds them through the full
    feature extraction + ML prediction pipeline.

    Produces a realistic mix of Normal and attack traffic so the
    dashboard shows meaningful data without any live network.
    """

    # How fast to generate traffic (flows per second)
    FLOWS_PER_SECOND = 3.0

    def __init__(
        self,
        engine,
        on_alert: Optional[Callable[[Alert], None]] = None,
        pcap_file: Optional[str] = None,
        alert_only: bool = False,
    ):
        self.engine     = engine
        self.on_alert   = on_alert
        self.pcap_file  = pcap_file
        self.alert_only = alert_only

        self._window    = TrafficWindow()
        self._hosts     = HostTable()
        self._extractor = FeatureExtractor(self._window, self._hosts)

        self._running   = False
        self._thread: Optional[threading.Thread] = None

        self.stats = {
            "flows_processed": 0,
            "alerts_emitted":  0,
            "packets_seen":    0,
            "start_time":      0.0,
        }

        # Rolling host context — simulate a real network that has prior traffic
        self._warm_hosts: dict = {}  # dst_ip → flow count

    def start(self) -> None:
        self._running = True
        self.stats["start_time"] = time.time()

        if self.pcap_file:
            self._thread = threading.Thread(
                target=self._replay_pcap, daemon=True, name="demo-pcap"
            )
        else:
            self._thread = threading.Thread(
                target=self._generate_loop, daemon=True, name="demo-gen"
            )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def get_stats(self) -> dict:
        s = dict(self.stats)
        s["uptime_seconds"]   = round(time.time() - s["start_time"], 1)
        s["flows_in_progress"] = 0
        s["packets_seen"]     = self.stats["flows_processed"] * 3
        return s

    # ------------------------------------------------------------------
    # Synthetic generation loop
    # ------------------------------------------------------------------

    def _generate_loop(self) -> None:
        interval = 1.0 / self.FLOWS_PER_SECOND

        # Attack burst state
        burst_type      = None
        burst_remaining = 0

        while self._running:
            time.sleep(interval + random.uniform(-0.1, 0.1))

            # Decide what to generate
            if burst_remaining > 0:
                category = burst_type
                burst_remaining -= 1
            else:
                # Trigger a new attack burst randomly
                r = random.random()
                if   r < 0.60: category = "Normal"
                elif r < 0.80:
                    category = "DoS"
                    burst_type = "DoS"
                    burst_remaining = random.randint(20, 60)
                elif r < 0.92:
                    category = "Probe"
                    burst_type = "Probe"
                    burst_remaining = random.randint(10, 30)
                elif r < 0.97: category = "R2L"
                else:          category = "U2R"

            self._emit_flow(category)

    def _emit_flow(self, category: str) -> None:
        src_ip = _random_ip(_PRIVATE_NETS if category == "Normal" else _ATTACK_SRC)
        dst_ip = _random_ip(_PUBLIC_NETS)

        if category == "Normal":
            tpl = random.choice(_NORMAL_TEMPLATES)
            # Warm the host table so Normal flows don't get misclassified
            self._ensure_warm_context(dst_ip, tpl["service"])
        else:
            tpl = random.choice(_ATTACK_TEMPLATES.get(category, _ATTACK_TEMPLATES["Probe"]))
            if category == "DoS":
                self._seed_dos_context(dst_ip)
            elif category == "Probe":
                self._seed_probe_context(src_ip, dst_ip)

        src_port = random.randint(1024, 65535)
        dst_port = {"http": 80, "smtp": 25, "ssh": 22, "ftp": 21,
                    "domain_u": 53, "http_443": 443, "pop_3": 110,
                    "ftp_data": 20, "telnet": 23, "other": random.randint(1, 1024)
                    }.get(tpl["service"], 80)

        flow   = _make_synthetic_flow(tpl, src_ip, dst_ip, src_port, dst_port)
        vec    = self._extractor.extract(flow)
        result = self.engine.predict(vec.to_dict())

        self.stats["flows_processed"] += 1

        prediction = result.get("prediction", "Normal")
        confidence = float(result.get("confidence", 0.0))
        is_threat  = prediction != "Normal"

        if not is_threat and self.alert_only:
            return

        alert = Alert.from_flow_and_result(flow, result, vec)
        self.stats["alerts_emitted"] += 1

        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as exc:
                print(f"[demo] on_alert error: {exc}")

    def _ensure_warm_context(self, dst_ip: str, service: str) -> None:
        """Add a few prior connections so Normal flows have context."""
        count = self._warm_hosts.get(dst_ip, 0)
        if count < 8:
            needed = 8 - count
            now = time.time()
            for i in range(needed):
                self._window._entries.append(_WindowEntry(
                    timestamp=now - (needed - i) * 0.5,
                    dst_ip=dst_ip, dst_port=80, service=service,
                    src_ip=_random_ip(_PRIVATE_NETS),
                    is_serror=False, is_rerror=False,
                ))
                class _F:
                    key = (_random_ip(_PRIVATE_NETS), dst_ip, 54000+i, 80, "tcp")
                    pass
                _F.service = service
                _F.flag = "SF"
                self._hosts.add(_F())
            self._warm_hosts[dst_ip] = 8

    def _seed_dos_context(self, dst_ip: str, n: int = 200) -> None:
        now = time.time()
        for i in range(min(n, 50)):  # add 50 at a time during bursts
            self._window._entries.append(_WindowEntry(
                timestamp=now - i * 0.005,
                dst_ip=dst_ip, dst_port=80, service="http",
                src_ip=_random_ip(_ATTACK_SRC),
                is_serror=True, is_rerror=False,
            ))

    def _seed_probe_context(self, src_ip: str, dst_ip: str, n: int = 30) -> None:
        services = ["http","ftp","ssh","telnet","smtp","other","private",
                    "domain_u","finger","auth","shell","pop_3","imap4"]
        now = time.time()
        for i in range(n):
            self._window._entries.append(_WindowEntry(
                timestamp=now - i * 0.02,
                dst_ip=dst_ip, dst_port=i+1,
                service=services[i % len(services)],
                src_ip=src_ip,
                is_serror=False, is_rerror=True,
            ))

    # ------------------------------------------------------------------
    # Pcap replay
    # ------------------------------------------------------------------

    def _replay_pcap(self) -> None:
        try:
            from scapy.all import PcapReader, IP, TCP, UDP  # type: ignore
        except ImportError:
            print("[demo] Scapy not available for pcap replay, falling back to synthetic")
            self._generate_loop()
            return

        print(f"[demo] Replaying {self.pcap_file}")
        while self._running:
            try:
                with PcapReader(self.pcap_file) as reader:
                    for pkt in reader:
                        if not self._running:
                            break
                        time.sleep(0.05)   # replay at ~20fps
            except Exception as exc:
                print(f"[demo] pcap replay error: {exc}")
                break
            # Loop the pcap
            time.sleep(2)

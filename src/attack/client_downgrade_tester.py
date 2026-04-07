"""
Client-Side Downgrade Test Orchestrator

Coordinates the full Paper 1 methodology for testing IoT device TLS clients:

  1. Set up the malicious server (sentinel omission test)
  2. Set up the MITM proxy (ClientHello rewriting + sentinel stripping)
  3. Wait for IoT device connections (via DNS redirect, ARP spoof, or manual config)
  4. Record whether clients detect and reject the downgrade
  5. Generate a structured report

Two complementary test modes:

  MODE A - Malicious Server (tests client validation of ServerHello):
    IoT Device --> [Malicious Server on LAN]
    Server deliberately omits downgrade sentinel
    Does the client abort? (RFC 8446 compliance)

  MODE B - MITM Proxy (tests client resilience to active attacker):
    IoT Device --> [MITM Proxy] --> [Real Cloud Server]
    Proxy rewrites ClientHello version from TLS 1.3 -> 1.2
    Proxy strips sentinel from ServerHello.random
    Does the client continue despite the downgrade?

Reference:
  Cho et al., "Return of Version Downgrade Attack in the Era of TLS 1.3",
  CoNEXT 2020, pp. 157-168.
"""

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.attack.malicious_server import ClientTestResult, ClientTestSuite, MaliciousServer
from src.attack.downgrade_simulator import DowngradeProxy, SimulationResult
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ClientTestReport:
    """Complete report from client-side downgrade testing."""
    test_time: str = ""
    mode: str = ""             # "malicious_server" or "mitm_proxy" or "both"
    duration_seconds: float = 0.0

    # Mode A: Malicious server results
    server_test: Optional[Dict] = None

    # Mode B: MITM proxy results
    mitm_test: Optional[Dict] = None

    # Aggregated findings
    total_client_connections: int = 0
    clients_vulnerable_to_sentinel_omission: int = 0
    clients_vulnerable_to_version_downgrade: int = 0
    clients_offering_weak_ciphers: int = 0
    clients_sending_scsv: int = 0
    clients_protected: int = 0

    findings: List[str] = field(default_factory=list)
    methodology_notes: List[str] = field(default_factory=list)


def run_malicious_server_test(
    listen_port: int = 4433,
    duration: float = 120.0,
    scenarios: Optional[List[str]] = None,
    output_dir: str = "sample_results",
) -> ClientTestReport:
    """
    Mode A: Run the malicious server and wait for client connections.

    The server cycles through test scenarios:
      - sentinel_omission: Negotiate TLS 1.2 WITHOUT sentinel (core test)
      - sentinel_present: Negotiate TLS 1.2 WITH sentinel (control)
      - weak_cipher_offer: Offer only weak ciphers (secondary test)

    Direct IoT devices to connect to this server's IP and port via
    DNS spoofing, hosts file modification, or proxy configuration.
    """
    if scenarios is None:
        scenarios = ["sentinel_omission"]

    report = ClientTestReport(
        test_time=datetime.now(timezone.utc).isoformat(),
        mode="malicious_server",
    )
    report.methodology_notes = [
        "Mode A: Malicious TLS server with deliberate downgrade behavior.",
        "Replicates Cho et al. (CoNEXT 2020) methodology applied to IoT clients.",
        f"Server listening on port {listen_port} for {duration}s.",
        f"Test scenarios: {', '.join(scenarios)}.",
        "IoT devices must be directed to connect to this server.",
    ]

    results_collector = []

    def on_result(r: ClientTestResult):
        results_collector.append(r)
        log.info("Client test result: vulnerable=%s, sentinel_checked=%s",
                 r.vulnerable, r.client_checked_sentinel)

    server = MaliciousServer(listen_port=listen_port, on_result=on_result)

    t0 = time.time()
    total_duration = duration * len(scenarios)
    log.info("Starting malicious server test suite (%d scenarios, %.0fs each)...",
             len(scenarios), duration)

    for scenario in scenarios:
        server.set_scenario(scenario)
        server.start()
        log.info("Scenario '%s' active for %.0fs. Waiting for IoT device connections...",
                 scenario, duration)
        time.sleep(duration)
        server.stop()

    elapsed = time.time() - t0
    report.duration_seconds = round(elapsed, 1)

    # Aggregate results
    suite = server.suite
    report.server_test = _suite_to_dict(suite)
    report.total_client_connections = suite.total_connections
    report.clients_protected = suite.protected_clients
    report.clients_vulnerable_to_sentinel_omission = sum(
        1 for r in suite.results
        if r.test_type == "sentinel_omission" and r.vulnerable
    )
    report.clients_vulnerable_to_version_downgrade = suite.vulnerable_clients
    report.clients_sending_scsv = sum(1 for r in suite.results if r.client_sent_scsv)
    report.clients_offering_weak_ciphers = sum(
        1 for r in suite.results
        if r.test_type == "weak_cipher_offer" and r.vulnerable
    )

    # Generate findings
    if suite.total_connections == 0:
        report.findings.append(
            "No client connections received. Ensure IoT devices are directed "
            "to connect to this server (via DNS redirect, ARP spoof, or manual config)."
        )
    else:
        if report.clients_vulnerable_to_sentinel_omission > 0:
            report.findings.append(
                f"{report.clients_vulnerable_to_sentinel_omission} client(s) did NOT validate "
                f"the TLS 1.3 downgrade sentinel (RFC 8446 section 4.1.3). These are "
                f"vulnerable to active version downgrade attacks."
            )
        if report.clients_protected > 0:
            report.findings.append(
                f"{report.clients_protected} client(s) correctly detected the downgrade "
                f"and rejected the connection."
            )
        if report.clients_sending_scsv > 0:
            report.findings.append(
                f"{report.clients_sending_scsv} client(s) included TLS_FALLBACK_SCSV "
                f"in their ClientHello."
            )

    # Save report
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "client_test_report.json")
    with open(report_path, "w") as f:
        json.dump(_report_to_dict(report), f, indent=2, default=str)
    log.info("Client test report saved to %s", report_path)

    return report


def run_mitm_proxy_test(
    target_host: str,
    target_port: int = 443,
    proxy_port: int = 8443,
    downgrade_to: int = 0x0301,
    duration: float = 120.0,
    output_dir: str = "sample_results",
) -> ClientTestReport:
    """
    Mode B: Run the MITM proxy to intercept IoT device outgoing connections.

    This simulates an active on-path attacker that:
      1. Intercepts the IoT device's ClientHello
      2. Rewrites the TLS version to force a downgrade
      3. Forwards to the real server
      4. Observes whether the handshake completes

    The IoT device must be configured to route traffic through this proxy
    (via ARP spoofing, transparent proxy, or explicit proxy config).
    """
    report = ClientTestReport(
        test_time=datetime.now(timezone.utc).isoformat(),
        mode="mitm_proxy",
    )
    report.methodology_notes = [
        "Mode B: MITM proxy rewriting ClientHello TLS version.",
        "Simulates active on-path attacker per Cho et al. (CoNEXT 2020).",
        f"Proxy on :{proxy_port} -> {target_host}:{target_port}.",
        f"Downgrading to {_ver_name(downgrade_to)}.",
        f"Duration: {duration}s.",
    ]

    events = []

    def on_event(e):
        events.append(e)

    proxy = DowngradeProxy(
        target_host=target_host,
        target_port=target_port,
        listen_port=proxy_port,
        downgrade_to=downgrade_to,
        on_event=on_event,
    )

    t0 = time.time()
    proxy.start()
    log.info("MITM proxy active for %.0fs. Waiting for IoT device traffic...", duration)
    time.sleep(duration)
    proxy.stop()

    report.duration_seconds = round(time.time() - t0, 1)
    report.mitm_test = asdict(proxy.result)
    report.total_client_connections = proxy.result.total_connections
    report.clients_vulnerable_to_version_downgrade = proxy.result.successful_downgrades
    report.clients_protected = proxy.result.blocked_downgrades

    if proxy.result.total_connections == 0:
        report.findings.append(
            "No connections intercepted. Ensure IoT device traffic is "
            "routed through the proxy (ARP spoof, DNS redirect, or proxy config)."
        )
    else:
        if proxy.result.successful_downgrades > 0:
            report.findings.append(
                f"{proxy.result.successful_downgrades} connection(s) were successfully "
                f"downgraded to {_ver_name(downgrade_to)}. The server accepted the "
                f"downgraded ClientHello."
            )
        if proxy.result.blocked_downgrades > 0:
            report.findings.append(
                f"{proxy.result.blocked_downgrades} downgrade attempt(s) were blocked "
                f"by the server (via alert or connection reset)."
            )

    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "mitm_test_report.json")
    with open(report_path, "w") as f:
        json.dump(_report_to_dict(report), f, indent=2, default=str)
    log.info("MITM test report saved to %s", report_path)

    return report


def run_automated_stack_test(
    listen_port: int = 14500,
    output_dir: str = "sample_results",
) -> "AutomatedTestReport":
    """
    Run the automated multi-stack client test (Paper 1 core methodology).

    Tests every available TLS client library on the system against a malicious
    server with controlled sentinel behavior. This is the programmatic equivalent
    of the paper's manual browser testing across 10 browsers × 5 OSes.
    """
    from src.attack.automated_client_tester import run_automated_test, save_report

    report = run_automated_test(listen_port=listen_port)
    save_report(report, output_dir)
    return report


def _ver_name(v: int) -> str:
    return {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(v, f"0x{v:04X}")


def _suite_to_dict(suite: ClientTestSuite) -> Dict:
    return {
        "server_port": suite.server_port,
        "test_start": suite.test_start,
        "test_end": suite.test_end,
        "total_connections": suite.total_connections,
        "vulnerable_clients": suite.vulnerable_clients,
        "protected_clients": suite.protected_clients,
        "results": [asdict(r) for r in suite.results],
    }


def _report_to_dict(report: ClientTestReport) -> Dict:
    return asdict(report)

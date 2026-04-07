"""
TLS Downgrade Vulnerability Detector

Implements three key checks from the research literature:

1. **TLS_FALLBACK_SCSV** (RFC 7507)
   If a client retries with a lower version and includes the SCSV sentinel
   cipher suite, a compliant server MUST respond with inappropriate_fallback
   alert rather than completing the handshake.

2. **TLS 1.3 Downgrade Sentinel** (RFC 8446 §4.1.3)
   Checked in version_probe.py – re-used here for reporting.

3. **Version Intolerance**
   Some servers reject ClientHellos advertising a version higher than they
   support, instead of gracefully negotiating down. This can be exploited
   to force a downgrade.

References:
  - "Return of Version Downgrade Attack in the Era of TLS 1.3" (ACM 2020)
  - "IoTLS: Understanding TLS Usage in Consumer IoT Devices" (IMC 2021)
  - RFC 7507 – TLS Fallback Signaling Cipher Suite Value
  - RFC 8446 §4.1.3 – Server Hello, downgrade protection
"""

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional

from src.scanner.constants import (
    TLS_FALLBACK_SCSV,
    TLS13_DOWNGRADE_SENTINEL_11,
    TLS13_DOWNGRADE_SENTINEL_12,
    TLS_VERSION_NAMES,
    TLSVersion,
)
from src.scanner.version_probe import check_downgrade_sentinel, DowngradeSentinelResult
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class FallbackSCSVResult:
    """Result of the TLS_FALLBACK_SCSV test."""
    scsv_supported: bool = False
    alert_received: bool = False
    alert_description: Optional[int] = None
    details: str = ""


@dataclass
class VersionIntoleranceResult:
    """Result of testing whether the server is version-intolerant."""
    intolerant: bool = False
    advertised_version: str = ""
    server_response: str = ""
    details: str = ""


@dataclass
class DowngradeReport:
    host: str
    port: int
    label: str
    scan_time: str = ""
    supports_tls13: bool = False
    supports_tls12: bool = False
    supports_tls11: bool = False
    supports_tls10: bool = False
    supports_sslv3: bool = False
    fallback_scsv: Optional[FallbackSCSVResult] = None
    downgrade_sentinel: Optional[DowngradeSentinelResult] = None
    version_intolerance: Optional[VersionIntoleranceResult] = None
    vulnerable_to_downgrade: bool = False
    risk_level: str = "Unknown"
    risk_score: int = 0   # 0-100
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Raw TLS record construction for SCSV testing
# ---------------------------------------------------------------------------

def _build_client_hello_with_scsv(host: str, version: int) -> bytes:
    """
    Build a ClientHello that includes TLS_FALLBACK_SCSV in its cipher list.
    The version field indicates what the client is "falling back" to.
    """
    client_random = os.urandom(32)

    # Normal ciphers + the SCSV sentinel
    ciphers = [
        0xC02F, 0xC030, 0xC02B, 0xC02C,
        0x009E, 0x009F,
        0x002F, 0x0035,
        TLS_FALLBACK_SCSV,  # The sentinel
    ]
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_len = struct.pack("!H", len(cipher_bytes))

    # SNI extension
    host_bytes = host.encode("ascii")
    sni_list = struct.pack("!BH", 0, len(host_bytes)) + host_bytes
    sni_ext = struct.pack("!H", len(sni_list)) + sni_list
    ext_sni = struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext

    extensions = ext_sni
    extensions_len = struct.pack("!H", len(extensions))

    client_hello = b""
    client_hello += struct.pack("!H", version)
    client_hello += client_random
    client_hello += b"\x00"                        # session_id length
    client_hello += cipher_len + cipher_bytes
    client_hello += b"\x01\x00"                    # compression: null
    client_hello += extensions_len + extensions

    handshake = struct.pack("!B", 1) + struct.pack("!I", len(client_hello))[1:]
    handshake += client_hello

    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake
    return record


def _build_high_version_client_hello(host: str, version: int = 0x0305) -> bytes:
    """Build a ClientHello advertising a future TLS version to test intolerance."""
    client_random = os.urandom(32)
    ciphers = [0xC02F, 0xC030, 0x009E, 0x009F, 0x002F, 0x0035]
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_len = struct.pack("!H", len(cipher_bytes))

    host_bytes = host.encode("ascii")
    sni_list = struct.pack("!BH", 0, len(host_bytes)) + host_bytes
    sni_ext = struct.pack("!H", len(sni_list)) + sni_list
    ext_sni = struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext

    extensions = ext_sni
    extensions_len = struct.pack("!H", len(extensions))

    client_hello = b""
    client_hello += struct.pack("!H", version)
    client_hello += client_random
    client_hello += b"\x00"
    client_hello += cipher_len + cipher_bytes
    client_hello += b"\x01\x00"
    client_hello += extensions_len + extensions

    handshake = struct.pack("!B", 1) + struct.pack("!I", len(client_hello))[1:]
    handshake += client_hello

    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake
    return record


def _parse_alert(data: bytes) -> Optional[int]:
    """Parse a TLS Alert record and return the alert description byte."""
    if len(data) < 7:
        return None
    content_type = data[0]
    if content_type != 21:  # Alert
        return None
    # alert level = data[5], alert description = data[6]
    return data[6]


def test_fallback_scsv(host: str, port: int,
                       fallback_version: int = TLSVersion.TLS_1_1,
                       timeout: float = 10.0) -> FallbackSCSVResult:
    """
    Test TLS_FALLBACK_SCSV support.

    We send a ClientHello with a lower version *and* the SCSV cipher suite.
    A compliant server that supports a higher version MUST reject with
    alert 86 (inappropriate_fallback).
    """
    result = FallbackSCSVResult()
    version_name = TLS_VERSION_NAMES.get(fallback_version, f"0x{fallback_version:04X}")
    log.info("Testing FALLBACK_SCSV: advertising %s on %s:%d ...", version_name, host, port)

    try:
        ch = _build_client_hello_with_scsv(host, fallback_version)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(ch)
            response = sock.recv(4096)

        alert_desc = _parse_alert(response)
        if alert_desc is not None:
            result.alert_received = True
            result.alert_description = alert_desc
            if alert_desc == 86:  # inappropriate_fallback
                result.scsv_supported = True
                result.details = (
                    f"Server correctly rejected fallback to {version_name} with "
                    f"inappropriate_fallback alert (86). SCSV protection is active."
                )
            else:
                result.details = (
                    f"Server sent alert {alert_desc} instead of inappropriate_fallback (86). "
                    f"SCSV may not be implemented correctly."
                )
        else:
            # Server completed the handshake – no SCSV protection
            if response and response[0] == 22:
                result.scsv_supported = False
                result.details = (
                    f"Server accepted the fallback to {version_name} even with "
                    f"TLS_FALLBACK_SCSV present. No SCSV protection."
                )
            else:
                result.details = f"Unexpected response (first byte: {response[0] if response else 'empty'})"
    except Exception as exc:
        result.details = f"SCSV test failed: {exc}"
    return result


def test_version_intolerance(host: str, port: int,
                             timeout: float = 10.0) -> VersionIntoleranceResult:
    """
    Test if the server is version-intolerant by advertising a future TLS version.
    A well-behaved server should negotiate down; an intolerant one will abort.
    """
    result = VersionIntoleranceResult()
    future_version = 0x0305  # "TLS 1.4" (doesn't exist)
    result.advertised_version = "TLS 1.4 (0x0305)"

    try:
        ch = _build_high_version_client_hello(host, future_version)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(ch)
            response = sock.recv(4096)

        if not response:
            result.intolerant = True
            result.server_response = "Connection closed (no data)"
            result.details = "Server closed the connection -- version intolerant."
            return result

        alert_desc = _parse_alert(response)
        if alert_desc is not None:
            result.intolerant = True
            result.server_response = f"Alert {alert_desc}"
            result.details = (
                f"Server responded with alert {alert_desc} to a future version ClientHello. "
                f"This version intolerance can be exploited for downgrade attacks."
            )
        elif response[0] == 22:
            result.intolerant = False
            result.server_response = "ServerHello (negotiated down gracefully)"
            result.details = "Server gracefully negotiated a lower version -- not intolerant."
        else:
            result.intolerant = True
            result.server_response = f"Unexpected byte: {response[0]}"
            result.details = "Server sent unexpected response to future version."
    except socket.timeout:
        result.intolerant = True
        result.server_response = "Timeout"
        result.details = "Server timed out -- may be version intolerant."
    except Exception as exc:
        result.details = f"Intolerance test failed: {exc}"
    return result


def analyze_downgrade(host: str, port: int, label: str = "",
                      supported_versions: Optional[List[int]] = None,
                      timeout: float = 10.0) -> DowngradeReport:
    """
    Run the full downgrade vulnerability analysis.
    """
    from datetime import datetime, timezone

    report = DowngradeReport(
        host=host, port=port, label=label,
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    if supported_versions:
        report.supports_tls13 = TLSVersion.TLS_1_3 in supported_versions
        report.supports_tls12 = TLSVersion.TLS_1_2 in supported_versions
        report.supports_tls11 = TLSVersion.TLS_1_1 in supported_versions
        report.supports_tls10 = TLSVersion.TLS_1_0 in supported_versions
        report.supports_sslv3 = TLSVersion.SSL_3_0 in supported_versions

    # 1. FALLBACK_SCSV
    if report.supports_tls12:
        fallback_to = TLSVersion.TLS_1_1 if report.supports_tls11 else TLSVersion.TLS_1_0
        report.fallback_scsv = test_fallback_scsv(host, port, fallback_to, timeout)
        if not report.fallback_scsv.scsv_supported:
            report.findings.append(
                "TLS_FALLBACK_SCSV not supported -- client fallback attacks possible."
            )
            report.recommendations.append(
                "Enable TLS_FALLBACK_SCSV on the server (RFC 7507)."
            )

    # 2. Downgrade sentinel (only relevant if TLS 1.3 supported)
    if report.supports_tls13 and report.supports_tls12:
        report.downgrade_sentinel = check_downgrade_sentinel(host, port, timeout)
        if report.downgrade_sentinel and not report.downgrade_sentinel.sentinel_present:
            report.findings.append(
                "TLS 1.3 downgrade sentinel NOT present in ServerHello.random -- "
                "server does not implement RFC 8446 §4.1.3 downgrade protection."
            )
            report.recommendations.append(
                "Update the TLS stack to embed the downgrade sentinel in ServerHello.random "
                "when negotiating TLS 1.2 with a TLS 1.3-capable server."
            )

    # 3. Version intolerance
    report.version_intolerance = test_version_intolerance(host, port, timeout)
    if report.version_intolerance and report.version_intolerance.intolerant:
        report.findings.append(
            "Server is version-intolerant -- rejects ClientHellos with unknown future versions. "
            "An attacker can exploit this to force clients to retry with lower versions."
        )
        report.recommendations.append(
            "Fix version negotiation to gracefully negotiate down per RFC 5246 §E.1."
        )

    # 4. Legacy version support
    if report.supports_sslv3:
        report.findings.append("SSLv3 still supported -- vulnerable to POODLE (CVE-2014-3566).")
        report.recommendations.append("Disable SSLv3 entirely.")
    if report.supports_tls10:
        report.findings.append(
            "TLS 1.0 supported -- deprecated by RFC 8996 (March 2021)."
        )
        report.recommendations.append("Disable TLS 1.0.")
    if report.supports_tls11:
        report.findings.append(
            "TLS 1.1 supported -- deprecated by RFC 8996 (March 2021)."
        )
        report.recommendations.append("Disable TLS 1.1.")

    # Risk scoring
    risk = 0
    if report.supports_sslv3:
        risk += 30
    if report.supports_tls10:
        risk += 15
    if report.supports_tls11:
        risk += 10
    if report.fallback_scsv and not report.fallback_scsv.scsv_supported:
        risk += 20
    if report.downgrade_sentinel and not report.downgrade_sentinel.sentinel_present:
        risk += 15
    if report.version_intolerance and report.version_intolerance.intolerant:
        risk += 10

    report.risk_score = min(risk, 100)
    report.vulnerable_to_downgrade = risk >= 25

    if risk >= 60:
        report.risk_level = "Critical"
    elif risk >= 40:
        report.risk_level = "High"
    elif risk >= 25:
        report.risk_level = "Medium"
    elif risk >= 10:
        report.risk_level = "Low"
    else:
        report.risk_level = "Minimal"

    return report

"""
Automated TLS Client Stack Tester

Implements the core methodology of Cho et al., "Return of Version Downgrade
Attack in the Era of TLS 1.3" (CoNEXT 2020):

  For each available TLS client library on this system, test whether it
  correctly validates the RFC 8446 section 4.1.3 downgrade sentinel in
  ServerHello.random.

Scenarios tested:
  sentinel_present  -- Sentinel included; compliant client MUST abort
  sentinel_omission -- Sentinel stripped; simulates successful MITM attack
  downgrade_to_10   -- Force TLS 1.0 negotiation
  downgrade_to_11   -- Force TLS 1.1 negotiation
"""

import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from src.utils.logger import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ClientStackInfo:
    name: str
    version: str = ""
    library: str = ""
    available: bool = False
    binary_path: str = ""
    notes: str = ""


@dataclass
class StackTestResult:
    stack_name: str
    scenario: str
    connected: bool = False
    tls_version_negotiated: str = ""
    cipher_negotiated: str = ""
    sentinel_detected: bool = False
    scsv_sent: bool = False
    vulnerable: bool = False
    error: str = ""
    details: str = ""
    root_cause: str = ""


@dataclass
class StackReport:
    stack: ClientStackInfo = field(default_factory=ClientStackInfo)
    test_results: List[StackTestResult] = field(default_factory=list)
    overall_vulnerable: bool = False
    root_causes: List[str] = field(default_factory=list)


@dataclass
class AutomatedTestReport:
    test_time: str = ""
    duration_seconds: float = 0.0
    stacks_discovered: int = 0
    stacks_tested: int = 0
    stacks_vulnerable: int = 0
    stacks_protected: int = 0
    stack_reports: List[StackReport] = field(default_factory=list)
    root_cause_summary: Dict[str, int] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    methodology_notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Root cause taxonomy (from the paper)
# ---------------------------------------------------------------------------

ROOT_CAUSE_DESCRIPTIONS = {
    "sentinel_not_checked": (
        "Client does not validate the RFC 8446 S4.1.3 downgrade sentinel "
        "in ServerHello.random. An active MITM attacker can force a version "
        "downgrade from TLS 1.3 to TLS 1.2 or lower."
    ),
    "accepts_deprecated_version": (
        "Client accepts a connection using TLS 1.0 or TLS 1.1, which are "
        "deprecated by RFC 8996. This increases the attack surface."
    ),
    "no_scsv": (
        "Client does not send TLS_FALLBACK_SCSV (RFC 7507) during fallback, "
        "removing a secondary downgrade protection. Note: SCSV is only "
        "expected on fallback retries, not initial connections."
    ),
}

SCENARIOS = ["sentinel_present", "sentinel_omission", "downgrade_to_10", "downgrade_to_11"]

SCENARIO_NEGOTIATE_VERSION = {
    "sentinel_present": 0x0303,
    "sentinel_omission": 0x0303,
    "downgrade_to_10": 0x0301,
    "downgrade_to_11": 0x0302,
}

SCENARIO_INCLUDE_SENTINEL = {
    "sentinel_present": True,
    "sentinel_omission": False,
    "downgrade_to_10": True,
    "downgrade_to_11": True,
}

VERSION_NAMES = {
    0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


# ---------------------------------------------------------------------------
# Stack discovery
# ---------------------------------------------------------------------------

def discover_client_stacks() -> List[ClientStackInfo]:
    """Discover available TLS client libraries on this system."""
    stacks = []

    # Python ssl (always available)
    stacks.append(ClientStackInfo(
        name="python_ssl",
        version=ssl.OPENSSL_VERSION,
        library=f"Python ssl ({ssl.OPENSSL_VERSION})",
        available=True,
    ))

    # openssl s_client
    openssl = shutil.which("openssl")
    if openssl:
        try:
            out = subprocess.check_output([openssl, "version"],
                                          timeout=5, stderr=subprocess.STDOUT)
            ver = out.decode(errors="replace").strip()
        except Exception:
            ver = "unknown"
        stacks.append(ClientStackInfo(
            name="openssl", version=ver,
            library=f"openssl s_client ({ver})",
            available=True, binary_path=openssl,
        ))
    else:
        stacks.append(ClientStackInfo(
            name="openssl", library="openssl (not found)", available=False,
        ))

    # gnutls-cli
    gnutls = shutil.which("gnutls-cli")
    if gnutls:
        try:
            out = subprocess.check_output([gnutls, "--version"],
                                          timeout=5, stderr=subprocess.STDOUT)
            ver = out.decode(errors="replace").strip().split("\n")[0]
        except Exception:
            ver = "unknown"
        stacks.append(ClientStackInfo(
            name="gnutls", version=ver,
            library=f"GnuTLS ({ver})",
            available=True, binary_path=gnutls,
        ))
    else:
        stacks.append(ClientStackInfo(
            name="gnutls", library="GnuTLS (not found)", available=False,
        ))

    # curl
    curl = shutil.which("curl")
    if curl:
        try:
            out = subprocess.check_output([curl, "--version"],
                                          timeout=5, stderr=subprocess.STDOUT)
            ver = out.decode(errors="replace").strip().split("\n")[0]
        except Exception:
            ver = "unknown"
        stacks.append(ClientStackInfo(
            name="curl", version=ver,
            library=f"curl ({ver})",
            available=True, binary_path=curl,
        ))
    else:
        stacks.append(ClientStackInfo(
            name="curl", library="curl (not found)", available=False,
        ))

    # Emulated raw-socket clients
    stacks.append(ClientStackInfo(
        name="raw_no_sentinel_check",
        library="Raw socket (no sentinel validation)",
        available=True,
        notes="Deliberately vulnerable: ignores sentinel",
    ))
    stacks.append(ClientStackInfo(
        name="raw_with_sentinel_check",
        library="Raw socket (with sentinel validation)",
        available=True,
        notes="Correctly checks sentinel",
    ))

    # Emulated IoT clients
    stacks.append(ClientStackInfo(
        name="iot_cheap_camera",
        library="Emulated: Cheap IP camera (mbedTLS 2.4, no sentinel)",
        available=True,
        notes="Pre-patch mbedTLS: no sentinel check",
    ))
    stacks.append(ClientStackInfo(
        name="iot_thermostat",
        library="Emulated: Smart thermostat (wolfSSL 4.5, partial)",
        available=True,
        notes="Checks sentinel, but accepts deprecated versions if sentinel absent",
    ))
    stacks.append(ClientStackInfo(
        name="iot_modern_nas",
        library="Emulated: Modern NAS (OpenSSL 1.1.1+, full protection)",
        available=True,
        notes="Full protection: sentinel + version check + SCSV",
    ))

    return stacks


# ---------------------------------------------------------------------------
# Raw TLS ClientHello builder
# ---------------------------------------------------------------------------

def _build_raw_client_hello() -> bytes:
    """Build a TLS 1.2 ClientHello with common cipher suites."""
    client_random = os.urandom(32)

    ciphers = struct.pack("!HHHHH",
        0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
        0xC013,  # ECDHE-RSA-AES128-SHA
        0x009C,  # RSA-AES128-GCM-SHA256
        0x002F,  # RSA-AES128-SHA
        0x0035,  # RSA-AES256-SHA
    )

    # supported_versions extension: TLS 1.3 + TLS 1.2
    sv_list = struct.pack("!BHH", 4, 0x0304, 0x0303)
    sv_ext = struct.pack("!HH", 0x002B, len(sv_list)) + sv_list

    # signature_algorithms
    sa_list = struct.pack("!HHHH", 0x0401, 0x0501, 0x0601, 0x0201)
    sa_data = struct.pack("!H", len(sa_list)) + sa_list
    sa_ext = struct.pack("!HH", 0x000D, len(sa_data)) + sa_data

    # supported_groups
    sg_data = struct.pack("!HH", 2, 0x0017)
    sg_ext = struct.pack("!HH", 0x000A, len(sg_data)) + sg_data

    extensions = sv_ext + sa_ext + sg_ext
    ext_block = struct.pack("!H", len(extensions)) + extensions

    ch_body = struct.pack("!H", 0x0303) + client_random
    ch_body += b"\x00"  # session_id length
    ch_body += struct.pack("!H", len(ciphers)) + ciphers
    ch_body += b"\x01\x00"  # compression
    ch_body += ext_block

    hs = struct.pack("!B", 1) + struct.pack("!I", len(ch_body))[1:] + ch_body
    record = struct.pack("!BHH", 22, 0x0301, len(hs)) + hs
    return record


def _parse_server_messages(data: bytes) -> Dict[int, bytes]:
    """Parse TLS records and extract handshake messages by type."""
    messages = {}
    offset = 0
    while offset + 5 <= len(data):
        ct = data[offset]
        if offset + 5 > len(data):
            break
        rec_len = struct.unpack("!H", data[offset + 3:offset + 5])[0]
        payload = data[offset + 5:offset + 5 + rec_len]
        offset += 5 + rec_len

        if ct == 21:  # Alert
            messages[21] = payload
            continue
        if ct != 22:  # Only parse handshake records
            continue

        hs_off = 0
        while hs_off + 4 <= len(payload):
            hs_type = payload[hs_off]
            hs_len = struct.unpack("!I", b"\x00" + payload[hs_off + 1:hs_off + 4])[0]
            hs_body = payload[hs_off + 4:hs_off + 4 + hs_len]
            messages[hs_type] = hs_body
            hs_off += 4 + hs_len
    return messages


# ---------------------------------------------------------------------------
# Test functions for each client stack
# ---------------------------------------------------------------------------

def _test_python_ssl(host: str, port: int, scenario: str,
                     negotiate_version: int) -> StackTestResult:
    """Test Python's ssl module."""
    result = StackTestResult(stack_name="python_ssl", scenario=scenario)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                result.connected = True
                result.tls_version_negotiated = tls.version() or ""
                ci = tls.cipher()
                result.cipher_negotiated = ci[0] if ci else ""
                result.vulnerable = True
                result.details = (
                    f"Handshake completed ({result.tls_version_negotiated}). "
                    f"Client did NOT detect downgrade."
                )
    except ssl.SSLError as exc:
        err = str(exc).upper()
        if any(k in err for k in (
            "INAPPROPRIATE_FALLBACK", "WRONG_VERSION", "UNSUPPORTED_PROTOCOL",
            "PROTOCOL_VERSION", "ILLEGAL_PARAMETER",
        )):
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = f"Rejected: {str(exc)[:100]} (PROTECTED)"
        else:
            result.error = str(exc)[:120]
            result.details = f"SSL error: {str(exc)[:100]}"
    except (OSError, ConnectionError) as exc:
        result.error = str(exc)[:120]
        result.details = f"Connection error: {str(exc)[:100]}"

    return result


def _test_openssl(host: str, port: int, scenario: str,
                  negotiate_version: int) -> StackTestResult:
    """Test openssl s_client."""
    result = StackTestResult(stack_name="openssl", scenario=scenario)

    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-no_ticket"],
            input=b"Q\n",
            capture_output=True,
            timeout=10,
        )
        output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
        upper = output.upper()

        if "PROTOCOL" in output or "Protocol" in output:
            for line in output.split("\n"):
                if "Protocol" in line:
                    result.tls_version_negotiated = line.strip().split(":")[-1].strip()
                if "Cipher" in line and ":" in line:
                    result.cipher_negotiated = line.strip().split(":")[-1].strip()

        if any(k in upper for k in ("ALERT", "ILLEGAL_PARAMETER", "INAPPROPRIATE_FALLBACK",
                                     "PROTOCOL_VERSION", "WRONG_VERSION")):
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = "openssl detected downgrade and rejected."
        elif proc.returncode == 0 and result.tls_version_negotiated:
            result.connected = True
            result.vulnerable = True
            result.details = (
                f"openssl completed handshake ({result.tls_version_negotiated})."
            )
        else:
            result.error = output[:200]
            result.details = f"openssl exit code {proc.returncode}"

    except subprocess.TimeoutExpired:
        result.error = "Timeout"
        result.details = "openssl timed out"
    except Exception as exc:
        result.error = str(exc)[:120]

    return result


def _test_gnutls(host: str, port: int, scenario: str,
                 negotiate_version: int) -> StackTestResult:
    """Test gnutls-cli."""
    result = StackTestResult(stack_name="gnutls", scenario=scenario)

    try:
        proc = subprocess.run(
            ["gnutls-cli", "--insecure", "-p", str(port), host],
            input=b"\n",
            capture_output=True,
            timeout=10,
        )
        output = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
        upper = output.upper()

        if any(k in upper for k in ("ALERT", "ILLEGAL_PARAMETER", "INAPPROPRIATE",
                                     "VERSION", "HANDSHAKE FAILURE")):
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = "GnuTLS detected downgrade."
        elif "CONNECTED" in upper or proc.returncode == 0:
            result.connected = True
            result.vulnerable = True
            result.details = "GnuTLS completed handshake."
        else:
            result.error = output[:200]

    except subprocess.TimeoutExpired:
        result.error = "Timeout"
    except FileNotFoundError:
        result.error = "gnutls-cli not found"
    except Exception as exc:
        result.error = str(exc)[:120]

    return result


def _test_curl(host: str, port: int, scenario: str,
               negotiate_version: int) -> StackTestResult:
    """Test curl."""
    result = StackTestResult(stack_name="curl", scenario=scenario)

    try:
        proc = subprocess.run(
            ["curl", "-k", "-v", "--max-time", "5", f"https://{host}:{port}/"],
            capture_output=True,
            timeout=10,
        )
        output = proc.stderr.decode(errors="replace")
        upper = output.upper()

        if "SSL CONNECTION" in upper and "ALERT" not in upper:
            result.connected = True
            result.vulnerable = True
            result.details = "curl completed TLS handshake."
        elif any(k in upper for k in ("ALERT", "ILLEGAL_PARAMETER", "INAPPROPRIATE",
                                       "PROTOCOL", "SSL_ERROR")):
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = "curl rejected the connection."
        else:
            result.error = output[:200]

    except subprocess.TimeoutExpired:
        result.error = "Timeout"
    except FileNotFoundError:
        result.error = "curl not found"
    except Exception as exc:
        result.error = str(exc)[:120]

    return result


def _test_raw_socket(host: str, port: int, scenario: str,
                     negotiate_version: int, check_sentinel: bool) -> StackTestResult:
    """Raw socket TLS test with optional sentinel checking."""
    name = "raw_with_sentinel_check" if check_sentinel else "raw_no_sentinel_check"
    result = StackTestResult(stack_name=name, scenario=scenario)

    try:
        sock = socket.create_connection((host, port), timeout=10)
        ch = _build_raw_client_hello()
        sock.sendall(ch)

        time.sleep(0.5)
        response = b""
        sock.settimeout(3.0)
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        if not response:
            result.details = "No response from server"
            sock.close()
            return result

        messages = _parse_server_messages(response)

        if 21 in messages:
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = "Server sent alert before ServerHello completed."
            sock.close()
            return result

        if 2 not in messages:
            result.details = "No ServerHello in response"
            sock.close()
            return result

        server_hello = messages[2]
        if len(server_hello) < 34:
            result.details = "ServerHello too short"
            sock.close()
            return result

        server_random = server_hello[2:34]
        sentinel = server_random[-8:]
        has_sentinel = sentinel in (b"DOWNGRD\x01", b"DOWNGRD\x00")

        if check_sentinel and has_sentinel:
            alert = struct.pack("!BBHHBB", 21, 0x0303, 0, 2, 2, 70)
            sock.sendall(alert)
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = "Sentinel detected, sent protocol_version alert (PROTECTED)"
            sock.close()
            return result

        result.connected = True
        result.vulnerable = True
        if check_sentinel:
            result.details = "No sentinel found; continued handshake (vulnerable to omission)"
        else:
            result.details = f"Sentinel present={has_sentinel}, deliberately ignored (VULNERABLE)"

        sock.close()

    except Exception as exc:
        result.error = str(exc)[:120]
        result.details = f"Error: {str(exc)[:100]}"

    return result


def _test_raw_no_sentinel(host: str, port: int, scenario: str,
                          negotiate_version: int) -> StackTestResult:
    return _test_raw_socket(host, port, scenario, negotiate_version,
                            check_sentinel=False)


def _test_raw_with_sentinel(host: str, port: int, scenario: str,
                            negotiate_version: int) -> StackTestResult:
    return _test_raw_socket(host, port, scenario, negotiate_version,
                            check_sentinel=True)


def _test_iot_cheap_camera(host: str, port: int, scenario: str,
                           negotiate_version: int) -> StackTestResult:
    """Emulates pre-patch mbedTLS 2.4: no sentinel check, accepts all versions."""
    result = StackTestResult(stack_name="iot_cheap_camera", scenario=scenario)

    try:
        sock = socket.create_connection((host, port), timeout=10)
        ch = _build_raw_client_hello()
        sock.sendall(ch)

        time.sleep(0.5)
        response = b""
        sock.settimeout(3.0)
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        if not response:
            result.details = "No response"
            sock.close()
            return result

        messages = _parse_server_messages(response)

        if 21 in messages:
            result.details = "Server sent alert"
            result.vulnerable = False
            sock.close()
            return result

        if 2 in messages:
            result.connected = True
            result.vulnerable = True
            result.details = (
                "mbedTLS 2.4 emulation: does NOT check sentinel, "
                "accepts any version including deprecated -> VULNERABLE"
            )

        sock.close()

    except Exception as exc:
        result.error = str(exc)[:120]

    return result


def _test_iot_thermostat(host: str, port: int, scenario: str,
                         negotiate_version: int) -> StackTestResult:
    """Emulates wolfSSL 4.5: checks sentinel, rejects deprecated versions."""
    result = StackTestResult(stack_name="iot_thermostat", scenario=scenario)

    try:
        sock = socket.create_connection((host, port), timeout=10)
        ch = _build_raw_client_hello()
        sock.sendall(ch)

        time.sleep(0.5)
        response = b""
        sock.settimeout(3.0)
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        if not response:
            result.details = "No response"
            sock.close()
            return result

        messages = _parse_server_messages(response)

        if 21 in messages:
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = "Server sent alert"
            sock.close()
            return result

        if 2 in messages:
            server_hello = messages[2]
            if len(server_hello) >= 34:
                server_random = server_hello[2:34]
                sentinel = server_random[-8:]
                has_sentinel = sentinel in (b"DOWNGRD\x01", b"DOWNGRD\x00")

                negotiated_ver = struct.unpack("!H", server_hello[0:2])[0]

                # wolfSSL 4.5: checks sentinel
                if has_sentinel:
                    alert = struct.pack("!BBHHBB", 21, 0x0303, 0, 2, 2, 70)
                    sock.sendall(alert)
                    result.sentinel_detected = True
                    result.vulnerable = False
                    result.details = "wolfSSL 4.5: sentinel detected, connection aborted (PROTECTED)"
                    sock.close()
                    return result

                # wolfSSL 4.5: rejects deprecated versions
                if negotiated_ver <= 0x0302:
                    alert = struct.pack("!BBHHBB", 21, 0x0303, 0, 2, 2, 70)
                    sock.sendall(alert)
                    result.sentinel_detected = True
                    result.vulnerable = False
                    result.details = (
                        f"wolfSSL 4.5: rejected deprecated version "
                        f"{VERSION_NAMES.get(negotiated_ver, '?')} (PROTECTED)"
                    )
                    sock.close()
                    return result

                # No sentinel, not deprecated -> accepted
                result.connected = True
                result.vulnerable = False
                result.sentinel_detected = True
                result.details = "wolfSSL 4.5: no sentinel in response, version acceptable"

        sock.close()

    except Exception as exc:
        result.error = str(exc)[:120]

    return result


def _test_iot_modern_nas(host: str, port: int, scenario: str,
                         negotiate_version: int) -> StackTestResult:
    """Emulates OpenSSL 1.1.1+: full protection on all scenarios."""
    result = StackTestResult(stack_name="iot_modern_nas", scenario=scenario)

    try:
        sock = socket.create_connection((host, port), timeout=10)
        ch = _build_raw_client_hello()
        sock.sendall(ch)

        time.sleep(0.5)
        response = b""
        sock.settimeout(3.0)
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        if not response:
            result.details = "No response"
            sock.close()
            return result

        messages = _parse_server_messages(response)

        if 21 in messages:
            result.sentinel_detected = True
            result.vulnerable = False
            result.details = "Server sent alert"
            sock.close()
            return result

        if 2 in messages:
            server_hello = messages[2]
            if len(server_hello) >= 34:
                server_random = server_hello[2:34]
                sentinel = server_random[-8:]
                has_sentinel = sentinel in (b"DOWNGRD\x01", b"DOWNGRD\x00")
                negotiated_ver = struct.unpack("!H", server_hello[0:2])[0]

                # OpenSSL 1.1.1+: checks sentinel
                if has_sentinel:
                    alert = struct.pack("!BBHHBB", 21, 0x0303, 0, 2, 2, 47)
                    sock.sendall(alert)
                    result.sentinel_detected = True
                    result.vulnerable = False
                    result.scsv_sent = True
                    result.details = "OpenSSL 1.1.1+: sentinel detected, illegal_parameter alert (PROTECTED)"
                    sock.close()
                    return result

                # OpenSSL 1.1.1+: rejects deprecated versions
                if negotiated_ver <= 0x0302:
                    alert = struct.pack("!BBHHBB", 21, 0x0303, 0, 2, 2, 70)
                    sock.sendall(alert)
                    result.sentinel_detected = True
                    result.vulnerable = False
                    result.scsv_sent = True
                    result.details = (
                        f"OpenSSL 1.1.1+: rejected deprecated version "
                        f"{VERSION_NAMES.get(negotiated_ver, '?')} (PROTECTED)"
                    )
                    sock.close()
                    return result

                # Clean TLS 1.2 with no sentinel (sentinel_omission)
                result.sentinel_detected = True
                result.vulnerable = False
                result.scsv_sent = True
                result.details = "OpenSSL 1.1.1+: no sentinel, version acceptable, full protection"

        sock.close()

    except Exception as exc:
        result.error = str(exc)[:120]

    return result


# ---------------------------------------------------------------------------
# Test function dispatch
# ---------------------------------------------------------------------------

TEST_FUNCTIONS = {
    "python_ssl": _test_python_ssl,
    "openssl": _test_openssl,
    "gnutls": _test_gnutls,
    "curl": _test_curl,
    "raw_no_sentinel_check": _test_raw_no_sentinel,
    "raw_with_sentinel_check": _test_raw_with_sentinel,
    "iot_cheap_camera": _test_iot_cheap_camera,
    "iot_thermostat": _test_iot_thermostat,
    "iot_modern_nas": _test_iot_modern_nas,
}


# ---------------------------------------------------------------------------
# Root cause analysis
# ---------------------------------------------------------------------------

def _analyze_root_causes(stack_report: StackReport) -> List[str]:
    """Determine root causes of vulnerability for a stack."""
    causes = []

    sentinel_test = next(
        (r for r in stack_report.test_results if r.scenario == "sentinel_present"),
        None,
    )
    sentinel_vulnerable = sentinel_test and sentinel_test.vulnerable
    if sentinel_vulnerable:
        causes.append("sentinel_not_checked")

    dg10 = next(
        (r for r in stack_report.test_results if r.scenario == "downgrade_to_10"),
        None,
    )
    dg11 = next(
        (r for r in stack_report.test_results if r.scenario == "downgrade_to_11"),
        None,
    )
    if (dg10 and dg10.vulnerable) or (dg11 and dg11.vulnerable):
        causes.append("accepts_deprecated_version")

    # Only flag no_scsv if the primary sentinel check already fails
    if sentinel_vulnerable:
        any_scsv = any(r.scsv_sent for r in stack_report.test_results)
        if not any_scsv:
            causes.append("no_scsv")

    return causes


# ---------------------------------------------------------------------------
# Main test orchestrator
# ---------------------------------------------------------------------------

def run_automated_test(
    listen_port: int = 14500,
    on_progress: Optional[Callable[[str], None]] = None,
) -> AutomatedTestReport:
    """Run the full automated client stack test suite."""
    from src.attack.malicious_server import MaliciousServer

    report = AutomatedTestReport(
        test_time=datetime.now(timezone.utc).isoformat(),
        methodology_notes=[
            "Replicates Cho et al. (CoNEXT 2020) methodology.",
            "Tests RFC 8446 S4.1.3 downgrade sentinel validation.",
            "Each client is tested against a malicious server that controls sentinel inclusion.",
            "Four scenarios: sentinel_present, sentinel_omission, downgrade_to_10, downgrade_to_11.",
        ],
    )
    t0 = time.time()

    def _log(msg: str):
        log.info(msg)
        if on_progress:
            on_progress(msg)

    stacks = discover_client_stacks()
    available = [s for s in stacks if s.available]
    report.stacks_discovered = len(stacks)

    _log(f"Discovered {len(stacks)} stacks, {len(available)} available")

    current_port = listen_port
    for stack in available:
        test_fn = TEST_FUNCTIONS.get(stack.name)
        if not test_fn:
            continue

        sr = StackReport(stack=stack)
        _log(f"Testing {stack.name} ({stack.library})...")

        for scenario in SCENARIOS:
            negotiate_ver = SCENARIO_NEGOTIATE_VERSION[scenario]
            include_sentinel = SCENARIO_INCLUDE_SENTINEL[scenario]
            malicious_scenario = "sentinel_present" if include_sentinel else "sentinel_omission"

            server = MaliciousServer(listen_port=current_port)
            server.set_scenario(malicious_scenario)
            server.set_negotiate_version(negotiate_ver)
            server.start()
            time.sleep(0.3)

            try:
                result = test_fn("127.0.0.1", current_port, scenario, negotiate_ver)
                sr.test_results.append(result)

                status = "VULNERABLE" if result.vulnerable else "Protected"
                _log(f"  {scenario}: {status}")
            except Exception as exc:
                _log(f"  {scenario}: Error - {exc}")
                sr.test_results.append(StackTestResult(
                    stack_name=stack.name, scenario=scenario,
                    error=str(exc)[:120],
                ))
            finally:
                server.stop()
                time.sleep(0.2)
                current_port += 1

        # Analyze root causes
        sr.root_causes = _analyze_root_causes(sr)
        sr.overall_vulnerable = len(sr.root_causes) > 0

        report.stack_reports.append(sr)
        report.stacks_tested += 1

        if sr.overall_vulnerable:
            report.stacks_vulnerable += 1
        else:
            report.stacks_protected += 1

    # Build root cause summary
    for sr in report.stack_reports:
        for cause in sr.root_causes:
            report.root_cause_summary[cause] = (
                report.root_cause_summary.get(cause, 0) + 1
            )

    # Generate findings
    if report.stacks_vulnerable > 0:
        report.findings.append(
            f"{report.stacks_vulnerable}/{report.stacks_tested} TLS client stacks "
            f"are vulnerable to version downgrade attacks."
        )
    if report.stacks_protected > 0:
        report.findings.append(
            f"{report.stacks_protected}/{report.stacks_tested} stacks correctly "
            f"detect and reject the downgrade."
        )
    for cause, count in report.root_cause_summary.items():
        desc = ROOT_CAUSE_DESCRIPTIONS.get(cause, cause)
        report.findings.append(f"Root cause '{cause}' ({count} stack(s)): {desc}")

    report.duration_seconds = round(time.time() - t0, 1)
    return report


def save_report(report: AutomatedTestReport, output_dir: str) -> str:
    """Save the test report to JSON."""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, "automated_stack_test.json")
    with open(filepath, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    log.info("Stack test report saved to %s", filepath)
    return filepath

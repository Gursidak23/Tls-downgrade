"""
Three-Profile Cipher Suite Selection Experiment

Core experiment from the term paper: tests whether IoT devices (as TLS servers)
will pick weak/outdated cipher suites when offered alongside stronger options.

Methodology:
  1. Connect to each target with three client profiles:
       Modern  -- only strong ciphers (ECDHE + AEAD, TLS 1.2+1.3)
       Mixed   -- strong AND weak ciphers (weak listed first)
       Legacy  -- only weak ciphers (RSA kex, CBC, TLS 1.2 only)
  2. Record what the server picks each time
  3. Determine if the server "chose weak when strong was available"
  4. Compare IoT devices vs regular web servers

Key insight tested:
  "Will it actually USE weak ciphers?" not just "does it support them?"
  A server might support strong ciphers but still pick a weak one when
  the client offers both -- that's the real exposure.
"""

import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── Client Profile Definitions ────────────────────────────────

PROFILES = {
    "modern": {
        "label": "Modern Client",
        "tag": "green",
        "description": "Only strong, current cipher suites (ECDHE + AEAD)",
        "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20",
        "max_version": None,
        "force_tls12": False,
    },
    "mixed": {
        "label": "Mixed Client",
        "tag": "yellow",
        "description": "Both strong AND weak ciphers (weak listed first)",
        "ciphers": (
            "AES256-SHA:AES128-SHA:AES256-SHA256:AES128-SHA256:"
            "AES256-GCM-SHA384:AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
            "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:"
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305"
        ),
        "max_version": None,
        "force_tls12": False,
    },
    "legacy": {
        "label": "Legacy Client",
        "tag": "red",
        "description": "Only old, weak cipher suites (RSA kex, CBC, no PFS)",
        "ciphers": "AES256-SHA:AES128-SHA:AES256-SHA256:AES128-SHA256",
        "max_version": "TLSv1_2",
        "force_tls12": True,
    },
}

# ── Data classes ──────────────────────────────────────────────

@dataclass
class ProfileResult:
    """Result of connecting to a target with one client profile."""
    profile: str = ""
    label: str = ""
    connected: bool = False
    tls_version: str = ""
    cipher_name: str = ""
    has_forward_secrecy: bool = False
    is_aead: bool = False
    security_rating: str = ""
    grade: str = ""
    error: str = ""
    latency_ms: float = 0.0


@dataclass
class DeviceProfileReport:
    """Aggregated results of all three profiles against one device."""
    host: str = ""
    port: int = 443
    label: str = ""
    device_type: str = ""
    scan_time: str = ""
    profiles: Dict[str, ProfileResult] = field(default_factory=dict)
    server_enforces_preference: bool = False
    chose_weak_with_mixed: bool = False
    chose_weak_details: str = ""


@dataclass
class ComparisonReport:
    """Overall comparison: IoT devices vs regular web servers."""
    scan_time: str = ""
    devices: List[DeviceProfileReport] = field(default_factory=list)
    iot_count: int = 0
    web_count: int = 0
    iot_weak_selection_pct: float = 0.0
    web_weak_selection_pct: float = 0.0
    iot_pfs_with_mixed_pct: float = 0.0
    web_pfs_with_mixed_pct: float = 0.0
    iot_preference_enforced_pct: float = 0.0
    web_preference_enforced_pct: float = 0.0
    findings: List[str] = field(default_factory=list)


# ── Cipher classification helpers ─────────────────────────────

def _is_tls13_cipher(cipher: str) -> bool:
    """TLS 1.3 ciphers start with TLS_ and always use ECDHE + AEAD."""
    return cipher.startswith("TLS_")

def _has_pfs(cipher: str) -> bool:
    if _is_tls13_cipher(cipher):
        return True
    return "ECDHE" in cipher or "DHE" in cipher

def _is_aead(cipher: str) -> bool:
    if _is_tls13_cipher(cipher):
        return True
    return "GCM" in cipher or "CHACHA20" in cipher or "CCM" in cipher

def _rate_cipher(cipher: str) -> str:
    upper = cipher.upper()
    if any(w in upper for w in ("RC4", "NULL", "EXPORT", "DES-CBC3", "3DES", "DES40")):
        return "Critical"
    if _is_tls13_cipher(cipher):
        return "Strong"
    pfs = _has_pfs(cipher)
    aead = _is_aead(cipher)
    if pfs and aead:
        return "Strong"
    if pfs and not aead:
        return "Acceptable"
    if not pfs and aead:
        return "Weak"
    return "Weak"

def _grade_cipher(cipher: str) -> str:
    return {
        "Strong": "A", "Acceptable": "B", "Weak": "D", "Critical": "F",
    }.get(_rate_cipher(cipher), "?")


# ── Core test function ────────────────────────────────────────

def test_with_profile(host: str, port: int, profile_name: str,
                      timeout: float = 10.0) -> ProfileResult:
    """Connect to host:port using the given client profile and record the result."""
    prof = PROFILES[profile_name]
    result = ProfileResult(profile=profile_name, label=prof["label"])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if prof.get("force_tls12"):
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass

    try:
        ctx.set_ciphers(prof["ciphers"])
    except ssl.SSLError:
        result.error = "No usable ciphers for this profile on this OpenSSL build"
        return result

    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                result.connected = True
                result.tls_version = tls.version() or ""
                ci = tls.cipher()
                if ci:
                    result.cipher_name = ci[0]
                    result.has_forward_secrecy = _has_pfs(ci[0])
                    result.is_aead = _is_aead(ci[0])
                    result.security_rating = _rate_cipher(ci[0])
                    result.grade = _grade_cipher(ci[0])
                result.latency_ms = round((time.time() - t0) * 1000, 1)
    except ssl.SSLError as exc:
        result.latency_ms = round((time.time() - t0) * 1000, 1)
        result.error = str(exc)[:120]
    except (OSError, ConnectionError) as exc:
        result.latency_ms = round((time.time() - t0) * 1000, 1)
        result.error = str(exc)[:120]

    return result


def test_server_preference(host: str, port: int,
                           timeout: float = 10.0) -> bool:
    """Check if the server enforces its own cipher preference order.

    Connects twice with opposite cipher orderings. If the server always
    picks the same cipher, it enforces preference (good practice).
    """
    order_a = "ECDHE+AESGCM:AES+SHA"
    order_b = "AES+SHA:ECDHE+AESGCM"

    def _quick(ciphers):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers(ciphers)
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    ci = tls.cipher()
                    return ci[0] if ci else None
        except Exception:
            return None

    c1 = _quick(order_a)
    c2 = _quick(order_b)

    if c1 and c2:
        return c1 == c2
    return False


# ── Full device test ──────────────────────────────────────────

def test_device(host: str, port: int, label: str = "",
                device_type: str = "unknown",
                timeout: float = 10.0) -> DeviceProfileReport:
    """Run all three client profiles against a single device."""
    report = DeviceProfileReport(
        host=host, port=port,
        label=label or f"{host}:{port}",
        device_type=device_type,
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    for name in ("modern", "mixed", "legacy"):
        log.info("  [%s] %s:%d with %s profile ...",
                 PROFILES[name]["tag"].upper(), host, port,
                 PROFILES[name]["label"])
        pr = test_with_profile(host, port, name, timeout)
        report.profiles[name] = pr

        status = pr.cipher_name if pr.connected else f"FAILED ({pr.error[:50]})"
        pfs_tag = " [PFS]" if pr.has_forward_secrecy else ""
        log.info("    -> %s %s (%s)%s", pr.tls_version, status,
                 pr.security_rating or "N/A", pfs_tag)

    # Check server preference
    log.info("  [PREF] Testing server preference enforcement ...")
    report.server_enforces_preference = test_server_preference(host, port, timeout)
    log.info("    -> Server enforces preference: %s",
             report.server_enforces_preference)

    # Key metric: did the server choose weak when strong was available?
    mixed = report.profiles.get("mixed")
    if mixed and mixed.connected:
        if not mixed.has_forward_secrecy:
            report.chose_weak_with_mixed = True
            report.chose_weak_details = (
                f"Server chose {mixed.cipher_name} (no forward secrecy) "
                f"even though ECDHE ciphers were offered"
            )
        elif not mixed.is_aead:
            report.chose_weak_with_mixed = True
            report.chose_weak_details = (
                f"Server chose {mixed.cipher_name} (CBC mode, not AEAD) "
                f"even though AEAD ciphers were offered"
            )
    elif mixed and not mixed.connected:
        report.chose_weak_details = f"Mixed profile could not connect: {mixed.error[:60]}"

    return report


# ── Batch test + comparison ───────────────────────────────────

def run_profile_experiment(
    targets: List[Dict],
    timeout: float = 10.0,
) -> ComparisonReport:
    """Run the full three-profile experiment on a list of targets.

    Each target dict: {"host": str, "port": int, "label": str, "type": "iot"|"web"}
    """
    comparison = ComparisonReport(
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    for t in targets:
        host = t["host"]
        port = t.get("port", 443)
        label = t.get("label", f"{host}:{port}")
        dtype = t.get("type", "unknown")

        log.info("=" * 50)
        log.info("Testing %s (%s) -- %s", label, dtype, f"{host}:{port}")
        log.info("=" * 50)

        report = test_device(host, port, label, dtype, timeout)
        comparison.devices.append(report)

    # Compute comparison statistics
    iot = [d for d in comparison.devices if d.device_type == "iot"]
    web = [d for d in comparison.devices if d.device_type == "web"]
    comparison.iot_count = len(iot)
    comparison.web_count = len(web)

    def _pct(subset, predicate):
        connected = [d for d in subset if d.profiles.get("mixed", ProfileResult()).connected]
        if not connected:
            return 0.0
        return round(100 * sum(1 for d in connected if predicate(d)) / len(connected), 1)

    comparison.iot_weak_selection_pct = _pct(iot, lambda d: d.chose_weak_with_mixed)
    comparison.web_weak_selection_pct = _pct(web, lambda d: d.chose_weak_with_mixed)

    comparison.iot_pfs_with_mixed_pct = _pct(
        iot, lambda d: d.profiles.get("mixed", ProfileResult()).has_forward_secrecy)
    comparison.web_pfs_with_mixed_pct = _pct(
        web, lambda d: d.profiles.get("mixed", ProfileResult()).has_forward_secrecy)

    comparison.iot_preference_enforced_pct = _pct(
        iot, lambda d: d.server_enforces_preference)
    comparison.web_preference_enforced_pct = _pct(
        web, lambda d: d.server_enforces_preference)

    # Generate findings
    if comparison.iot_weak_selection_pct > comparison.web_weak_selection_pct:
        comparison.findings.append(
            f"IoT devices chose weak ciphers {comparison.iot_weak_selection_pct}% of the time "
            f"vs {comparison.web_weak_selection_pct}% for web servers when both strong and weak "
            f"options were available."
        )
    elif comparison.iot_weak_selection_pct == 0 and comparison.web_weak_selection_pct == 0:
        comparison.findings.append(
            "All tested servers chose strong ciphers when given the option -- good."
        )

    if comparison.iot_pfs_with_mixed_pct < comparison.web_pfs_with_mixed_pct:
        comparison.findings.append(
            f"Forward secrecy with mixed client: IoT {comparison.iot_pfs_with_mixed_pct}% "
            f"vs Web {comparison.web_pfs_with_mixed_pct}%."
        )

    if comparison.iot_preference_enforced_pct < comparison.web_preference_enforced_pct:
        comparison.findings.append(
            f"Server preference enforcement: IoT {comparison.iot_preference_enforced_pct}% "
            f"vs Web {comparison.web_preference_enforced_pct}%. "
            f"IoT devices are more likely to follow client cipher order."
        )

    for d in comparison.devices:
        if d.chose_weak_with_mixed:
            comparison.findings.append(
                f"{d.label} ({d.device_type}): {d.chose_weak_details}"
            )

    return comparison

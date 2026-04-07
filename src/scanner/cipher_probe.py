"""
Cipher Suite Probe – enumerates accepted cipher suites and detects server preference.

Strategy:
  1. Offer ALL known suites -> record which one the server picks.
  2. Remove the chosen suite, repeat until the server rejects.
  3. Detect whether the server enforces its own preference order
     (server-side preference) or just follows the client's order.
"""

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from src.scanner.constants import (
    CIPHER_SUITES,
    PROBE_ORDER_STRONG_FIRST,
    PROBE_ORDER_WEAK_FIRST,
    SecurityLevel,
    get_cipher_info,
    security_grade,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class CipherResult:
    code: int
    name: str
    kex: str
    auth: str
    enc: str
    mac: str
    security: str         # SecurityLevel label
    security_value: int   # Numeric security level
    grade: str            # Letter grade
    color: str
    notes: str = ""


@dataclass
class CipherScanResult:
    host: str
    port: int
    label: str
    scan_time: str = ""
    tls_version_tested: str = ""
    accepted_ciphers: List[CipherResult] = field(default_factory=list)
    server_preference_enforced: bool = False
    preferred_cipher: Optional[CipherResult] = None
    weakest_cipher: Optional[CipherResult] = None
    overall_grade: str = "?"
    forward_secrecy_support: bool = False
    aead_support: bool = False
    has_null_cipher: bool = False
    has_rc4: bool = False
    has_3des: bool = False
    has_export: bool = False
    has_cbc: bool = False


def _get_openssl_cipher_string(cipher_codes: List[int]) -> str:
    """Convert a list of cipher suite codes to an OpenSSL cipher string."""
    names = []
    for code in cipher_codes:
        info = CIPHER_SUITES.get(code)
        if info:
            names.append(info.name)
    if not names:
        return "ALL:COMPLEMENTOFALL:@SECLEVEL=0"
    return ":".join(names)


def _try_connect(host: str, port: int, cipher_string: str,
                 tls_version: str = "TLSv1.2",
                 timeout: float = 10.0) -> Optional[Tuple[str, str]]:
    """Attempt a TLS connection with a specific cipher string. Returns (cipher_name, version) or None."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(cipher_string)

        if tls_version == "TLSv1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        elif tls_version == "TLSv1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif tls_version == "TLSv1.1":
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            except (ValueError, AttributeError):
                return None
        elif tls_version == "TLSv1.0":
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
            except (ValueError, AttributeError):
                return None

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cipher_info = tls.cipher()
                if cipher_info:
                    return (cipher_info[0], tls.version())
    except (ssl.SSLError, OSError, ConnectionError):
        return None
    return None


def enumerate_ciphers(host: str, port: int,
                      tls_version: str = "TLSv1.2",
                      timeout: float = 10.0) -> List[str]:
    """
    Iteratively discover all cipher suites accepted by the server.
    Uses the successive-elimination approach.
    """
    accepted = []
    remaining_ciphers = "ALL:COMPLEMENTOFALL:@SECLEVEL=0"
    excluded = []

    for _ in range(200):  # safety cap
        cipher_str = remaining_ciphers
        if excluded:
            cipher_str += ":" + ":".join(f"!{c}" for c in excluded)

        result = _try_connect(host, port, cipher_str, tls_version, timeout)
        if result is None:
            break

        cipher_name, _ = result
        accepted.append(cipher_name)
        excluded.append(cipher_name)
        log.debug("  Accepted: %s", cipher_name)

    return accepted


def detect_server_preference(host: str, port: int,
                             tls_version: str = "TLSv1.2",
                             timeout: float = 10.0) -> bool:
    """
    Determine if the server enforces its own cipher preference order.
    Send two ClientHellos with cipher lists in opposite orders.
    If the server picks the same cipher both times, it enforces its preference.
    """
    try:
        ctx1 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx1.check_hostname = False
        ctx1.verify_mode = ssl.CERT_NONE
        ctx1.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
        if tls_version == "TLSv1.2":
            ctx1.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx1.maximum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx1.wrap_socket(raw, server_hostname=host) as tls:
                cipher1 = tls.cipher()[0]
    except Exception:
        return False

    try:
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        # Reverse the cipher string: put weakest first
        ctx2.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0:@STRENGTH")
        if tls_version == "TLSv1.2":
            ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx2.maximum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx2.wrap_socket(raw, server_hostname=host) as tls:
                cipher2 = tls.cipher()[0]
    except Exception:
        return False

    enforced = (cipher1 == cipher2)
    log.info("Server preference: order1->%s, order2->%s -> enforced=%s",
             cipher1, cipher2, enforced)
    return enforced


OPENSSL_TO_IANA = {
    # TLS 1.3
    "TLS_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384":       "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256":  "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256":       "TLS_AES_128_CCM_SHA256",
    # ECDHE-ECDSA GCM
    "ECDHE-ECDSA-AES128-GCM-SHA256":  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384":  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    # ECDHE-RSA GCM
    "ECDHE-RSA-AES128-GCM-SHA256":    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384":    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    # ECDHE ChaCha20
    "ECDHE-RSA-CHACHA20-POLY1305":     "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305":   "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    # DHE GCM
    "DHE-RSA-AES128-GCM-SHA256":  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "DHE-RSA-AES256-GCM-SHA384":  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    # ECDHE-ECDSA CBC
    "ECDHE-ECDSA-AES128-SHA":     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA":     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-ECDSA-AES128-SHA256":  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-ECDSA-AES256-SHA384":  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    # ECDHE-RSA CBC
    "ECDHE-RSA-AES128-SHA":       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA":       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-AES128-SHA256":    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-RSA-AES256-SHA384":    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    # RSA (no PFS)
    "AES128-SHA":     "TLS_RSA_WITH_AES_128_CBC_SHA",
    "AES256-SHA":     "TLS_RSA_WITH_AES_256_CBC_SHA",
    "AES128-SHA256":  "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "AES256-SHA256":  "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "AES128-GCM-SHA256":  "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "AES256-GCM-SHA384":  "TLS_RSA_WITH_AES_256_GCM_SHA384",
    # DHE CBC
    "DHE-RSA-AES128-SHA":     "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "DHE-RSA-AES256-SHA":     "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "DHE-RSA-AES128-SHA256":  "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "DHE-RSA-AES256-SHA256":  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    # Broken / legacy
    "DES-CBC3-SHA":   "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "RC4-SHA":        "TLS_RSA_WITH_RC4_128_SHA",
    "RC4-MD5":        "TLS_RSA_WITH_RC4_128_MD5",
    "ECDHE-ECDSA-RC4-SHA":  "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "ECDHE-RSA-RC4-SHA":    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "NULL-MD5":       "TLS_RSA_WITH_NULL_MD5",
    "NULL-SHA":       "TLS_RSA_WITH_NULL_SHA",
    "NULL-SHA256":    "TLS_RSA_WITH_NULL_SHA256",
}


def _classify_unknown_cipher(openssl_name: str) -> CipherResult:
    """Derive security properties from an OpenSSL cipher name we don't have in the DB."""
    from src.scanner.constants import SECURITY_COLORS, SECURITY_LABELS

    name = openssl_name.upper()
    kex = "RSA"
    if "ECDHE" in name:
        kex = "ECDHE"
    elif "DHE" in name:
        kex = "DHE"

    auth = "RSA"
    if "ECDSA" in name:
        auth = "ECDSA"
    elif "DSS" in name:
        auth = "DSS"
    elif "PSK" in name:
        auth = "PSK"

    enc = "?"
    if "AES256-GCM" in name or "AES-256-GCM" in name:
        enc = "AES-256-GCM"
    elif "AES128-GCM" in name or "AES-128-GCM" in name:
        enc = "AES-128-GCM"
    elif "CHACHA20" in name:
        enc = "CHACHA20-POLY1305"
    elif "AES256" in name:
        enc = "AES-256-CBC"
    elif "AES128" in name:
        enc = "AES-128-CBC"
    elif "3DES" in name or "DES-CBC3" in name:
        enc = "3DES-CBC"
    elif "RC4" in name:
        enc = "RC4-128"
    elif "NULL" in name:
        enc = "NULL"

    mac = "?"
    if "GCM" in name or "CHACHA20" in name:
        mac = "AEAD"
    elif "SHA384" in name:
        mac = "SHA-384"
    elif "SHA256" in name:
        mac = "SHA-256"
    elif "SHA" in name:
        mac = "SHA-1"
    elif "MD5" in name:
        mac = "MD5"

    # Security assessment
    from src.scanner.constants import SecurityLevel
    if "NULL" in enc or "RC4" in enc or "3DES" in enc or "EXPORT" in name or "DES-40" in name:
        sec = SecurityLevel.CRITICAL
    elif kex == "RSA":
        sec = SecurityLevel.WEAK
    elif "CBC" in enc:
        sec = SecurityLevel.LEGACY
    elif mac == "AEAD" and kex in ("ECDHE", "DHE"):
        sec = SecurityLevel.STRONG if "128" in enc else SecurityLevel.OPTIMAL
    else:
        sec = SecurityLevel.ACCEPTABLE

    return CipherResult(
        code=0, name=openssl_name, kex=kex, auth=auth, enc=enc, mac=mac,
        security=SECURITY_LABELS[sec],
        security_value=int(sec),
        grade=security_grade(sec),
        color=SECURITY_COLORS[sec],
        notes="",
    )


def _cipher_name_to_result(name: str) -> CipherResult:
    """Map an OpenSSL cipher name to our CipherResult via lookup table or heuristic."""
    from src.scanner.constants import SECURITY_COLORS, SECURITY_LABELS

    iana_name = OPENSSL_TO_IANA.get(name)
    if iana_name:
        for code, info in CIPHER_SUITES.items():
            if info.name == iana_name:
                return CipherResult(
                    code=code, name=info.name, kex=info.kex, auth=info.auth,
                    enc=info.enc, mac=info.mac,
                    security=SECURITY_LABELS[info.security],
                    security_value=int(info.security),
                    grade=security_grade(info.security),
                    color=SECURITY_COLORS[info.security],
                    notes=info.notes,
                )

    # Direct IANA name match (e.g. TLS 1.3 suites already use IANA names)
    for code, info in CIPHER_SUITES.items():
        if info.name == name:
            return CipherResult(
                code=code, name=info.name, kex=info.kex, auth=info.auth,
                enc=info.enc, mac=info.mac,
                security=SECURITY_LABELS[info.security],
                security_value=int(info.security),
                grade=security_grade(info.security),
                color=SECURITY_COLORS[info.security],
                notes=info.notes,
            )

    # Fall back to heuristic classification from the OpenSSL name itself
    return _classify_unknown_cipher(name)


def scan_ciphers(host: str, port: int, label: str = "",
                 tls_version: str = "TLSv1.2",
                 timeout: float = 10.0) -> CipherScanResult:
    """Full cipher suite scan for a target."""
    from datetime import datetime, timezone

    result = CipherScanResult(
        host=host, port=port, label=label,
        scan_time=datetime.now(timezone.utc).isoformat(),
        tls_version_tested=tls_version,
    )

    log.info("Enumerating cipher suites on %s:%d (%s) ...", host, port, tls_version)
    accepted_names = enumerate_ciphers(host, port, tls_version, timeout)

    for name in accepted_names:
        cr = _cipher_name_to_result(name)
        result.accepted_ciphers.append(cr)

    if result.accepted_ciphers:
        result.preferred_cipher = result.accepted_ciphers[0]
        result.weakest_cipher = min(result.accepted_ciphers,
                                    key=lambda c: c.security_value)

        # Flags
        result.forward_secrecy_support = any(
            c.kex in ("ECDHE", "DHE") for c in result.accepted_ciphers
        )
        result.aead_support = any(
            c.mac == "AEAD" for c in result.accepted_ciphers
        )
        result.has_null_cipher = any(
            "NULL" in c.enc for c in result.accepted_ciphers
        )
        result.has_rc4 = any(
            "RC4" in c.enc for c in result.accepted_ciphers
        )
        result.has_3des = any(
            "3DES" in c.enc for c in result.accepted_ciphers
        )
        result.has_export = any(
            "EXPORT" in c.name for c in result.accepted_ciphers
        )
        result.has_cbc = any(
            "CBC" in c.enc for c in result.accepted_ciphers
        )

        weakest_level = min(c.security_value for c in result.accepted_ciphers)
        result.overall_grade = security_grade(SecurityLevel(weakest_level))

    log.info("Detecting server cipher preference on %s:%d ...", host, port)
    result.server_preference_enforced = detect_server_preference(
        host, port, tls_version, timeout
    )

    return result

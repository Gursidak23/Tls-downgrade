"""
TLS Version Probe – tests which TLS protocol versions a server supports,
and checks for the RFC 8446 downgrade sentinel in ServerHello.random.

Strategy:
  For each version (SSLv3 through TLS 1.3), create a restricted SSLContext
  and attempt a handshake. If it succeeds, the version is supported.

  Separately, send a raw TLS 1.2 ClientHello to extract the ServerHello
  random bytes and look for the downgrade sentinel.
"""

import socket
import ssl
import struct
import time
from dataclasses import dataclass
from typing import Optional

from src.scanner.constants import (
    TLS13_DOWNGRADE_SENTINEL_11,
    TLS13_DOWNGRADE_SENTINEL_12,
    TLS_VERSION_NAMES,
    TLSVersion,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class VersionProbeResult:
    version_name: str
    version_code: int
    supported: bool = False
    negotiated_version: str = ""
    negotiated_cipher: str = ""
    error: str = ""
    latency_ms: float = 0.0


@dataclass
class DowngradeSentinelResult:
    sentinel_present: bool = False
    random_bytes_hex: str = ""
    details: str = ""


@dataclass
class VersionScanResult:
    host: str
    port: int
    label: str
    scan_time: str = ""
    versions: list = None
    highest_supported: str = ""
    lowest_supported: str = ""
    downgrade_sentinel: DowngradeSentinelResult = None

    def __post_init__(self):
        if self.versions is None:
            self.versions = []


def _make_context_for_version(version_code: int) -> Optional[ssl.SSLContext]:
    """Build an SSLContext restricted to exactly one TLS version.

    Uses a broad cipher list so the probe can connect to IoT devices
    that only offer legacy ciphers (RSA kex, CBC mode).
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Use a broad cipher list so we can connect to servers with weak configs.
        # The version probe's job is to check "does this version work?" -- cipher
        # quality assessment is cipher_probe's job.
        try:
            ctx.set_ciphers("ALL:!aNULL:!eNULL")
        except ssl.SSLError:
            pass

        if version_code == TLSVersion.TLS_1_3:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        elif version_code == TLSVersion.TLS_1_2:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif version_code == TLSVersion.TLS_1_1:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        elif version_code == TLSVersion.TLS_1_0:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif version_code == TLSVersion.SSL_3_0:
            ctx.minimum_version = ssl.TLSVersion.SSLv3
            ctx.maximum_version = ssl.TLSVersion.SSLv3
        else:
            return None
        return ctx
    except (ValueError, AttributeError):
        return None


def probe_version(host: str, port: int, version_code: int,
                  timeout: float = 10.0) -> VersionProbeResult:
    """Probe whether *host:port* supports a single TLS version."""
    version_name = TLS_VERSION_NAMES.get(version_code, f"0x{version_code:04X}")
    ctx = _make_context_for_version(version_code)
    if ctx is None:
        return VersionProbeResult(
            version_name=version_name, version_code=version_code,
            supported=False, error="Version not available in local OpenSSL build",
        )

    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                negotiated = tls.version()
                cipher = tls.cipher()
                latency = (time.time() - t0) * 1000
                return VersionProbeResult(
                    version_name=version_name,
                    version_code=version_code,
                    supported=True,
                    negotiated_version=negotiated,
                    negotiated_cipher=cipher[0] if cipher else None,
                    latency_ms=round(latency, 1),
                )
    except ssl.SSLError as exc:
        latency = (time.time() - t0) * 1000
        return VersionProbeResult(
            version_name=version_name, version_code=version_code,
            supported=False, error=str(exc), latency_ms=round(latency, 1),
        )
    except (OSError, ConnectionError) as exc:
        latency = (time.time() - t0) * 1000
        return VersionProbeResult(
            version_name=version_name, version_code=version_code,
            supported=False, error=str(exc), latency_ms=round(latency, 1),
        )


# ---------------------------------------------------------------------------
# Raw ClientHello for downgrade-sentinel extraction
# ---------------------------------------------------------------------------

def _build_client_hello_12(host: str) -> bytes:
    """
    Craft a minimal TLS 1.2 ClientHello with a broad set of cipher suites.
    We advertise TLS 1.2 as the max version so a TLS 1.3-capable server will
    negotiate 1.2, and we can inspect the random bytes for the downgrade sentinel.
    """
    import os
    client_random = os.urandom(32)

    ciphers = [
        0xC02F, 0xC030, 0xC02B, 0xC02C,  # ECDHE-GCM
        0x009E, 0x009F,                     # DHE-GCM
        0xC013, 0xC014, 0xC009, 0xC00A,    # ECDHE-CBC
        0x002F, 0x0035, 0x009C, 0x009D,    # RSA
        0x000A,                             # 3DES
    ]
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_len = struct.pack("!H", len(cipher_bytes))

    host_bytes = host.encode("ascii")
    sni_list = struct.pack("!BH", 0, len(host_bytes)) + host_bytes
    sni_ext = struct.pack("!H", len(sni_list)) + sni_list
    ext_sni = struct.pack("!HH", 0x0000, len(sni_ext)) + sni_ext

    groups = struct.pack("!HHH", 0x0017, 0x0018, 0x0019)
    groups_ext = struct.pack("!H", len(groups)) + groups
    ext_groups = struct.pack("!HH", 0x000A, len(groups_ext)) + groups_ext

    sig_algs = struct.pack("!HHHH", 0x0401, 0x0501, 0x0601, 0x0201)
    sig_ext = struct.pack("!H", len(sig_algs)) + sig_algs
    ext_sig = struct.pack("!HH", 0x000D, len(sig_ext)) + sig_ext

    extensions = ext_sni + ext_groups + ext_sig
    extensions_len = struct.pack("!H", len(extensions))

    client_hello = b""
    client_hello += struct.pack("!H", 0x0303)           # client_version = TLS 1.2
    client_hello += client_random
    client_hello += b"\x00"                               # session_id length = 0
    client_hello += cipher_len + cipher_bytes
    client_hello += b"\x01\x00"                           # compression_methods: null
    client_hello += extensions_len + extensions

    handshake = struct.pack("!B", 1) + struct.pack("!I", len(client_hello))[1:]
    handshake += client_hello

    record = struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake
    return record


def _parse_server_hello_random(data: bytes) -> Optional[bytes]:
    """Extract the 32-byte random from a ServerHello inside a TLS record."""
    if len(data) < 5:
        return None
    content_type = data[0]
    if content_type != 22:
        return None

    record_len = struct.unpack("!H", data[3:5])[0]
    payload = data[5:5 + record_len]
    if len(payload) < 4:
        return None

    hs_type = payload[0]
    if hs_type != 2:
        return None

    offset = 4 + 2
    if len(payload) < offset + 32:
        return None
    server_random = payload[offset:offset + 32]
    return server_random


def check_downgrade_sentinel(host: str, port: int,
                             timeout: float = 10.0) -> DowngradeSentinelResult:
    """
    Send a TLS 1.2-only ClientHello to a potentially TLS 1.3 server.
    If the server supports 1.3 but negotiates 1.2, RFC 8446 mandates that
    the last 8 bytes of ServerHello.random contain a specific sentinel value.
    """
    result = DowngradeSentinelResult()
    try:
        ch = _build_client_hello_12(host)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(ch)
            response = sock.recv(4096)

        server_random = _parse_server_hello_random(response)
        if server_random is None:
            result.details = "Could not parse ServerHello random"
            return result

        result.random_bytes_hex = server_random.hex()
        tail = server_random[-8:]

        if tail == TLS13_DOWNGRADE_SENTINEL_12:
            result.sentinel_present = True
            result.details = (
                "TLS 1.3 downgrade sentinel detected (DOWNGRD\\x01). "
                "Server correctly signals it supports TLS 1.3 but is negotiating 1.2."
            )
        elif tail == TLS13_DOWNGRADE_SENTINEL_11:
            result.sentinel_present = True
            result.details = (
                "TLS 1.3 downgrade sentinel detected (DOWNGRD\\x00). "
                "Server signals it supports TLS 1.2+ but is negotiating 1.1 or lower."
            )
        else:
            result.sentinel_present = False
            result.details = (
                "No downgrade sentinel found. If the server supports TLS 1.3, "
                "this means it does NOT implement the RFC 8446 downgrade protection -- "
                "potentially vulnerable to version downgrade attacks."
            )
    except Exception as exc:
        result.details = f"Sentinel check failed: {exc}"
    return result


def scan_versions(host: str, port: int, label: str = "",
                  timeout: float = 10.0) -> VersionScanResult:
    """Run a full version scan against a single target."""
    from datetime import datetime, timezone
    result = VersionScanResult(
        host=host, port=port, label=label,
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    ordered_versions = [
        TLSVersion.SSL_3_0,
        TLSVersion.TLS_1_0,
        TLSVersion.TLS_1_1,
        TLSVersion.TLS_1_2,
        TLSVersion.TLS_1_3,
    ]

    supported_codes = []
    for ver in ordered_versions:
        log.info("Probing %s:%d for %s ...", host, port,
                 TLS_VERSION_NAMES.get(ver, "?"))
        probe = probe_version(host, port, ver, timeout)
        result.versions.append(probe)
        if probe.supported:
            supported_codes.append(ver)

    if supported_codes:
        result.highest_supported = TLS_VERSION_NAMES.get(max(supported_codes))
        result.lowest_supported = TLS_VERSION_NAMES.get(min(supported_codes))

    if TLSVersion.TLS_1_3 in supported_codes and TLSVersion.TLS_1_2 in supported_codes:
        log.info("Checking TLS 1.3 downgrade sentinel on %s:%d ...", host, port)
        result.downgrade_sentinel = check_downgrade_sentinel(host, port, timeout)

    return result

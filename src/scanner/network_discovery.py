"""
Local Network IoT Device Discovery

Scans a local subnet for devices exposing TLS services (HTTPS, 8443, etc.).
Identifies potential IoT devices by fingerprinting common ports and banners.
"""

import ipaddress
import json
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from src.utils.logger import get_logger

log = get_logger(__name__)

IOT_PORTS = [443, 8443, 8080, 8888, 4443, 9443, 993, 995, 465, 636]

IOT_BANNER_HINTS = {
    "hikvision": "IP Camera (Hikvision)",
    "dahua": "IP Camera (Dahua)",
    "axis": "IP Camera (Axis)",
    "synology": "NAS (Synology)",
    "qnap": "NAS (QNAP)",
    "netgear": "Router (Netgear)",
    "tp-link": "Router (TP-Link)",
    "openwrt": "Router (OpenWrt)",
    "mikrotik": "Router (MikroTik)",
    "ubiquiti": "IoT Gateway (Ubiquiti)",
    "philips": "Smart Hub (Philips Hue)",
    "ring": "Doorbell (Ring)",
    "nest": "Thermostat (Nest)",
    "tuya": "Smart Device (Tuya)",
    "tapo": "Smart Plug (TP-Link Tapo)",
    "esp": "Microcontroller (ESP32/ESP8266)",
    "raspberry": "SBC (Raspberry Pi)",
    "lighttpd": "Embedded Web Server",
    "mini_httpd": "Embedded Web Server",
    "boa": "Embedded Web Server (Boa)",
    "goahead": "Embedded Web Server (GoAhead)",
    "thttpd": "Embedded Web Server",
}


@dataclass
class DiscoveredDevice:
    ip: str
    port: int
    tls_available: bool = False
    tls_version: Optional[str] = None
    certificate_cn: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_san: Optional[List[str]] = None
    server_banner: Optional[str] = None
    device_type: str = "Unknown"
    label: str = ""
    latency_ms: float = 0.0


@dataclass
class DiscoveryResult:
    subnet: str
    scan_time: str = ""
    total_hosts_scanned: int = 0
    devices_found: List[DiscoveredDevice] = field(default_factory=list)
    duration_ms: float = 0.0


def _check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, ConnectionError):
        return False


def _grab_tls_info(ip: str, port: int,
                   timeout: float = 3.0) -> Optional[DiscoveredDevice]:
    """Connect via TLS and extract certificate/version info."""
    dev = DiscoveredDevice(ip=ip, port=port)
    t0 = time.time()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                dev.tls_available = True
                dev.tls_version = tls.version()
                dev.latency_ms = round((time.time() - t0) * 1000, 1)

                cert = tls.getpeercert(binary_form=False)
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    dev.certificate_cn = subject.get("commonName", "")
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    dev.certificate_issuer = issuer.get("organizationName", "")
                    san = cert.get("subjectAltName", ())
                    dev.certificate_san = [v for _, v in san]

                # Try to grab server banner via HTTP HEAD
                try:
                    tls.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    tls.settimeout(2.0)
                    resp = tls.recv(2048).decode("utf-8", errors="replace")
                    for line in resp.split("\r\n"):
                        if line.lower().startswith("server:"):
                            dev.server_banner = line.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass

                # Classify device type from certificate and banner
                dev.device_type = _classify_device(dev)
                dev.label = dev.device_type if dev.device_type != "Unknown" else f"TLS Device {ip}:{port}"
                return dev
    except ssl.SSLError:
        dev.latency_ms = round((time.time() - t0) * 1000, 1)
        dev.tls_available = True
        dev.device_type = "TLS Device (handshake issue)"
        dev.label = f"TLS Device {ip}:{port}"
        return dev
    except (OSError, ConnectionError):
        return None


def _classify_device(dev: DiscoveredDevice) -> str:
    """Heuristic device classification from cert/banner strings."""
    searchable = " ".join(filter(None, [
        dev.certificate_cn, dev.certificate_issuer,
        dev.server_banner, str(dev.certificate_san),
    ])).lower()

    for keyword, dtype in IOT_BANNER_HINTS.items():
        if keyword in searchable:
            return dtype

    if dev.server_banner:
        banner_lower = dev.server_banner.lower()
        if any(w in banner_lower for w in ["nginx", "apache", "iis"]):
            return "Web Server"
        if "openssl" in banner_lower:
            return "Generic TLS Service"

    if dev.port in (8443, 4443, 9443):
        return "IoT/Embedded Device (alt HTTPS port)"
    if dev.port == 443:
        return "HTTPS Service"

    return "Unknown"


def discover_subnet(subnet: str, ports: Optional[List[int]] = None,
                    timeout: float = 2.0,
                    max_threads: int = 50) -> DiscoveryResult:
    """
    Scan a subnet for devices with TLS services.

    Args:
        subnet: CIDR notation, e.g. "192.168.1.0/24"
        ports: List of ports to check (default: IOT_PORTS)
        timeout: Per-connection timeout
        max_threads: Maximum concurrent scanning threads
    """
    from datetime import datetime, timezone

    if ports is None:
        ports = IOT_PORTS

    network = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    result = DiscoveryResult(
        subnet=subnet,
        scan_time=datetime.now(timezone.utc).isoformat(),
        total_hosts_scanned=len(hosts),
    )

    t0 = time.time()
    log.info("Scanning %d hosts on %s (ports: %s) ...", len(hosts), subnet,
             ", ".join(str(p) for p in ports))

    found_devices = []
    lock = threading.Lock()
    semaphore = threading.Semaphore(max_threads)

    def scan_host(ip):
        with semaphore:
            for port in ports:
                if _check_port(ip, port, timeout):
                    dev = _grab_tls_info(ip, port, timeout + 1)
                    if dev and dev.tls_available:
                        with lock:
                            found_devices.append(dev)
                        log.info("  Found: %s:%d -> %s (%s)",
                                 ip, port, dev.device_type, dev.tls_version or "?")

    threads = []
    for ip in hosts:
        t = threading.Thread(target=scan_host, args=(ip,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=timeout * len(ports) + 5)

    result.devices_found = found_devices
    result.duration_ms = round((time.time() - t0) * 1000, 1)

    log.info("Discovery complete: %d TLS devices found on %s in %.1fs",
             len(found_devices), subnet, result.duration_ms / 1000)
    return result


def discover_single(ip: str, ports: Optional[List[int]] = None,
                    timeout: float = 3.0) -> List[DiscoveredDevice]:
    """Scan a single IP for TLS services across common IoT ports."""
    if ports is None:
        ports = IOT_PORTS
    devices = []
    for port in ports:
        if _check_port(ip, port, timeout):
            dev = _grab_tls_info(ip, port, timeout)
            if dev and dev.tls_available:
                devices.append(dev)
    return devices

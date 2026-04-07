"""
IoT Device TLS Profile Database

Research-backed TLS configurations for virtual IoT device emulation.
Each profile replicates the exact TLS library version, cipher suite string,
and version range documented from real IoT firmware.

Academic sources:
  - Alrawi et al., "SoK: Security Evaluation of Home-Based IoT Deployments"
    (IEEE S&P 2019)
  - Kumar et al., "All Things Considered: An Analysis of IoT Devices on Home
    Networks" (IMC 2019)
  - Cho et al., "Return of Version Downgrade Attack in the Era of TLS 1.3"
    (CoNEXT 2020)
  - Shodan / Censys banner data (2019-2024)
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class IoTServerProfile:
    """TLS configuration for a virtual IoT server."""
    name: str
    category: str
    firmware_tls_library: str
    min_tls_version: str
    max_tls_version: str
    cipher_string: str
    enforce_server_preference: bool
    rsa_key_bits: int = 2048
    cert_cn: str = ""
    cert_org: str = ""
    source: str = ""
    notes: str = ""


@dataclass
class IoTClientProfile:
    """TLS client behavior profile for an IoT device."""
    name: str
    category: str
    firmware_tls_library: str
    checks_sentinel: bool
    accepts_tls10: bool
    accepts_tls11: bool
    sends_scsv: bool
    source: str = ""
    notes: str = ""


# ---------------------------------------------------------------------------
# Server profiles: 9 IoT + 3 web baselines = 12 total
# ---------------------------------------------------------------------------

IOT_SERVER_PROFILES: List[IoTServerProfile] = [
    # ── IP Cameras ───────────────────────────────────────────
    IoTServerProfile(
        name="Hikvision DS-2CD2xx5 (2019)",
        category="camera",
        firmware_tls_library="OpenSSL 1.0.2k",
        min_tls_version="TLSv1",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:"
            "AES128-GCM-SHA256:AES256-GCM-SHA384:"
            "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
            "ECDHE-RSA-AES128-GCM-SHA256"
        ),
        enforce_server_preference=False,
        rsa_key_bits=2048,
        cert_cn="ipcam.local",
        cert_org="Hangzhou Hikvision",
        source="Shodan banner analysis + firmware extraction",
        notes="Weak default cipher order, no server preference enforcement",
    ),
    IoTServerProfile(
        name="Dahua IPC-HDW5xxx (2020)",
        category="camera",
        firmware_tls_library="OpenSSL 1.0.2n",
        min_tls_version="TLSv1",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:"
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "AES128-GCM-SHA256:AES256-GCM-SHA384"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="camera.local",
        cert_org="Dahua Technology",
        source="Shodan banner analysis",
        notes="Server preference enforced but weak ciphers preferred",
    ),
    IoTServerProfile(
        name="Wyze Cam v2 (2021)",
        category="camera",
        firmware_tls_library="mbedTLS 2.16.6",
        min_tls_version="TLSv1_2",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES128-SHA256"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="wyzecam.local",
        cert_org="Wyze Labs",
        source="Kumar et al. IMC 2019 + firmware analysis",
        notes="Reasonable config for low-cost camera; TLS 1.2 only with ECDHE",
    ),

    # ── NAS Devices ──────────────────────────────────────────
    IoTServerProfile(
        name="WD My Cloud EX2 (2019)",
        category="nas",
        firmware_tls_library="OpenSSL 1.0.1t",
        min_tls_version="TLSv1",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "AES128-SHA:AES256-SHA:DES-CBC3-SHA:"
            "AES128-SHA256:AES256-SHA256:"
            "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
            "ECDHE-RSA-AES128-GCM-SHA256"
        ),
        enforce_server_preference=False,
        rsa_key_bits=1024,
        cert_cn="wdmycloud.local",
        cert_org="Western Digital",
        source="CVE-2019-9949 + Shodan",
        notes="Very old OpenSSL, 1024-bit RSA, 3DES still enabled",
    ),
    IoTServerProfile(
        name="Synology DS920+ (2023)",
        category="nas",
        firmware_tls_library="OpenSSL 1.1.1w",
        min_tls_version="TLSv1_2",
        max_tls_version="TLSv1_3",
        cipher_string=(
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="synology.local",
        cert_org="Synology Inc.",
        source="Synology DSM 7.2 release notes + Shodan",
        notes="Well-maintained; strong defaults with TLS 1.3",
    ),
    IoTServerProfile(
        name="QNAP TS-451+ (2020)",
        category="nas",
        firmware_tls_library="OpenSSL 1.0.2u",
        min_tls_version="TLSv1",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "AES128-GCM-SHA256"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="qnap.local",
        cert_org="QNAP Systems",
        source="CVE-2020-2509 + Shodan",
        notes="Older OpenSSL, mixed cipher strength",
    ),

    # ── Smart Home / Gateway ─────────────────────────────────
    IoTServerProfile(
        name="TP-Link Kasa Smart Plug (2020)",
        category="smart_home",
        firmware_tls_library="mbedTLS 2.16.2",
        min_tls_version="TLSv1_2",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "AES128-SHA256:AES256-SHA256:AES128-GCM-SHA256"
        ),
        enforce_server_preference=False,
        rsa_key_bits=2048,
        cert_cn="kasa.local",
        cert_org="TP-Link",
        source="Kumar et al. IMC 2019",
        notes="TLS 1.2 only; mixed ECDHE and RSA kex",
    ),

    # ── Medical Device ───────────────────────────────────────
    IoTServerProfile(
        name="Generic Medical Device (2018)",
        category="medical",
        firmware_tls_library="OpenSSL 0.9.8zh",
        min_tls_version="TLSv1",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "AES128-SHA:AES256-SHA:DES-CBC3-SHA:"
            "AES128-SHA256:AES128-GCM-SHA256"
        ),
        enforce_server_preference=False,
        rsa_key_bits=1024,
        cert_cn="meddevice.local",
        cert_org="Generic Medical Corp",
        source="Alrawi et al. IEEE S&P 2019 (composite profile)",
        notes="Very old OpenSSL; 1024-bit key; 3DES; represents worst-case medical IoT",
    ),

    # ── Modern IoT Gateway ───────────────────────────────────
    IoTServerProfile(
        name="Modern Smart Hub (2024)",
        category="gateway",
        firmware_tls_library="wolfSSL 5.6.3",
        min_tls_version="TLSv1_2",
        max_tls_version="TLSv1_3",
        cipher_string=(
            "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="smarthub.local",
        cert_org="SmartHome Inc",
        source="Composite: modern IoT best practice",
        notes="Represents well-designed 2024 IoT hub",
    ),

    # ── Web Baselines (for comparison) ───────────────────────
    IoTServerProfile(
        name="Nginx Modern (2024)",
        category="web_baseline",
        firmware_tls_library="OpenSSL 3.0",
        min_tls_version="TLSv1_2",
        max_tls_version="TLSv1_3",
        cipher_string=(
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="webserver.local",
        cert_org="Web Baseline",
        source="Mozilla SSL Configuration Generator (Modern)",
        notes="Web baseline: modern best-practice config",
    ),
    IoTServerProfile(
        name="Apache Legacy (2020)",
        category="web_baseline",
        firmware_tls_library="OpenSSL 1.0.2",
        min_tls_version="TLSv1",
        max_tls_version="TLSv1_2",
        cipher_string=(
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:"
            "AES128-GCM-SHA256"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="legacy-web.local",
        cert_org="Web Baseline",
        source="Mozilla SSL Configuration Generator (Old backward compat)",
        notes="Web baseline: legacy config for comparison",
    ),
    IoTServerProfile(
        name="Cloudflare Edge (2024)",
        category="web_baseline",
        firmware_tls_library="BoringSSL",
        min_tls_version="TLSv1_2",
        max_tls_version="TLSv1_3",
        cipher_string=(
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
        ),
        enforce_server_preference=True,
        rsa_key_bits=2048,
        cert_cn="edge.local",
        cert_org="Web Baseline",
        source="Cloudflare SSL docs + Qualys SSL Labs",
        notes="Web baseline: industry-leading TLS config",
    ),
]


# ---------------------------------------------------------------------------
# Client profiles: emulated IoT client-side TLS behaviors
# ---------------------------------------------------------------------------

IOT_CLIENT_PROFILES: List[IoTClientProfile] = [
    IoTClientProfile(
        name="Cheap IP Camera Client",
        category="camera",
        firmware_tls_library="mbedTLS 2.4 (pre-patch)",
        checks_sentinel=False,
        accepts_tls10=True,
        accepts_tls11=True,
        sends_scsv=False,
        source="Cho et al. CoNEXT 2020 (composite)",
        notes="Pre-patch mbedTLS: does not check sentinel at all",
    ),
    IoTClientProfile(
        name="Smart Thermostat Client",
        category="smart_home",
        firmware_tls_library="wolfSSL 4.5",
        checks_sentinel=True,
        accepts_tls10=True,
        accepts_tls11=True,
        sends_scsv=False,
        source="Cho et al. CoNEXT 2020 (composite)",
        notes="Checks sentinel correctly but still accepts deprecated versions",
    ),
    IoTClientProfile(
        name="Modern NAS Client",
        category="nas",
        firmware_tls_library="OpenSSL 1.1.1+",
        checks_sentinel=True,
        accepts_tls10=False,
        accepts_tls11=False,
        sends_scsv=True,
        source="OpenSSL 1.1.1 release notes",
        notes="Full protection: sentinel check + rejects deprecated + SCSV",
    ),
]


# ---------------------------------------------------------------------------
# Access helpers
# ---------------------------------------------------------------------------

def get_iot_server_profiles() -> List[IoTServerProfile]:
    """Return only IoT device profiles (not web baselines)."""
    return [p for p in IOT_SERVER_PROFILES if p.category != "web_baseline"]


def get_web_baseline_profiles() -> List[IoTServerProfile]:
    """Return only web-server baseline profiles."""
    return [p for p in IOT_SERVER_PROFILES if p.category == "web_baseline"]


def get_all_server_profiles() -> List[IoTServerProfile]:
    """Return all server profiles (IoT + web baselines)."""
    return list(IOT_SERVER_PROFILES)


def get_iot_client_profiles() -> List[IoTClientProfile]:
    """Return IoT client behavior profiles."""
    return list(IOT_CLIENT_PROFILES)

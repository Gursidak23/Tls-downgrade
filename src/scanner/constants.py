"""
TLS protocol constants: version codes, cipher suite definitions, and security ratings.

References:
  - RFC 8446 (TLS 1.3)
  - RFC 5246 (TLS 1.2)
  - IANA TLS Cipher Suite Registry
  - RFC 7507 (TLS Fallback SCSV)
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# TLS Record / Handshake version bytes
# ---------------------------------------------------------------------------

class TLSVersion(IntEnum):
    SSL_3_0 = 0x0300
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

TLS_VERSION_NAMES: Dict[int, str] = {
    TLSVersion.SSL_3_0: "SSLv3",
    TLSVersion.TLS_1_0: "TLS 1.0",
    TLSVersion.TLS_1_1: "TLS 1.1",
    TLSVersion.TLS_1_2: "TLS 1.2",
    TLSVersion.TLS_1_3: "TLS 1.3",
}

TLS_VERSION_FROM_NAME: Dict[str, int] = {
    "SSLv3":   TLSVersion.SSL_3_0,
    "TLSv1.0": TLSVersion.TLS_1_0,
    "TLSv1.1": TLSVersion.TLS_1_1,
    "TLSv1.2": TLSVersion.TLS_1_2,
    "TLSv1.3": TLSVersion.TLS_1_3,
}

# Python ssl module version constant mapping
SSL_VERSION_MAP = {
    "SSLv3":   "SSLv3",
    "TLSv1.0": "TLSv1",
    "TLSv1.1": "TLSv1_1",
    "TLSv1.2": "TLSv1_2",
    "TLSv1.3": "TLSv1_3",
}

# TLS 1.3 downgrade sentinels (RFC 8446 §4.1.3)
# Last 8 bytes of ServerHello.random when a TLS 1.3 server negotiates 1.2 or below
TLS13_DOWNGRADE_SENTINEL_12 = bytes.fromhex("444F574E47524401")  # "DOWNGRD\x01"
TLS13_DOWNGRADE_SENTINEL_11 = bytes.fromhex("444F574E47524400")  # "DOWNGRD\x00"

# TLS_FALLBACK_SCSV (RFC 7507) cipher suite value
TLS_FALLBACK_SCSV = 0x5600

# ---------------------------------------------------------------------------
# Security rating for cipher suite components
# ---------------------------------------------------------------------------

class SecurityLevel(IntEnum):
    CRITICAL = 0   # Broken, must not be used
    WEAK = 1       # Known weaknesses, should be avoided
    LEGACY = 2     # Acceptable for backward compat only
    ACCEPTABLE = 3 # Meets minimum bar
    STRONG = 4     # Recommended
    OPTIMAL = 5    # Best practice

@dataclass
class CipherSuiteInfo:
    code: int
    name: str
    protocol: str          # "TLS" or "SSL"
    kex: str               # Key exchange algorithm
    auth: str              # Authentication algorithm
    enc: str               # Encryption algorithm
    mac: str               # MAC algorithm
    security: SecurityLevel
    notes: str = ""

# ---------------------------------------------------------------------------
# Comprehensive cipher suite database
# Organised by TLS version families; security ratings based on 2024 best-practice.
# ---------------------------------------------------------------------------

CIPHER_SUITES: Dict[int, CipherSuiteInfo] = {}

def _add(code, name, proto, kex, auth, enc, mac, sec, notes=""):
    CIPHER_SUITES[code] = CipherSuiteInfo(code, name, proto, kex, auth, enc, mac, sec, notes)

# ---- TLS 1.3 cipher suites (AEAD only, no key-exchange/auth in suite) ----
_add(0x1301, "TLS_AES_128_GCM_SHA256",       "TLS1.3", "ANY", "ANY", "AES-128-GCM",       "AEAD", SecurityLevel.STRONG)
_add(0x1302, "TLS_AES_256_GCM_SHA384",       "TLS1.3", "ANY", "ANY", "AES-256-GCM",       "AEAD", SecurityLevel.OPTIMAL)
_add(0x1303, "TLS_CHACHA20_POLY1305_SHA256",  "TLS1.3", "ANY", "ANY", "CHACHA20-POLY1305", "AEAD", SecurityLevel.OPTIMAL)
_add(0x1304, "TLS_AES_128_CCM_SHA256",       "TLS1.3", "ANY", "ANY", "AES-128-CCM",       "AEAD", SecurityLevel.STRONG)
_add(0x1305, "TLS_AES_128_CCM_8_SHA256",     "TLS1.3", "ANY", "ANY", "AES-128-CCM-8",     "AEAD", SecurityLevel.ACCEPTABLE, "Truncated tag – IoT only")

# ---- TLS 1.2 ECDHE + AEAD (recommended) ----
_add(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",   "TLS1.2", "ECDHE", "ECDSA", "AES-128-GCM", "AEAD", SecurityLevel.STRONG)
_add(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",   "TLS1.2", "ECDHE", "ECDSA", "AES-256-GCM", "AEAD", SecurityLevel.OPTIMAL)
_add(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",     "TLS1.2", "ECDHE", "RSA",   "AES-128-GCM", "AEAD", SecurityLevel.STRONG)
_add(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",     "TLS1.2", "ECDHE", "RSA",   "AES-256-GCM", "AEAD", SecurityLevel.OPTIMAL)
_add(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",   "TLS1.2", "ECDHE", "RSA",   "CHACHA20-POLY1305", "AEAD", SecurityLevel.OPTIMAL)
_add(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS1.2", "ECDHE", "ECDSA", "CHACHA20-POLY1305", "AEAD", SecurityLevel.OPTIMAL)

# ---- TLS 1.2 DHE + AEAD ----
_add(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",   "TLS1.2", "DHE", "RSA", "AES-128-GCM", "AEAD", SecurityLevel.ACCEPTABLE)
_add(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",   "TLS1.2", "DHE", "RSA", "AES-256-GCM", "AEAD", SecurityLevel.ACCEPTABLE)

# ---- TLS 1.2 ECDHE + CBC (legacy but common in IoT) ----
_add(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",      "TLS1.2", "ECDHE", "ECDSA", "AES-128-CBC", "SHA-1",   SecurityLevel.LEGACY, "CBC mode – padding oracle risk")
_add(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",      "TLS1.2", "ECDHE", "ECDSA", "AES-256-CBC", "SHA-1",   SecurityLevel.LEGACY, "CBC mode")
_add(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",        "TLS1.2", "ECDHE", "RSA",   "AES-128-CBC", "SHA-1",   SecurityLevel.LEGACY, "CBC mode")
_add(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",        "TLS1.2", "ECDHE", "RSA",   "AES-256-CBC", "SHA-1",   SecurityLevel.LEGACY, "CBC mode")
_add(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",   "TLS1.2", "ECDHE", "ECDSA", "AES-128-CBC", "SHA-256", SecurityLevel.LEGACY, "CBC mode")
_add(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",   "TLS1.2", "ECDHE", "ECDSA", "AES-256-CBC", "SHA-384", SecurityLevel.LEGACY, "CBC mode")
_add(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",     "TLS1.2", "ECDHE", "RSA",   "AES-128-CBC", "SHA-256", SecurityLevel.LEGACY, "CBC mode")
_add(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",     "TLS1.2", "ECDHE", "RSA",   "AES-256-CBC", "SHA-384", SecurityLevel.LEGACY, "CBC mode")

# ---- TLS 1.2 RSA key exchange (no forward secrecy) ----
_add(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA",          "TLS1.2", "RSA", "RSA", "AES-128-CBC", "SHA-1",   SecurityLevel.WEAK, "No forward secrecy")
_add(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA",          "TLS1.2", "RSA", "RSA", "AES-256-CBC", "SHA-1",   SecurityLevel.WEAK, "No forward secrecy")
_add(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256",       "TLS1.2", "RSA", "RSA", "AES-128-CBC", "SHA-256", SecurityLevel.WEAK, "No forward secrecy")
_add(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256",       "TLS1.2", "RSA", "RSA", "AES-256-CBC", "SHA-256", SecurityLevel.WEAK, "No forward secrecy")
_add(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256",       "TLS1.2", "RSA", "RSA", "AES-128-GCM", "AEAD",    SecurityLevel.WEAK, "No forward secrecy")
_add(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384",       "TLS1.2", "RSA", "RSA", "AES-256-GCM", "AEAD",    SecurityLevel.WEAK, "No forward secrecy")

# ---- Weak / broken suites commonly found on IoT ----
_add(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA",         "TLS1.2", "RSA", "RSA", "3DES-CBC",    "SHA-1",   SecurityLevel.CRITICAL, "Sweet32 + no PFS")
_add(0x0004, "TLS_RSA_WITH_RC4_128_MD5",              "TLS1.2", "RSA", "RSA", "RC4-128",     "MD5",     SecurityLevel.CRITICAL, "RC4 broken + MD5")
_add(0x0005, "TLS_RSA_WITH_RC4_128_SHA",              "TLS1.2", "RSA", "RSA", "RC4-128",     "SHA-1",   SecurityLevel.CRITICAL, "RC4 broken")
_add(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",      "TLS1.2", "ECDHE", "ECDSA", "RC4-128", "SHA-1",   SecurityLevel.CRITICAL, "RC4 broken")
_add(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA",        "TLS1.2", "ECDHE", "RSA",   "RC4-128", "SHA-1",   SecurityLevel.CRITICAL, "RC4 broken")
_add(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",     "TLS1.2", "DHE",  "DSS",   "3DES-CBC", "SHA-1",   SecurityLevel.CRITICAL, "Sweet32")
_add(0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",  "TLS1.2", "DHE",  "DSS",   "CAMELLIA-128-CBC", "SHA-1", SecurityLevel.LEGACY)
_add(0x008A, "TLS_PSK_WITH_RC4_128_SHA",               "TLS1.2", "PSK",  "PSK",   "RC4-128", "SHA-1",   SecurityLevel.CRITICAL, "RC4 broken")

# ---- NULL / export-grade (catastrophic) ----
_add(0x0000, "TLS_NULL_WITH_NULL_NULL",                "TLS1.2", "NULL", "NULL", "NULL", "NULL", SecurityLevel.CRITICAL, "No encryption at all")
_add(0x0001, "TLS_RSA_WITH_NULL_MD5",                  "TLS1.2", "RSA",  "RSA",  "NULL", "MD5",  SecurityLevel.CRITICAL, "No encryption")
_add(0x0002, "TLS_RSA_WITH_NULL_SHA",                  "TLS1.2", "RSA",  "RSA",  "NULL", "SHA-1", SecurityLevel.CRITICAL, "No encryption")
_add(0x003B, "TLS_RSA_WITH_NULL_SHA256",               "TLS1.2", "RSA",  "RSA",  "NULL", "SHA-256", SecurityLevel.CRITICAL, "No encryption")
_add(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5",         "TLS1.2", "RSA",  "RSA",  "RC4-40", "MD5", SecurityLevel.CRITICAL, "Export-grade")
_add(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",     "TLS1.2", "RSA",  "RSA",  "RC2-40", "MD5", SecurityLevel.CRITICAL, "Export-grade")
_add(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",      "TLS1.2", "RSA",  "RSA",  "DES-40", "SHA-1", SecurityLevel.CRITICAL, "Export-grade")
_add(0x0009, "TLS_RSA_WITH_DES_CBC_SHA",               "TLS1.2", "RSA",  "RSA",  "DES-CBC","SHA-1", SecurityLevel.CRITICAL, "DES 56-bit")

# ---------------------------------------------------------------------------
# Security level colour coding for dashboard
# ---------------------------------------------------------------------------

SECURITY_COLORS = {
    SecurityLevel.CRITICAL:   "#e74c3c",
    SecurityLevel.WEAK:       "#e67e22",
    SecurityLevel.LEGACY:     "#f39c12",
    SecurityLevel.ACCEPTABLE: "#3498db",
    SecurityLevel.STRONG:     "#2ecc71",
    SecurityLevel.OPTIMAL:    "#27ae60",
}

SECURITY_LABELS = {
    SecurityLevel.CRITICAL:   "Critical",
    SecurityLevel.WEAK:       "Weak",
    SecurityLevel.LEGACY:     "Legacy",
    SecurityLevel.ACCEPTABLE: "Acceptable",
    SecurityLevel.STRONG:     "Strong",
    SecurityLevel.OPTIMAL:    "Optimal",
}

# ---------------------------------------------------------------------------
# Ordered cipher suite lists for probing (by preference – worst first)
# ---------------------------------------------------------------------------

PROBE_ORDER_WEAK_FIRST: List[int] = [
    0x0000, 0x0001, 0x0002, 0x003B,
    0x0003, 0x0006, 0x0008, 0x0009,
    0x0004, 0x0005, 0x008A,
    0x000A, 0x0013,
    0xC007, 0xC011,
    0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D,
    0xC009, 0xC00A, 0xC013, 0xC014,
    0xC023, 0xC024, 0xC027, 0xC028,
    0x009E, 0x009F,
    0xC02B, 0xC02C, 0xC02F, 0xC030,
    0xCCA8, 0xCCA9,
    0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
]

PROBE_ORDER_STRONG_FIRST: List[int] = list(reversed(PROBE_ORDER_WEAK_FIRST))

def get_cipher_info(code: int) -> CipherSuiteInfo:
    return CIPHER_SUITES.get(code, CipherSuiteInfo(
        code=code, name=f"UNKNOWN_0x{code:04X}", protocol="?",
        kex="?", auth="?", enc="?", mac="?",
        security=SecurityLevel.WEAK, notes="Unknown cipher suite"
    ))

def security_grade(level: SecurityLevel) -> str:
    grades = {
        SecurityLevel.CRITICAL: "F",
        SecurityLevel.WEAK: "D",
        SecurityLevel.LEGACY: "C",
        SecurityLevel.ACCEPTABLE: "B",
        SecurityLevel.STRONG: "A",
        SecurityLevel.OPTIMAL: "A+",
    }
    return grades.get(level, "?")

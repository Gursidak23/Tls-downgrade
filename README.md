# TLS Downgrade & Cipher Suite Analyzer for IoT Devices

A research-aligned security analysis tool for evaluating TLS downgrade vulnerabilities
in IoT devices, implementing the methodology from:

> Cho, Lee, & Kim. **"Return of Version Downgrade Attack in the Era of TLS 1.3"**
> (ACM CoNEXT 2020, DOI: [10.1145/3386367.3431310](https://dl.acm.org/doi/10.1145/3386367.3431310))

## Research Background

### The Problem

TLS 1.3 (RFC 8446) introduced a downgrade protection mechanism: when a TLS 1.3-capable
server negotiates TLS 1.2 or lower, it embeds a sentinel value (`DOWNGRD\x01`) in the
last 8 bytes of `ServerHello.random`. Clients MUST check this sentinel and abort if
present, as it indicates a potential Man-in-the-Middle downgrade attack.

**The paper found that many TLS client implementations fail to validate this sentinel**,
leaving them vulnerable to active version downgrade attacks even in the TLS 1.3 era.

### Threat Models

This tool evaluates two complementary threat models:

**Threat Model 1 — IoT Device as TLS Server (Passive Attacker)**
- IoT devices (cameras, NAS, smart hubs) expose HTTPS management interfaces
- An attacker on the local network probes the server's TLS configuration
- Tests: supported TLS versions, cipher suite preferences, FALLBACK_SCSV, sentinel

**Threat Model 2 — IoT Device as TLS Client (Active Attacker)**
- IoT devices make outgoing TLS connections (cloud APIs, firmware updates, telemetry)
- An on-path attacker (via ARP spoofing, DNS redirect) intercepts these connections
- Tests: does the client validate the downgrade sentinel? Does it accept weak ciphers?
- This directly replicates the CoNEXT 2020 paper's experimental methodology

## Architecture

```
scan.py (CLI)
  |
  |-- discover     Scan LAN for IoT devices with TLS services
  |-- server       Probe IoT server: versions, ciphers, downgrade
  |-- profiles     Three-profile cipher preference experiment
  |-- stacks       Automated client stack sentinel testing (Paper 1)
  |-- client       Malicious server / MITM proxy for real devices
  |-- lab          Virtual IoT Lab -- runs everything, no hardware
  |
  +-- src/scanner/         Server-side scanning pipeline
  |     version_probe      TLS version detection + sentinel check
  |     cipher_probe       Cipher enumeration + preference order
  |     downgrade_detector FALLBACK_SCSV, version intolerance
  |     profile_tester     Modern/Mixed/Legacy experiment
  |     tls_scanner        Orchestrator
  |
  +-- src/attack/          Client-side testing (Paper 1)
  |     malicious_server   Controllable sentinel + multi-version
  |     automated_client_tester  Multi-stack testing + root cause
  |     downgrade_simulator      MITM proxy + sentinel stripping
  |
  +-- src/emulation/       Virtual IoT Lab (no hardware)
  |     iot_profiles       12 research-backed device profiles
  |     virtual_iot_server Real TLS servers on localhost
  |     virtual_lab        Lab orchestrator
  |
  +-- src/dashboard/       Flask + Chart.js visualization
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Mode 0: Discover IoT Devices on Local Network

```bash
# Scan your subnet for devices with TLS services
python scan.py discover --subnet 192.168.1.0/24

# Custom ports
python scan.py discover --subnet 10.0.0.0/24 --ports 443,8443,4443,9443
```

### Mode 1: Test IoT Device as TLS Server

```bash
# Scan a single device
python scan.py server --target 192.168.1.100:443 --label "IP Camera"

# Scan multiple targets from config
python scan.py server --config config.yaml

# Quick scan (version detection only)
python scan.py server --target 192.168.1.100:443
```

### Mode 2: Automated Client Stack Testing (Paper 1 Core)

**This is the key command that replicates the paper's methodology.**

The paper tested 10 browsers × 5 OSes. This command tests every TLS client
library available on your system against a malicious server with controlled
sentinel behavior.

```bash
# Test all available TLS stacks
python scan.py stacks

# Custom port
python scan.py stacks --port 15000
```

Output for each stack:
- **sentinel_present**: Does the client detect and abort? (core test)
- **sentinel_omission**: Does the client proceed when sentinel is stripped? (MITM simulation)
- **downgrade_to_10**: Will the client accept TLS 1.0? (paper: 1.3 → 1.0)
- **Root cause**: `sentinel_not_checked`, `accepts_deprecated_version`, or `no_scsv`

### Virtual IoT Lab (No Hardware Required)

**One command to run the entire analysis pipeline without any physical devices.**

```bash
# Full lab: server scans + cipher profiles + client stacks
python scan.py lab

# Individual phases
python scan.py lab --server-only        # TLS version/cipher/downgrade scan
python scan.py lab --profiles-only      # Modern/Mixed/Legacy cipher preference
python scan.py lab --client-only        # Client stack sentinel testing (Paper 1)
```

The lab spawns 12 virtual TLS servers on localhost, each configured to faithfully
replicate a real IoT device's firmware TLS behavior:

| Device | TLS Library | Category | Key Behavior |
|---|---|---|---|
| Hikvision DS-2CD2xx5 (2019) | OpenSSL 1.0.2k | Camera | TLS 1.0, CBC, no server pref |
| Dahua IPC-HDW5xxx (2020) | OpenSSL 1.0.2n | Camera | CBC preferred over GCM |
| Wyze Cam v2 (2021) | mbedTLS 2.16.6 | Camera | TLS 1.2 only, GCM |
| WD My Cloud EX2 (2019) | OpenSSL 1.0.1t | NAS | TLS 1.0, 3DES, 1024-bit RSA |
| Synology DS920+ (2023) | OpenSSL 1.1.1w | NAS | TLS 1.2+1.3, strong config |
| QNAP TS-451+ (2020) | OpenSSL 1.0.2u | NAS | Wide cipher acceptance |
| TP-Link Kasa (2020) | mbedTLS 2.16.2 | Smart Home | Minimal cipher set |
| Generic Medical (2018) | OpenSSL 0.9.8zh | Medical | TLS 1.0, very weak |
| Modern Smart Hub (2024) | wolfSSL 5.6.3 | Smart Home | TLS 1.2+1.3, AEAD only |
| Nginx Modern (2024) | OpenSSL 3.0 | Web baseline | Best-practice config |
| Apache Legacy (2020) | OpenSSL 1.0.2 | Web baseline | Follows client order |
| Cloudflare Edge (2024) | BoringSSL | Web baseline | Strict AEAD, ECDSA pref |

**Why this is academically defensible**: The hardware is irrelevant to TLS protocol
analysis. A camera running OpenSSL 1.0.2k produces identical handshakes to software
configured the same way. Each profile is sourced from published firmware analysis,
Shodan scans, and CVE reports (see `src/emulation/iot_profiles.py` for citations).

### Mode 3: Test IoT Device as TLS Client (Paper 1 Methodology)

This is the key addition that aligns with the research paper.

#### Mode 2A — Malicious Server (Sentinel Omission)

```bash
# Start a malicious server that omits the downgrade sentinel
python scan.py client --mode malicious-server --port 4433 --duration 120

# Then direct the IoT device to connect to YOUR_IP:4433
# (via DNS spoofing, hosts file, or manual configuration)
```

The server:
1. Accepts TLS 1.3 ClientHellos
2. Negotiates TLS 1.2 WITHOUT embedding the downgrade sentinel
3. Records whether the client detects and rejects the downgrade
4. Reports: VULNERABLE (continued handshake) or PROTECTED (sent alert/closed)

#### Mode 2B — MITM Proxy (Full Active Attack)

```bash
# Start the MITM proxy between IoT device and its cloud server
python scan.py client --mode mitm --target api.vendor.com:443 --port 8443

# Route IoT device traffic through YOUR_IP:8443
# (via ARP spoofing, transparent proxy, or iptables redirect)
```

The proxy:
1. Intercepts the IoT device's ClientHello and rewrites TLS 1.3 -> TLS 1.0
2. Forwards the modified hello to the real server
3. Strips the downgrade sentinel from ServerHello.random before forwarding back
4. Records whether the client detects the manipulation

### Dashboard

```bash
python dashboard.py
# Open http://127.0.0.1:5000
```

The dashboard shows:
- **Server scan results** — TLS versions, cipher suites, downgrade protection status
- **Client test results** — Sentinel validation, SCSV usage, vulnerability status
- **Network discovery** — Discovered IoT devices with TLS services

## Project Structure

```
TLS Downgrade/
├── scan.py                          # CLI entry point (6 commands)
├── dashboard.py                     # Web dashboard launcher
├── config.yaml                      # Configuration for all modes
├── run_demo.py                      # Full demonstration script
├── requirements.txt
├── src/
│   ├── scanner/
│   │   ├── constants.py             # TLS versions, cipher suites, security levels
│   │   ├── version_probe.py         # TLS version detection + sentinel check
│   │   ├── cipher_probe.py          # Cipher suite enumeration + preference
│   │   ├── downgrade_detector.py    # FALLBACK_SCSV, version intolerance, sentinel
│   │   ├── profile_tester.py        # Three-profile cipher preference experiment
│   │   ├── tls_scanner.py           # Orchestrator for server scanning
│   │   └── network_discovery.py     # LAN IoT device discovery
│   ├── attack/
│   │   ├── malicious_server.py      # Paper 1: fake server (multi-version, sentinel control)
│   │   ├── automated_client_tester.py  # Paper 1 CORE: multi-stack + IoT emulation
│   │   ├── client_downgrade_tester.py  # Orchestrator for client tests
│   │   └── downgrade_simulator.py   # MITM proxy with sentinel stripping
│   ├── emulation/                   # Virtual IoT Lab (no hardware required)
│   │   ├── iot_profiles.py          # 12 research-backed device TLS profiles
│   │   ├── virtual_iot_server.py    # Spawns real TLS servers per profile
│   │   └── virtual_lab.py           # Lab orchestrator (3 phases)
│   ├── dashboard/
│   │   ├── app.py                   # Flask API
│   │   ├── templates/index.html     # Dashboard UI
│   │   └── static/{css,js}/         # Frontend assets
│   └── utils/
│       ├── logger.py                # Colored logging
│       └── report.py                # Terminal report formatting
└── sample_results/                  # Scan output (JSON)
```

## Research Alignment

### Paper 1: Cho et al. (CoNEXT 2020) — Version Downgrade Attack

| Paper Element | Implementation | Status |
|---|---|---|
| Test 10 browsers × 5 OSes for sentinel validation | `automated_client_tester.py` — tests all available TLS stacks | **Implemented** (adapted for IoT TLS libs) |
| Malicious server with sentinel omission | `malicious_server.py` — controllable sentinel + multi-version | **Implemented** |
| Active MITM version downgrade (1.3 → 1.0) | `downgrade_simulator.py` — ClientHello rewrite + sentinel strip | **Implemented** |
| Multi-version downgrade (1.3→1.2, 1.3→1.1, 1.3→1.0) | `malicious_server.py` — configurable negotiate version | **Implemented** |
| Root cause analysis (why stacks are vulnerable) | `automated_client_tester.py` — categorizes sentinel_not_checked, accepts_deprecated_version, no_scsv | **Implemented** |
| FALLBACK_SCSV testing (RFC 7507) | `downgrade_detector.py` — raw ClientHello with SCSV | **Implemented** |
| Identify vulnerable implementations (paper: SChannel, SecureTransport) | `scan.py stacks` — identifies which local TLS libraries are vulnerable | **Implemented** |

### Term Paper: Three-Profile Cipher Selection

| Element | Implementation | Status |
|---|---|---|
| Three client profiles (Modern/Mixed/Legacy) | `profile_tester.py` — ECDHE+AEAD / mixed / RSA+CBC | **Implemented** |
| Server cipher preference detection | `cipher_probe.py` — opposite-order test | **Implemented** |
| IoT vs web server comparison | `profile_tester.py` — aggregated statistics | **Implemented** |
| IoT device discovery | `network_discovery.py` — LAN subnet scanning | **Implemented** |

### What Requires Physical Devices (and What Doesn't)

> **The `python scan.py lab` command runs the entire analysis pipeline without
> any physical hardware.** It spawns virtual TLS servers configured from
> research-backed IoT device profiles and tests them with the same scan code
> used for real devices. Results are structurally identical.
>
> **No hardware needed for:**
> - `scan.py lab` -- Virtual IoT Lab (12 emulated devices + 3 web baselines)
> - `scan.py stacks` -- Tests real TLS libraries on your machine
> - `scan.py lab --profiles-only` -- Cipher preference IoT vs web comparison
>
> **Hardware needed for:**
> - `scan.py discover` -- Scans a real LAN subnet
> - `scan.py server --target <ip>` -- Probes a real device
> - `scan.py client --mode malicious-server` -- Waits for real device connections
> - `scan.py client --mode mitm` -- Proxies real device traffic
>
> The `run_demo.py` script uses simulated servers labeled `"simulated": true`.
> The `scan.py lab` results use `"virtual_lab": true` to indicate emulated devices.

## Security Grading

| Grade | Criteria |
|---|---|
| A+ | TLS 1.3 + AEAD ciphers only + all downgrade protections |
| A | TLS 1.2+ with strong ciphers + SCSV + sentinel |
| B | TLS 1.2 with acceptable ciphers, minor issues |
| C | Legacy ciphers (CBC), missing some protections |
| D | TLS 1.1 or weak ciphers present |
| F | SSLv3 or broken ciphers (RC4, NULL, export) |

## Ethical Use

This tool is for **authorized security research and testing only**. The MITM proxy and
malicious server features are designed for testing devices you own or have explicit
written permission to test. Unauthorized interception of network traffic is illegal.

## References

1. Cho, S., Lee, S., & Kim, H. (2020). Return of Version Downgrade Attack in the Era
   of TLS 1.3. *ACM CoNEXT*, 157-168. DOI: 10.1145/3386367.3431310
2. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
3. RFC 7507 — TLS Fallback Signaling Cipher Suite Value (SCSV)
# Tls-downgrade
# Tls-downgrade

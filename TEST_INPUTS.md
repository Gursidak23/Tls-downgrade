# Test Inputs for All Scan Types

Ready-to-use inputs for every scan type in the TLS Downgrade & Cipher Suite Analyzer dashboard.
Open the dashboard at `http://127.0.0.1:5000`, click **New Scan**, select a scan type, and paste the values below.

---

## 1. Server Scan

Scans a real remote host for TLS versions, cipher suites, and downgrade vulnerabilities.

| # | Host | Port | Label | Why this target? |
|---|------|------|-------|------------------|
| 1 | `www.google.com` | 443 | Google (TLS 1.3) | Modern TLS 1.3 with strong ciphers, good baseline |
| 2 | `github.com` | 443 | GitHub | Strict TLS config, HSTS, strong forward secrecy |
| 3 | `www.cloudflare.com` | 443 | Cloudflare Edge | Industry-leading TLS 1.3 deployment |
| 4 | `mozilla.org` | 443 | Mozilla | Reference config from Mozilla SSL guidelines |
| 5 | `tls-v1-2.badssl.com` | 443 | badssl TLS 1.2 Only | Forces TLS 1.2 max — tests version detection |
| 6 | `expired.badssl.com` | 443 | Expired Certificate | Valid TLS but expired cert — tests cipher scan still works |
| 7 | `self-signed.badssl.com` | 443 | Self-Signed Cert | Self-signed cert — common in IoT devices |
| 8 | `sha256.badssl.com` | 443 | SHA-256 Baseline | Standard SHA-256 signed cert, baseline comparison |
| 9 | `cbc.badssl.com` | 443 | CBC Ciphers | Offers CBC cipher suites — should flag as legacy |
| 10 | `rc4.badssl.com` | 443 | RC4 Cipher (Insecure) | RC4 is broken — should flag as critical risk |
| 11 | `www.microsoft.com` | 443 | Microsoft | Large CDN with modern config |
| 12 | `amazon.com` | 443 | Amazon | Mixed TLS support for backward compatibility |

### How to use
1. Click **New Scan** → select **Server Scan**
2. Enter the **Host** and **Port** from the table
3. Optionally set a **Label** for easier identification
4. Click **Start Scan**

---

## 2. Virtual IoT Lab

Launches 12 emulated IoT TLS servers on localhost, scans them all, runs cipher preference experiments, and tests client stacks. **No user input needed** — just click Start.

| # | What it does | Ports used | Duration |
|---|-------------|------------|----------|
| 1 | Default config | 17000–17011 (servers), 17100 (stacks) | ~2 min |
| 2 | Custom base port | Set base port to 24000 | ~2 min |
| 3 | Custom stacks port | Set stacks port to 24100 | ~2 min |

### Emulated devices tested automatically
| Device | Category | TLS Library | Max TLS | Notable |
|--------|----------|-------------|---------|---------|
| Hikvision DS-2CD2xx5 | Camera | OpenSSL 1.0.2k | TLS 1.2 | Weak cipher order |
| Dahua IPC-HDW5xxx | Camera | OpenSSL 1.0.2n | TLS 1.2 | Server preference but weak ciphers first |
| Wyze Cam v2 | Camera | mbedTLS 2.16.6 | TLS 1.2 | Decent for low-cost device |
| WD My Cloud EX2 | NAS | OpenSSL 1.0.1t | TLS 1.2 | 1024-bit RSA, 3DES enabled |
| Synology DS920+ | NAS | OpenSSL 1.1.1w | TLS 1.3 | Strong modern config |
| QNAP TS-451+ | NAS | OpenSSL 1.0.2u | TLS 1.2 | Mixed cipher strength |
| TP-Link Kasa Smart Plug | Smart Home | mbedTLS 2.16.2 | TLS 1.2 | Mixed ECDHE and RSA |
| Generic Medical Device | Medical | OpenSSL 0.9.8zh | TLS 1.2 | Worst-case: 1024-bit key, 3DES |
| Modern Smart Hub | Gateway | wolfSSL 5.6.3 | TLS 1.3 | Best-practice IoT config |
| Nginx Modern | Web Baseline | OpenSSL 3.0 | TLS 1.3 | Mozilla Modern guideline |
| Apache Legacy | Web Baseline | OpenSSL 1.0.2 | TLS 1.2 | Old backward compat config |
| Cloudflare Edge | Web Baseline | BoringSSL | TLS 1.3 | Industry-leading config |

### How to use
1. Click **New Scan** → select **Virtual IoT Lab**
2. Click **Start Scan** (no inputs required)
3. Wait ~2 minutes for all 3 phases to complete

---

## 3. Client Stack Test

Tests local TLS client libraries against a malicious server that omits the downgrade sentinel. **No user input needed** — just click Start.

| # | Config | Port | Notes |
|---|--------|------|-------|
| 1 | Default | 17100 | Standard test |
| 2 | Custom port | 24200 | Use if default port is busy |
| 3 | Custom port | 25000 | Alternative port |

### Client stacks tested automatically
| Client | TLS Library | Checks Sentinel? | Accepts TLS 1.0? | Sends SCSV? | Expected |
|--------|-------------|-------------------|-------------------|-------------|----------|
| Cheap IP Camera | mbedTLS 2.4 (pre-patch) | No | Yes | No | VULNERABLE |
| Smart Thermostat | wolfSSL 4.5 | Yes | Yes | No | PARTIAL |
| Modern NAS | OpenSSL 1.1.1+ | Yes | No | Yes | PROTECTED |

### How to use
1. Click **New Scan** → select **Client Stack Test**
2. Click **Start Scan**
3. Results show which client libraries are vulnerable to version downgrade

---

## 4. Cipher Preference (Three-Profile Experiment)

Tests whether IoT servers prefer weak ciphers when strong ones are also offered. Sends three different ClientHello profiles (Modern, Mixed, Legacy) to each emulated server. **No user input needed**.

| # | Config | Base Port | Notes |
|---|--------|-----------|-------|
| 1 | Default | 17000 | Standard 12-device experiment |
| 2 | Custom port | 24300 | Use if default ports are busy |
| 3 | Custom port | 25000 | Alternative port range |

### What the three profiles offer
| Profile | Cipher Strategy | Purpose |
|---------|----------------|---------|
| Modern | Only ECDHE-GCM and ChaCha20 | Best-practice client |
| Mixed | Strong + legacy ciphers together | Typical browser behavior |
| Legacy | Weak ciphers (RSA kex, CBC, 3DES) first | Tests if server picks the weak option |

### How to use
1. Click **New Scan** → select **Cipher Preference**
2. Click **Start Scan**
3. Results show which servers chose weak ciphers when strong ones were available

---

## 5. Network Discovery

Scans a subnet for TLS-enabled devices (IoT cameras, NAS, routers, etc.).

| # | Subnet | Ports | Timeout | What it finds |
|---|--------|-------|---------|---------------|
| 1 | `192.168.1.0/24` | 443,8443,4443 | 2s | Home network devices |
| 2 | `192.168.0.0/24` | 443,8443,4443 | 2s | Alternative home subnet |
| 3 | `10.0.0.0/24` | 443,8443,4443 | 2s | Corporate/VPN subnet |
| 4 | `172.16.0.0/24` | 443,8443,4443 | 2s | Docker/VM network |
| 5 | `127.0.0.1/32` | 443,5000,8443 | 2s | Localhost only (safe test — finds the dashboard itself) |
| 6 | `192.168.1.0/28` | 443,8443,993,995 | 3s | Small subnet, include mail ports |
| 7 | `10.0.1.0/24` | 443,8443,9443,4443 | 2s | Lab/office network with IoT ports |

### How to use
1. Click **New Scan** → select **Network Discovery**
2. Enter a **Subnet** in CIDR notation (e.g., `192.168.1.0/24`)
3. Set **Ports** as comma-separated list
4. Set **Timeout** in seconds (2-3s recommended)
5. Click **Start Scan**

> **Tip**: Start with `127.0.0.1/32` as a safe test. Then use your actual home/lab subnet.
> Find your subnet: run `ipconfig` (Windows) or `ifconfig` / `ip addr` (Linux/Mac).

---

## 6. Malicious Server

Starts a TLS server that deliberately omits the downgrade sentinel. IoT clients connecting to it reveal whether they validate the sentinel.

| # | Listen Port | Duration | Use Case |
|---|-------------|----------|----------|
| 1 | 4433 | 30s | Standard test — point IoT device to this port |
| 2 | 4434 | 60s | Longer window for slower IoT devices |
| 3 | 8443 | 30s | Common alt-HTTPS port |
| 4 | 9443 | 45s | Another IoT-common port |
| 5 | 5443 | 30s | Custom port for isolated testing |
| 6 | 4433 | 15s | Quick demo — just to verify it starts |
| 7 | 7443 | 120s | Extended listening for multiple devices |

### How to use
1. Click **New Scan** → select **Malicious Server**
2. Set **Listen Port** and **Duration**
3. Click **Start Scan**
4. Point an IoT device (or curl/openssl s_client) at `your-ip:port`

### Test with openssl (from another terminal)
```bash
openssl s_client -connect 127.0.0.1:4433 -tls1_2
```

---

## 7. MITM Proxy

Intercepts TLS traffic between an IoT client and its real server. Rewrites the ClientHello to force a version downgrade and strips the sentinel.

| # | Target Host | Target Port | Proxy Port | Downgrade To | Duration | Use Case |
|---|-------------|-------------|------------|--------------|----------|----------|
| 1 | `www.google.com` | 443 | 8443 | TLS 1.2 | 30s | Standard test against Google |
| 2 | `github.com` | 443 | 8444 | TLS 1.2 | 30s | Test against GitHub |
| 3 | `www.cloudflare.com` | 443 | 8445 | TLS 1.1 | 30s | Aggressive downgrade to 1.1 |
| 4 | `amazon.com` | 443 | 8446 | TLS 1.2 | 45s | Large CDN target |
| 5 | `mozilla.org` | 443 | 8447 | TLS 1.0 | 30s | Maximum downgrade to 1.0 |
| 6 | `www.microsoft.com` | 443 | 8448 | TLS 1.2 | 30s | Microsoft CDN |
| 7 | `api.github.com` | 443 | 8449 | TLS 1.2 | 60s | API endpoint interception |

### How to use
1. Click **New Scan** → select **MITM Proxy**
2. Enter **Target Host**, **Target Port**, **Proxy Port**, **Downgrade To**, and **Duration**
3. Click **Start Scan**
4. Point client traffic to `127.0.0.1:proxy_port` instead of the real server

### Test with curl (from another terminal)
```bash
curl -k --resolve www.google.com:8443:127.0.0.1 https://www.google.com:8443/
```

---

## 8. Generate PDF Report

Exports all existing scan results into a formatted PDF report. **No input needed**.

| # | When to run | What it includes |
|---|-------------|------------------|
| 1 | After running Server Scans | All server TLS analysis results |
| 2 | After running Virtual IoT Lab | Emulated device scan data |
| 3 | After running all scan types | Complete report with all data |
| 4 | After Network Discovery | Includes discovered devices |
| 5 | After Client Stack Tests | Includes vulnerability findings |

### How to use
1. Run some scans first (the PDF pulls from saved results)
2. Click **New Scan** → select **Generate PDF**
3. Click **Start Scan**
4. When done, click the download link in the completion summary

---

## Quick-Start Testing Order

For the best experience, run scans in this order:

| Step | Scan Type | Input | Time |
|------|-----------|-------|------|
| 1 | **Server Scan** | `www.google.com:443` | ~15s |
| 2 | **Server Scan** | `tls-v1-2.badssl.com:443` | ~15s |
| 3 | **Server Scan** | `self-signed.badssl.com:443` | ~15s |
| 4 | **Virtual IoT Lab** | (no input) | ~2 min |
| 5 | **Client Stack Test** | (no input) | ~30s |
| 6 | **Cipher Preference** | (no input) | ~1 min |
| 7 | **Network Discovery** | `127.0.0.1/32`, ports `443,5000` | ~5s |
| 8 | **Generate PDF** | (no input) | ~10s |

This gives you a complete dataset covering all scan types with real-world + emulated results.

#!/usr/bin/env python3
"""
Full IoT Network Demonstration

Simulates a realistic test scenario without requiring physical IoT hardware:

  Phase 1: Scan simulated IoT servers (camera, thermostat) on localhost
  Phase 2: Test simulated IoT clients against the malicious server
           - "Cheap IP Camera" firmware: does NOT check sentinel -> VULNERABLE
           - "Modern NAS" firmware: uses Python/OpenSSL which checks -> PROTECTED
  Phase 3: MITM proxy intercepts a connection with sentinel stripping

All results are saved to sample_results/ and appear in the dashboard.
"""

import json
import os
import socket
import ssl
import struct
import sys
import threading
import time

# ── Phase 1: Simulated IoT Server Scanning ───────────────────

def _generate_iot_cert(cn, org):
    """Generate a self-signed cert mimicking an IoT device."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timezone
    import tempfile

    key = rsa.generate_private_key(65537, 2048)
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
        .not_valid_after(datetime(2028, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(tempfile.gettempdir(), f"iot_{cn.replace('.','_')}.pem")
    key_path = os.path.join(tempfile.gettempdir(), f"iot_{cn.replace('.','_')}_key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    return cert_path, key_path


class SimulatedIoTServer:
    """A TLS server mimicking a real IoT device's configuration."""

    def __init__(self, port, cn, org, cipher_string, label):
        self.port = port
        self.label = label
        self._running = False
        self._cert, self._key = _generate_iot_cert(cn, org)

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
        self._ctx.set_ciphers(cipher_string)
        self._ctx.load_cert_chain(self._cert, self._key)

    def start(self):
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(5)
        self._sock.settimeout(1.0)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"  [IoT Server] {self.label} listening on :{self.port}")

    def _loop(self):
        while self._running:
            try:
                client, addr = self._sock.accept()
                try:
                    tls = self._ctx.wrap_socket(client, server_side=True)
                    tls.recv(1024)
                    tls.sendall(b"HTTP/1.0 200 OK\r\nServer: IoT-Firmware/1.0\r\n\r\nOK")
                    tls.close()
                except Exception:
                    client.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._running = False
        self._sock.close()


def run_iot_server_scans():
    """Scan the already-running simulated IoT servers."""
    from src.scanner.tls_scanner import scan_target, _to_dict

    print("\n" + "=" * 60)
    print("  PHASE 1: Scanning Simulated IoT Servers")
    print("=" * 60 + "\n")

    iot_targets = [
        (10443, "IP Camera (Hikvision-like)"),
        (10444, "Smart Thermostat"),
    ]

    results = []
    output_dir = "sample_results"
    os.makedirs(output_dir, exist_ok=True)

    for port, label in iot_targets:
        print(f"\n  Scanning {label} on 127.0.0.1:{port}...")
        try:
            result = scan_target("127.0.0.1", port, label, timeout=10)
            result_dict = _to_dict(result)
            result_dict["simulated"] = True
            result_dict["simulation_note"] = (
                "This result is from a SIMULATED IoT server on localhost, not a real device. "
                "For real results, scan actual IoT devices with: "
                "python scan.py server --target <device_ip>:<port>"
            )
            results.append(result_dict)

            safe_name = f"iot_{label.replace(' ', '_').replace('(', '').replace(')', '').lower()}"
            filepath = os.path.join(output_dir, f"{safe_name}.json")
            with open(filepath, "w") as f:
                json.dump(result_dict, f, indent=2, default=str)
            print(f"  -> Saved to {filepath}")
            print(f"     Grade: {result_dict.get('overall_grade', '?')}  "
                  f"Risk: {result_dict.get('overall_risk', '?')}")
        except Exception as exc:
            print(f"  -> Scan failed: {exc}")

    return results


# ── Phase 2: Client-Side Downgrade Testing ────────────────────

def _build_tls13_client_hello():
    """Build a realistic TLS 1.3 ClientHello with supported_versions."""
    client_random = os.urandom(32)
    session_id = os.urandom(32)

    ciphers = struct.pack("!HHHHH",
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
        0x009C,  # RSA-AES128-GCM-SHA256
        0x002F,  # RSA-AES128-SHA
    )

    # supported_versions: TLS 1.3 + TLS 1.2
    sv_list = struct.pack("!BHH", 4, 0x0304, 0x0303)
    sv_ext = struct.pack("!HH", 0x002B, len(sv_list)) + sv_list

    # signature_algorithms
    sa_list = struct.pack("!HHHH", 0x0401, 0x0501, 0x0601, 0x0201)
    sa_data = struct.pack("!H", len(sa_list)) + sa_list
    sa_ext = struct.pack("!HH", 0x000D, len(sa_data)) + sa_data

    # supported_groups
    sg_data = struct.pack("!HH", 2, 0x0017)
    sg_ext = struct.pack("!HH", 0x000A, len(sg_data)) + sg_data

    extensions = sv_ext + sa_ext + sg_ext
    ext_block = struct.pack("!H", len(extensions)) + extensions

    ch_body = struct.pack("!H", 0x0303) + client_random
    ch_body += struct.pack("!B", len(session_id)) + session_id
    ch_body += struct.pack("!H", len(ciphers)) + ciphers
    ch_body += b"\x01\x00"  # compression
    ch_body += ext_block

    hs = struct.pack("!B", 1) + struct.pack("!I", len(ch_body))[1:] + ch_body
    record = struct.pack("!BHH", 22, 0x0301, len(hs)) + hs
    return record


def _parse_handshake_messages(data):
    """Parse TLS records and extract handshake messages by type."""
    messages = {}
    offset = 0
    while offset + 5 <= len(data):
        ct = data[offset]
        rec_len = struct.unpack("!H", data[offset + 3:offset + 5])[0]
        payload = data[offset + 5:offset + 5 + rec_len]
        offset += 5 + rec_len
        if ct != 22:
            continue
        hs_off = 0
        while hs_off + 4 <= len(payload):
            hs_type = payload[hs_off]
            hs_len = struct.unpack("!I", b"\x00" + payload[hs_off + 1:hs_off + 4])[0]
            hs_body = payload[hs_off + 4:hs_off + 4 + hs_len]
            messages[hs_type] = hs_body
            hs_off += 4 + hs_len
    return messages


def _extract_cert_pubkey(cert_msg_body):
    """Extract the RSA public key from a Certificate handshake message body."""
    from cryptography.x509 import load_der_x509_certificate
    # cert_list_len(3) + cert_len(3) + cert_der
    cert_len = struct.unpack("!I", b"\x00" + cert_msg_body[3:6])[0]
    cert_der = cert_msg_body[6:6 + cert_len]
    cert = load_der_x509_certificate(cert_der)
    return cert.public_key()


def vulnerable_iot_client(host, port, label):
    """Simulate a vulnerable IoT client that does NOT check the sentinel.

    This replicates the behavior found by Cho et al. (CoNEXT 2020):
    the client offers TLS 1.3 but blindly continues the handshake when the
    server negotiates TLS 1.2, without checking ServerHello.random for the
    RFC 8446 downgrade sentinel.
    """
    from cryptography.hazmat.primitives.asymmetric import padding

    print(f"  [{label}] Connecting to {host}:{port}...")
    sock = socket.create_connection((host, port), timeout=10)

    ch = _build_tls13_client_hello()
    sock.sendall(ch)

    # Receive the full server flight
    time.sleep(0.5)
    response = b""
    sock.settimeout(3.0)
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break

    if not response:
        print(f"  [{label}] No response from server")
        sock.close()
        return

    messages = _parse_handshake_messages(response)

    if 2 in messages:
        server_random = messages[2][2:34]
        sentinel = server_random[-8:]
        has_sentinel = sentinel in (b"DOWNGRD\x01", b"DOWNGRD\x00")
        print(f"  [{label}] Received ServerHello (sentinel present: {has_sentinel})")
        print(f"  [{label}] ** NOT checking sentinel ** (vulnerable firmware)")
    else:
        print(f"  [{label}] No ServerHello in response")
        sock.close()
        return

    if 11 not in messages:
        print(f"  [{label}] No Certificate message")
        sock.close()
        return

    if 14 not in messages:
        print(f"  [{label}] No ServerHelloDone")
        sock.close()
        return

    # Extract the server's RSA public key from the certificate
    try:
        pub_key = _extract_cert_pubkey(messages[11])
    except Exception as exc:
        print(f"  [{label}] Failed to extract public key: {exc}")
        sock.close()
        return

    # Build ClientKeyExchange: RSA-encrypt a premaster secret
    premaster = struct.pack("!H", 0x0303) + os.urandom(46)
    encrypted = pub_key.encrypt(premaster, padding.PKCS1v15())
    cke_body = struct.pack("!H", len(encrypted)) + encrypted
    cke_hs = struct.pack("!B", 16) + struct.pack("!I", len(cke_body))[1:] + cke_body
    cke_record = struct.pack("!BHH", 22, 0x0303, len(cke_hs)) + cke_hs

    sock.sendall(cke_record)
    print(f"  [{label}] Sent ClientKeyExchange -> VULNERABLE (continued despite downgrade)")

    time.sleep(0.5)
    sock.close()


def protected_iot_client(host, port, label):
    """Simulate a protected IoT client using Python's ssl module.

    Python's OpenSSL correctly implements RFC 8446 sentinel checking,
    so it will detect the downgrade and abort.
    """
    print(f"  [{label}] Connecting to {host}:{port}...")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                print(f"  [{label}] Handshake completed: {tls.version()} -> UNEXPECTED")
    except ssl.SSLError as e:
        err = str(e)
        if "INAPPROPRIATE_FALLBACK" in err or "illegal_parameter" in err:
            print(f"  [{label}] Detected sentinel -> PROTECTED (correct RFC 8446 behavior)")
        else:
            print(f"  [{label}] Rejected handshake: {err[:80]} -> PROTECTED")
    except Exception as e:
        print(f"  [{label}] Connection error: {e} -> PROTECTED")


def run_client_tests():
    """Run the malicious server and connect simulated IoT clients."""
    from src.attack.malicious_server import MaliciousServer
    from dataclasses import asdict

    print("\n" + "=" * 60)
    print("  PHASE 2: Client-Side Downgrade Testing (Paper 1)")
    print("=" * 60 + "\n")

    results = []

    def on_result(r):
        results.append(r)

    server = MaliciousServer(listen_port=14433, on_result=on_result)

    # Test 1: sentinel_present -- does the client abort when it sees the sentinel?
    print("  Test 1: Sentinel PRESENT (compliant client should abort)\n")
    server.set_scenario("sentinel_present")
    server.start()
    time.sleep(0.5)

    vulnerable_iot_client("127.0.0.1", 14433, "Cheap IP Camera (no sentinel check)")
    time.sleep(1)
    protected_iot_client("127.0.0.1", 14433, "Modern NAS (OpenSSL 3.x)")
    time.sleep(1)

    server.stop()
    time.sleep(0.5)

    # Test 2: sentinel_omission -- simulates post-MITM scenario
    print("\n  Test 2: Sentinel OMITTED (simulating MITM stripping)\n")
    server2 = MaliciousServer(listen_port=14434, on_result=on_result)
    server2.set_scenario("sentinel_omission")
    server2.start()
    time.sleep(0.5)

    vulnerable_iot_client("127.0.0.1", 14434, "Cheap IP Camera (sentinel omitted)")
    time.sleep(1)
    protected_iot_client("127.0.0.1", 14434, "Modern NAS (sentinel omitted)")
    time.sleep(1)

    server2.stop()

    # Save combined client test report
    output_dir = "sample_results"
    os.makedirs(output_dir, exist_ok=True)

    report = {
        "test_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "malicious_server",
        "simulated": True,
        "simulation_note": (
            "These client tests use SIMULATED IoT firmware behavior, not real devices. "
            "The 'vulnerable' client is a raw socket that deliberately skips sentinel "
            "validation. The 'protected' client uses Python's ssl module (OpenSSL). "
            "For testing real TLS stacks, use: python scan.py stacks"
        ),
        "duration_seconds": 0,
        "server_test": {
            "server_port": 14433,
            "test_start": "",
            "test_end": "",
            "total_connections": len(results),
            "vulnerable_clients": sum(1 for r in results if r.vulnerable),
            "protected_clients": sum(1 for r in results if not r.vulnerable),
            "results": [asdict(r) for r in results],
        },
        "mitm_test": None,
        "total_client_connections": len(results),
        "clients_vulnerable_to_sentinel_omission": sum(
            1 for r in results if r.vulnerable and r.sentinel_omitted
        ),
        "clients_vulnerable_to_version_downgrade": sum(1 for r in results if r.vulnerable),
        "clients_offering_weak_ciphers": 0,
        "clients_sending_scsv": sum(1 for r in results if r.client_sent_scsv),
        "clients_protected": sum(1 for r in results if not r.vulnerable),
        "findings": [],
        "methodology_notes": [
            "SIMULATED client test: Malicious TLS server replicating Cho et al. (CoNEXT 2020).",
            "Vulnerable client: raw socket, deliberately skips sentinel check.",
            "Protected client: Python ssl module (OpenSSL), full RFC 8446 compliance.",
            "For real multi-stack testing, use: python scan.py stacks",
        ],
    }

    vuln_count = report["clients_vulnerable_to_version_downgrade"]
    prot_count = report["clients_protected"]
    if vuln_count > 0:
        report["findings"].append(
            f"{vuln_count} client(s) did NOT validate the TLS 1.3 downgrade sentinel "
            f"(RFC 8446 section 4.1.3). These are vulnerable to active MITM downgrade attacks."
        )
    if prot_count > 0:
        report["findings"].append(
            f"{prot_count} client(s) correctly detected the downgrade and rejected the connection."
        )

    filepath = os.path.join(output_dir, "client_test_report.json")
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Client test report saved to {filepath}")

    return results


# ── Phase 3: MITM Proxy Test ─────────────────────────────────

def run_mitm_test():
    """Run the MITM proxy to demonstrate version downgrade + sentinel stripping."""
    from src.attack.downgrade_simulator import DowngradeProxy
    from dataclasses import asdict

    print("\n" + "=" * 60)
    print("  PHASE 3: MITM Proxy Downgrade (TLS 1.2)")
    print("=" * 60 + "\n")

    events = []
    proxy = DowngradeProxy(
        target_host="www.google.com", target_port=443,
        listen_port=18443, downgrade_to=0x0303,  # TLS 1.2
        on_event=lambda e: events.append(e),
    )
    proxy.start()
    time.sleep(0.5)

    print("  Connecting through MITM proxy to www.google.com:443...")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", 18443), timeout=10) as raw:
            try:
                with ctx.wrap_socket(raw, server_hostname="www.google.com") as tls:
                    print(f"  -> Negotiated: {tls.version()}")
            except ssl.SSLError as e:
                print(f"  -> SSL error (expected): {str(e)[:80]}")
    except Exception as e:
        print(f"  -> Connection error: {e}")

    time.sleep(1)
    proxy.stop()

    if events:
        ev = events[0]
        print(f"  -> Original version: {ev.original_version}")
        print(f"  -> Downgraded to: {ev.downgraded_version}")
        print(f"  -> Server response: {ev.server_response}")
        print(f"  -> Sentinel was present: {ev.sentinel_was_present}")
        print(f"  -> Sentinel stripped: {ev.sentinel_stripped}")

    # Save MITM report
    output_dir = "sample_results"
    report = {
        "test_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "mitm_proxy",
        "duration_seconds": 0,
        "server_test": None,
        "mitm_test": asdict(proxy.result),
        "total_client_connections": proxy.result.total_connections,
        "clients_vulnerable_to_sentinel_omission": 0,
        "clients_vulnerable_to_version_downgrade": proxy.result.successful_downgrades,
        "clients_offering_weak_ciphers": 0,
        "clients_sending_scsv": 0,
        "clients_protected": proxy.result.blocked_downgrades,
        "findings": [],
        "methodology_notes": [
            "MITM proxy rewriting ClientHello: strips supported_versions extension.",
            "Also strips downgrade sentinel from ServerHello.random.",
            "Simulates active on-path attacker per Cho et al. (CoNEXT 2020).",
            f"Target: www.google.com:443, downgrade to TLS 1.2.",
        ],
    }
    if proxy.result.successful_downgrades > 0:
        report["findings"].append(
            f"Server accepted the downgraded ClientHello. "
            f"Sentinel {'was stripped' if any(e.sentinel_stripped for e in events) else 'was not present'}."
        )
    if proxy.result.blocked_downgrades > 0:
        report["findings"].append(
            f"Server rejected the downgrade attempt with an alert."
        )

    filepath = os.path.join(output_dir, "mitm_test_report.json")
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  MITM test report saved to {filepath}")


# ── Main ──────────────────────────────────────────────────────

# ── Phase 4: Automated Client Stack Testing (Paper 1 Core) ────

def run_automated_stack_test():
    """Run automated multi-stack testing — tests REAL TLS libraries on this system."""
    from src.attack.automated_client_tester import run_automated_test, save_report

    print("\n" + "=" * 60)
    print("  PHASE 4: Automated TLS Client Stack Testing")
    print("  (Paper 1 Core: Tests REAL TLS libraries, not simulations)")
    print("  Reference: Cho et al., CoNEXT 2020")
    print("=" * 60 + "\n")

    def on_progress(msg):
        print(f"  {msg}")

    report = run_automated_test(listen_port=14500, on_progress=on_progress)
    path = save_report(report, "sample_results")

    print(f"\n  {'Stack':<28} {'Sentinel?':<12} {'Verdict':<12}")
    print("  " + "-" * 52)
    for sr in report.stack_reports:
        sentinel_test = next((r for r in sr.test_results if r.scenario == "sentinel_present"), None)
        sentinel_str = "Yes" if (sentinel_test and sentinel_test.sentinel_detected) else "No"
        verdict = "VULNERABLE" if sr.overall_vulnerable else "Protected"
        print(f"  {sr.stack.name:<28} {sentinel_str:<12} {verdict:<12}")

    print(f"\n  Vulnerable: {report.stacks_vulnerable}/{report.stacks_tested}")
    print(f"  Protected:  {report.stacks_protected}/{report.stacks_tested}")
    print(f"  Report saved to {path}")

    return report


# ── Phase 0: Three-Profile Cipher Selection (TERM PAPER CORE) ─

def run_profile_experiment():
    """Run the three-profile experiment: Modern/Mixed/Legacy against IoT + Web."""
    from src.scanner.profile_tester import run_profile_experiment as _run_exp
    from dataclasses import asdict

    print("\n" + "=" * 60)
    print("  PHASE 0: Three-Profile Cipher Selection Experiment")
    print("  (Term Paper Core: 'Will servers USE weak ciphers?')")
    print("=" * 60 + "\n")

    targets = [
        # IoT devices (simulated, must already be running)
        {"host": "127.0.0.1", "port": 10443, "label": "IP Camera (Hikvision-like)", "type": "iot"},
        {"host": "127.0.0.1", "port": 10444, "label": "Smart Thermostat", "type": "iot"},
        # Real web servers (baseline comparison)
        {"host": "www.google.com", "port": 443, "label": "Google", "type": "web"},
        {"host": "www.cloudflare.com", "port": 443, "label": "Cloudflare", "type": "web"},
        {"host": "github.com", "port": 443, "label": "GitHub", "type": "web"},
    ]

    report = _run_exp(targets, timeout=10.0)

    # Print summary table
    print(f"\n  {'Device':<30} {'Type':<6} {'Modern':<20} {'Mixed':<20} {'Legacy':<20} {'Pref?':<5}")
    print("  " + "-" * 100)

    for d in report.devices:
        def _fmt(p):
            if not p or not p.connected:
                return "FAILED"
            pfs = " [PFS]" if p.has_forward_secrecy else ""
            return f"{p.cipher_name[:14]}{pfs}"
        m = _fmt(d.profiles.get("modern"))
        x = _fmt(d.profiles.get("mixed"))
        l = _fmt(d.profiles.get("legacy"))
        pref = "Yes" if d.server_enforces_preference else "No"
        weak = " *WEAK*" if d.chose_weak_with_mixed else ""
        print(f"  {d.label:<30} {d.device_type:<6} {m:<20} {x:<20} {l:<20} {pref:<5}{weak}")

    print(f"\n  IoT weak selection: {report.iot_weak_selection_pct}%  |  "
          f"Web weak selection: {report.web_weak_selection_pct}%")
    print(f"  IoT PFS (mixed):   {report.iot_pfs_with_mixed_pct}%  |  "
          f"Web PFS (mixed):   {report.web_pfs_with_mixed_pct}%")

    # Save
    output_dir = "sample_results"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, "profile_comparison.json")
    with open(filepath, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    print(f"\n  Saved to {filepath}")

    return report


if __name__ == "__main__":
    print("=" * 60)
    print("  TLS Downgrade Analyzer -- Full IoT Demo")
    print("=" * 60)

    # Start simulated IoT servers for the profile experiment
    servers = [
        SimulatedIoTServer(
            port=10443,
            cn="ipcam.local",
            org="Generic Camera Corp",
            cipher_string="DEFAULT:!aNULL",
            label="IP Camera (Hikvision-like)",
        ),
        SimulatedIoTServer(
            port=10444,
            cn="thermostat.local",
            org="SmartHome Inc",
            cipher_string="ECDHE+AESGCM:AES+AESGCM",
            label="Smart Thermostat",
        ),
    ]
    for s in servers:
        s.start()
    time.sleep(1)

    # Phase 0: Term paper core experiment (three profiles)
    profile_report = run_profile_experiment()

    # Phase 1: Detailed IoT server scans
    run_iot_server_scans()

    # Stop IoT servers (scans are done)
    for s in servers:
        s.stop()

    # Phase 2: Client-side downgrade testing
    client_results = run_client_tests()

    # Phase 3: MITM proxy
    run_mitm_test()

    # Phase 4: Automated Client Stack Testing (Paper 1 Core Methodology)
    stack_report = run_automated_stack_test()

    # Summary
    print("\n" + "=" * 60)
    print("  DEMO COMPLETE -- SUMMARY")
    print("=" * 60)
    print()
    print("  -- Term Paper Experiment (Profile Testing) ----------------")
    print(f"  |  Devices tested:      {len(profile_report.devices)} "
          f"({profile_report.iot_count} IoT [SIMULATED], {profile_report.web_count} web [REAL])")
    print(f"  |  IoT weak selection:  {profile_report.iot_weak_selection_pct}%")
    print(f"  |  Web weak selection:  {profile_report.web_weak_selection_pct}%")
    print(f"  |  NOTE: IoT servers are simulated on localhost.")
    print(f"  |  For real results, scan actual IoT devices with:")
    print(f"  |    python scan.py profiles --config config.yaml")
    print("  |")
    print("  -- IoT Server Scans ----------------------------------------")
    print(f"  |  2 SIMULATED IoT servers scanned on localhost")
    print("  |")
    print("  -- Client Downgrade Testing (Paper 1: Simulated) -----------")
    print(f"  |  Connections:  {len(client_results)} tested")
    vuln = sum(1 for r in client_results if r.vulnerable)
    prot = sum(1 for r in client_results if not r.vulnerable)
    print(f"  |  Vulnerable:   {vuln} (raw socket, no sentinel check)")
    print(f"  |  Protected:    {prot} (Python ssl / OpenSSL)")
    print("  |")
    print("  -- Automated Stack Testing (Paper 1: REAL) -----------------")
    print(f"  |  Stacks tested:  {stack_report.stacks_tested}")
    print(f"  |  Vulnerable:     {stack_report.stacks_vulnerable}")
    print(f"  |  Protected:      {stack_report.stacks_protected}")
    if stack_report.root_cause_summary:
        for cause, count in stack_report.root_cause_summary.items():
            print(f"  |  Root cause '{cause}': {count} stack(s)")
    print("  |")
    print("  ------------------------------------------------------------")
    print(f"\n  Results saved to: sample_results/")
    print(f"  Launch dashboard:     python dashboard.py")
    print("  For zero-hardware lab: python scan.py lab")
    print("=" * 60)

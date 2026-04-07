#!/usr/bin/env python3
"""
Test All Dashboard Scan Types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Exercises every scan type via the dashboard API with working sample inputs.
Run while dashboard.py is active on port 5000.

Usage:
    python test_all_scans.py              # Run all tests sequentially
    python test_all_scans.py --scan server  # Run a single test
"""

import json
import sys
import time

import requests

BASE = "http://127.0.0.1:5000"

# ─── Sample payloads for every scan type ──────────────────────

SAMPLES = {
    # 1) Server Scan – real public targets with interesting TLS configs
    "server_google": {
        "scan_type": "server",
        "host": "www.google.com",
        "port": 443,
        "label": "Google (modern TLS 1.3)",
    },
    "server_tls12_only": {
        "scan_type": "server",
        "host": "tls-v1-2.badssl.com",
        "port": 443,
        "label": "badssl TLS 1.2 only",
    },
    "server_github": {
        "scan_type": "server",
        "host": "github.com",
        "port": 443,
        "label": "GitHub (strong config)",
    },
    "server_expired": {
        "scan_type": "server",
        "host": "expired.badssl.com",
        "port": 443,
        "label": "badssl expired cert",
    },
    "server_self_signed": {
        "scan_type": "server",
        "host": "self-signed.badssl.com",
        "port": 443,
        "label": "badssl self-signed",
    },
    "server_sha256": {
        "scan_type": "server",
        "host": "sha256.badssl.com",
        "port": 443,
        "label": "badssl SHA-256 (baseline)",
    },
    "server_cbc": {
        "scan_type": "server",
        "host": "cbc.badssl.com",
        "port": 443,
        "label": "badssl CBC ciphers (weak)",
    },
    "server_rc4": {
        "scan_type": "server",
        "host": "rc4.badssl.com",
        "port": 443,
        "label": "badssl RC4 (insecure cipher)",
    },
    "server_mozilla": {
        "scan_type": "server",
        "host": "mozilla.org",
        "port": 443,
        "label": "Mozilla (reference config)",
    },
    "server_cloudflare": {
        "scan_type": "server",
        "host": "www.cloudflare.com",
        "port": 443,
        "label": "Cloudflare (TLS 1.3 leader)",
    },

    # 2) Virtual IoT Lab – no inputs needed, tests 12 emulated devices
    "lab": {
        "scan_type": "lab",
        "base_port": 24000,
        "stacks_port": 24100,
    },

    # 3) Client Stack Test – tests local TLS libraries
    "stacks": {
        "scan_type": "stacks",
        "port": 24200,
    },

    # 4) Cipher Preference Experiment
    "profiles": {
        "scan_type": "profiles",
        "base_port": 24300,
    },

    # 5) Network Discovery – scan localhost (will find dashboard itself)
    "discovery_localhost": {
        "scan_type": "discovery",
        "subnet": "127.0.0.1/32",
        "ports": "443,5000,8443",
        "timeout": 2,
    },

    # 6) Malicious Server – listens for 15s (short demo)
    "client_malicious": {
        "scan_type": "client_malicious",
        "port": 4433,
        "duration": 15,
    },

    # 7) MITM Proxy – proxies to google.com for 15s
    "client_mitm": {
        "scan_type": "client_mitm",
        "target_host": "www.google.com",
        "target_port": 443,
        "proxy_port": 8443,
        "downgrade_to": "TLSv1.2",
        "duration": 15,
    },

    # 8) PDF Report Generation
    "pdf": {
        "scan_type": "pdf",
    },
}

# ─── Quick preset groups ─────────────────────────────────────

QUICK_TESTS = [
    "server_google",
    "lab",
    "stacks",
    "profiles",
    "pdf",
]

ALL_SERVER_TESTS = [
    "server_google",
    "server_tls12_only",
    "server_github",
    "server_cbc",
    "server_rc4",
    "server_cloudflare",
    "server_mozilla",
]


def wait_for_completion(label, timeout=300):
    """Poll /api/scan/status until done or error."""
    print(f"  [{label}] Waiting...", end="", flush=True)
    t0 = time.time()
    last_pct = -1
    while time.time() - t0 < timeout:
        time.sleep(2)
        r = requests.get(f"{BASE}/api/scan/status")
        state = r.json()
        pct = state.get("percent", 0)
        if pct != last_pct:
            print(f" {pct}%", end="", flush=True)
            last_pct = pct

        if state["status"] == "done":
            summary = state.get("result_summary") or {}
            print(f"\n  [{label}] DONE in {time.time()-t0:.1f}s")
            print(f"  Summary: {json.dumps(summary, indent=4)}")
            return True
        elif state["status"] == "error":
            print(f"\n  [{label}] ERROR: {state.get('error')}")
            msgs = state.get("progress", [])
            if msgs:
                print(f"  Last messages: {msgs[-3:]}")
            return False

    print(f"\n  [{label}] TIMEOUT after {timeout}s")
    return False


def run_scan(name):
    payload = SAMPLES[name]
    scan_type = payload["scan_type"]
    print(f"\n{'='*60}")
    print(f"  SCAN: {name}  (type: {scan_type})")
    print(f"  Payload: {json.dumps(payload)}")
    print(f"{'='*60}")

    r = requests.post(f"{BASE}/api/scan", json=payload)
    if r.status_code == 409:
        print("  A scan is already running. Waiting for it to finish first...")
        wait_for_completion(name)
        r = requests.post(f"{BASE}/api/scan", json=payload)

    if r.status_code != 200:
        print(f"  FAILED to start: {r.status_code} {r.text}")
        return False

    print(f"  Started: {r.json()}")
    return wait_for_completion(name)


def check_result_endpoints():
    """Verify all result APIs return data."""
    print(f"\n{'='*60}")
    print(f"  CHECKING RESULT ENDPOINTS")
    print(f"{'='*60}")

    endpoints = {
        "/api/results": "Server Scan Results",
        "/api/discovery": "Network Discovery",
        "/api/lab-results": "Virtual Lab Report",
        "/api/stack-results": "Stack Test Results",
        "/api/profile-results": "Profile Comparison",
        "/api/vlab-profiles": "VLab Profile Comparison",
        "/api/client-results": "Client Test Results",
        "/api/scan/status": "Scan Status",
    }
    for ep, label in endpoints.items():
        r = requests.get(f"{BASE}{ep}")
        data = r.json()
        keys = list(data.keys()) if isinstance(data, dict) else f"[{len(data)} items]"
        has_data = "message" not in data if isinstance(data, dict) else len(data) > 0
        status = "HAS DATA" if has_data else "empty"
        print(f"  {label:30s} {ep:30s} {r.status_code}  {status}  keys={keys}")


def main():
    # Check dashboard is reachable
    try:
        requests.get(f"{BASE}/", timeout=3)
    except Exception:
        print("ERROR: Dashboard not reachable at", BASE)
        print("Start it first: python dashboard.py")
        sys.exit(1)

    arg = sys.argv[1] if len(sys.argv) > 1 else None

    if arg == "--help":
        print("Usage:")
        print("  python test_all_scans.py               # Quick tests (server, lab, stacks, profiles, pdf)")
        print("  python test_all_scans.py --all          # ALL tests including client modes")
        print("  python test_all_scans.py --servers      # All 6 server scan targets")
        print("  python test_all_scans.py --scan NAME    # Single scan (see SAMPLES dict)")
        print("  python test_all_scans.py --check        # Just check result endpoints")
        print(f"\nAvailable scan names: {', '.join(SAMPLES.keys())}")
        return

    if arg == "--check":
        check_result_endpoints()
        return

    if arg == "--scan":
        name = sys.argv[2] if len(sys.argv) > 2 else None
        if not name or name not in SAMPLES:
            print(f"Unknown scan name. Choose from: {', '.join(SAMPLES.keys())}")
            return
        run_scan(name)
        check_result_endpoints()
        return

    if arg == "--servers":
        for name in ALL_SERVER_TESTS:
            run_scan(name)
        check_result_endpoints()
        return

    if arg == "--all":
        for name in SAMPLES:
            run_scan(name)
        check_result_endpoints()
        return

    # Default: quick tests
    print("Running QUICK tests (server + lab + stacks + profiles + pdf)...")
    print("Use --all for everything, --help for options.\n")
    for name in QUICK_TESTS:
        run_scan(name)
    check_result_endpoints()


if __name__ == "__main__":
    main()

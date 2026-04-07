#!/usr/bin/env python3
"""
TLS Downgrade & Cipher Suite Analyzer for IoT Devices

Three operational modes aligned with the research methodology:

  MODE 1: Discover IoT devices on local network
    python scan.py discover --subnet 192.168.1.0/24

  MODE 2: Test IoT device as TLS SERVER (cipher/version/downgrade probing)
    python scan.py server --target 192.168.1.100:443 --label "IP Camera"
    python scan.py server --config config.yaml

  MODE 3: Test IoT device as TLS CLIENT (Paper 1 methodology)
    python scan.py client --mode malicious-server --port 4433 --duration 120
    python scan.py client --mode mitm --target api.vendor.com:443 --port 8443

References:
  Cho et al., "Return of Version Downgrade Attack in the Era of TLS 1.3"
  (CoNEXT 2020, DOI: 10.1145/3386367.3431310)
"""

import json
import os
import sys

import click
import yaml

from src.utils.logger import get_logger

log = get_logger("scan")


@click.group()
def cli():
    """TLS Downgrade & Cipher Suite Analyzer for IoT Devices"""
    pass


# ── MODE 1: Discover ─────────────────────────────────────────

@cli.command()
@click.option("--subnet", "-s", required=True,
              help="Subnet in CIDR notation (e.g. 192.168.1.0/24)")
@click.option("--ports", "-p", default="443,8443,4443",
              help="Comma-separated list of ports to scan")
@click.option("--timeout", default=2.0, help="Per-connection timeout (seconds)")
@click.option("--output", "-o", default="sample_results", help="Output directory")
def discover(subnet, ports, timeout, output):
    """Discover IoT devices with TLS services on local network."""
    from src.scanner.network_discovery import discover_subnet
    from dataclasses import asdict

    port_list = [int(p.strip()) for p in ports.split(",")]

    click.echo(f"\n{'='*60}")
    click.echo(f"  IoT Device Discovery")
    click.echo(f"  Subnet: {subnet}  Ports: {port_list}")
    click.echo(f"{'='*60}\n")

    result = discover_subnet(subnet, port_list, timeout)

    click.echo(f"\nFound {len(result.devices_found)} TLS-enabled devices:\n")
    for dev in result.devices_found:
        click.echo(f"  {dev.ip}:{dev.port}")
        click.echo(f"    Type:    {dev.device_type}")
        click.echo(f"    TLS:     {dev.tls_version or '?'}")
        click.echo(f"    Cert CN: {dev.certificate_cn or '?'}")
        click.echo(f"    Banner:  {dev.server_banner or '?'}")
        click.echo()

    os.makedirs(output, exist_ok=True)
    filepath = os.path.join(output, "discovery.json")
    with open(filepath, "w") as f:
        json.dump(asdict(result), f, indent=2, default=str)
    click.echo(f"Results saved to {filepath}")

    if result.devices_found:
        click.echo("\nTo scan a discovered device as a server:")
        dev = result.devices_found[0]
        click.echo(f'  python scan.py server --target {dev.ip}:{dev.port} --label "{dev.device_type}"')


# ── MODE 2: Test IoT Device as Server ────────────────────────

@cli.command()
@click.option("--target", "-t",
              help="Target in host:port format (e.g. 192.168.1.100:443)")
@click.option("--label", "-l", default="", help="Friendly label for the target")
@click.option("--config", "-c", type=click.Path(exists=True),
              help="YAML config with server_targets list")
@click.option("--timeout", default=10.0, help="Connection timeout (seconds)")
@click.option("--output", "-o", default="sample_results", help="Output directory")
@click.option("--json-only", is_flag=True, help="JSON output only, no terminal report")
def server(target, label, config, timeout, output, json_only):
    """Test IoT device acting as TLS server (versions, ciphers, downgrade)."""
    from src.scanner.tls_scanner import scan_target, scan_targets
    from src.utils.report import print_full_report

    targets = []

    if config:
        with open(config) as f:
            cfg = yaml.safe_load(f)
        targets = cfg.get("server_targets", cfg.get("targets", []))
        timeout = cfg.get("scan", {}).get("timeout", timeout)
        output = cfg.get("output", {}).get("results_dir", output)
    elif target:
        if ":" in target:
            parts = target.rsplit(":", 1)
            host, port = parts[0], int(parts[1])
        else:
            host, port = target, 443
        targets = [{"host": host, "port": port, "label": label or target}]
    else:
        click.echo("Specify --target or --config. Use --help for details.")
        sys.exit(1)

    click.echo(f"\n{'='*60}")
    click.echo(f"  IoT Server TLS Analysis")
    click.echo(f"  Testing {len(targets)} device(s) as TLS servers")
    click.echo(f"{'='*60}\n")

    results = scan_targets(targets, timeout, output)

    if not json_only:
        for r in results:
            click.echo(print_full_report(r))

    click.echo(f"\nResults saved to: {os.path.abspath(output)}/")
    click.echo("Launch dashboard: python dashboard.py")


# ── MODE 3: Three-Profile Cipher Selection (Term Paper) ──────

@cli.command()
@click.option("--target", "-t", multiple=True,
              help="Target in host:port:type format (type = iot or web). Repeat for multiple.")
@click.option("--config", "-c", type=click.Path(exists=True),
              help="YAML config with profile_targets list")
@click.option("--timeout", default=10.0, help="Connection timeout (seconds)")
@click.option("--output", "-o", default="sample_results", help="Output directory")
def profiles(target, config, timeout, output):
    """Run the three-profile cipher selection experiment (Term Paper).

    \b
    Tests each target with three client personalities:
      Modern (green)  -- only strong ciphers (ECDHE + AEAD)
      Mixed  (yellow) -- strong AND weak ciphers together
      Legacy (red)    -- only old, weak ciphers (RSA kex, CBC)

    \b
    Records what the server picks each time and compares IoT vs web servers.

    \b
    Examples:
      python scan.py profiles -t 192.168.1.100:443:iot -t www.google.com:443:web
      python scan.py profiles --config config.yaml
    """
    from src.scanner.profile_tester import run_profile_experiment
    from dataclasses import asdict

    targets = []

    if config:
        with open(config) as f:
            cfg = yaml.safe_load(f)
        targets = cfg.get("profile_targets", [])
        timeout = cfg.get("scan", {}).get("timeout", timeout)
        output = cfg.get("output", {}).get("results_dir", output)
    elif target:
        for t in target:
            parts = t.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443
            dtype = parts[2] if len(parts) > 2 else "unknown"
            targets.append({"host": host, "port": port, "label": host, "type": dtype})

    if not targets:
        click.echo("Specify --target or --config. Use --help for details.")
        sys.exit(1)

    click.echo(f"\n{'='*60}")
    click.echo(f"  Three-Profile Cipher Selection Experiment")
    click.echo(f"  Testing {len(targets)} device(s) with Modern/Mixed/Legacy clients")
    click.echo(f"{'='*60}\n")

    report = run_profile_experiment(targets, timeout)

    # Print summary table
    click.echo(f"\n{'='*60}")
    click.echo(f"  RESULTS")
    click.echo(f"{'='*60}\n")

    header = f"  {'Device':<30} {'Type':<6} {'Modern':<22} {'Mixed':<22} {'Legacy':<22} {'Pref?':<5}"
    click.echo(header)
    click.echo("  " + "-" * 110)

    for d in report.devices:
        def _fmt(p):
            if not p or not p.connected:
                return "FAILED"
            pfs = " [PFS]" if p.has_forward_secrecy else ""
            return f"{p.cipher_name[:16]}{pfs}"
        m = _fmt(d.profiles.get("modern"))
        x = _fmt(d.profiles.get("mixed"))
        l = _fmt(d.profiles.get("legacy"))
        pref = "Yes" if d.server_enforces_preference else "No"
        weak = " *WEAK*" if d.chose_weak_with_mixed else ""
        click.echo(f"  {d.label:<30} {d.device_type:<6} {m:<22} {x:<22} {l:<22} {pref:<5}{weak}")

    click.echo(f"\n  IoT weak selection rate:  {report.iot_weak_selection_pct}%")
    click.echo(f"  Web weak selection rate:  {report.web_weak_selection_pct}%")
    click.echo(f"  IoT PFS rate (mixed):     {report.iot_pfs_with_mixed_pct}%")
    click.echo(f"  Web PFS rate (mixed):     {report.web_pfs_with_mixed_pct}%")

    if report.findings:
        click.echo(f"\n  Findings:")
        for f in report.findings:
            click.echo(f"    -> {f}")

    # Save
    os.makedirs(output, exist_ok=True)
    filepath = os.path.join(output, "profile_comparison.json")
    with open(filepath, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    click.echo(f"\n  Results saved to {filepath}")
    click.echo("  Launch dashboard: python dashboard.py")


# ── MODE 4: Automated Client Stack Testing (Paper 1 Core) ────

@cli.command()
@click.option("--port", "-p", default=14500,
              help="Port for the malicious test server")
@click.option("--output", "-o", default="sample_results", help="Output directory")
def stacks(port, output):
    """Test available TLS client stacks for downgrade vulnerability (Paper 1).

    \b
    Replicates the core methodology of Cho et al. (CoNEXT 2020):
    the paper tested 10 browsers x 5 OSes for sentinel validation.
    This command tests every TLS client library available on this system.

    \b
    Discovers and tests: OpenSSL, GnuTLS, curl, Python ssl, and raw
    socket simulations of vulnerable/protected IoT firmware.

    \b
    For each client, tests:
      sentinel_present   -- Server includes sentinel (client MUST abort)
      sentinel_omission  -- Sentinel stripped (simulates MITM attack)
      downgrade_to_10    -- Force TLS 1.0 (paper demonstrated 1.3 -> 1.0)
      downgrade_to_11    -- Force TLS 1.1

    \b
    Example:
      python scan.py stacks
      python scan.py stacks --port 15000 --output results/
    """
    from src.attack.automated_client_tester import (
        discover_client_stacks, run_automated_test, save_report,
    )

    click.echo(f"\n{'='*60}")
    click.echo(f"  Automated TLS Client Stack Testing (Paper 1 Methodology)")
    click.echo(f"  Reference: Cho et al., CoNEXT 2020")
    click.echo(f"{'='*60}\n")

    stacks_info = discover_client_stacks()
    available = [s for s in stacks_info if s.available]
    click.echo(f"  Discovered {len(stacks_info)} client stacks, {len(available)} available:\n")
    for s in stacks_info:
        status = "+" if s.available else "-"
        click.echo(f"    [{status}] {s.name:<25} {s.library}")

    click.echo(f"\n  Starting tests on port {port}...\n")

    def on_progress(msg):
        click.echo(f"  {msg}")

    report = run_automated_test(listen_port=port, on_progress=on_progress)
    path = save_report(report, output)

    click.echo(f"\n{'='*60}")
    click.echo(f"  RESULTS")
    click.echo(f"{'='*60}\n")

    header = f"  {'Stack':<28} {'Library':<35} {'Sentinel Check':<16} {'Verdict':<12}"
    click.echo(header)
    click.echo("  " + "-" * 90)
    for sr in report.stack_reports:
        sentinel_test = next((r for r in sr.test_results if r.scenario == "sentinel_present"), None)
        sentinel_str = "Yes" if (sentinel_test and sentinel_test.sentinel_detected) else "No"
        verdict = "VULNERABLE" if sr.overall_vulnerable else "Protected"
        click.echo(f"  {sr.stack.name:<28} {sr.stack.library:<35} {sentinel_str:<16} {verdict:<12}")

    click.echo(f"\n  Vulnerable: {report.stacks_vulnerable}/{report.stacks_tested}")
    click.echo(f"  Protected:  {report.stacks_protected}/{report.stacks_tested}")

    if report.root_cause_summary:
        click.echo(f"\n  Root causes:")
        for cause, count in report.root_cause_summary.items():
            click.echo(f"    {cause}: {count} stack(s)")

    for f in report.findings:
        click.echo(f"\n  >> {f}")

    click.echo(f"\n  Report saved to: {os.path.abspath(path)}")
    click.echo("  Launch dashboard: python dashboard.py")


# ── MODE 5: Test IoT Device as Client (Paper 1) ─────────────

@cli.command()
@click.option("--mode", "-m", type=click.Choice(["malicious-server", "mitm"]),
              required=True,
              help="Test mode: malicious-server (sentinel omission) or mitm (proxy)")
@click.option("--port", "-p", default=4433, help="Listen port for the test server/proxy")
@click.option("--target", "-t", default="",
              help="[mitm mode] Real server the IoT device connects to (host:port)")
@click.option("--downgrade-to", default="TLSv1.0",
              type=click.Choice(["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"]),
              help="[mitm mode] Version to downgrade to")
@click.option("--duration", "-d", default=120.0,
              help="How long to wait for connections (seconds)")
@click.option("--output", "-o", default="sample_results", help="Output directory")
def client(mode, port, target, downgrade_to, duration, output):
    """Test IoT device acting as TLS client (Paper 1 downgrade methodology).

    This implements the core methodology from Cho et al. (CoNEXT 2020):
    testing whether IoT device TLS client stacks properly validate the
    RFC 8446 downgrade sentinel.

    \b
    Malicious Server mode (--mode malicious-server):
      Starts a TLS server that deliberately omits the downgrade sentinel.
      Direct IoT devices to connect to this server via DNS/ARP redirect.
      If the client completes the handshake, it is VULNERABLE.

    \b
    MITM Proxy mode (--mode mitm):
      Starts a proxy that intercepts IoT device traffic, rewrites the
      ClientHello version, and strips the sentinel from ServerHello.
      Requires --target to specify the real server.
    """
    version_map = {
        "SSLv3": 0x0300, "TLSv1.0": 0x0301,
        "TLSv1.1": 0x0302, "TLSv1.2": 0x0303,
    }

    click.echo(f"\n{'='*60}")
    click.echo(f"  IoT Client Downgrade Testing (Paper 1 Methodology)")
    click.echo(f"  Mode: {mode}")
    click.echo(f"{'='*60}")
    click.echo()
    click.echo("  Reference: Cho et al., 'Return of Version Downgrade Attack")
    click.echo("  in the Era of TLS 1.3' (CoNEXT 2020)")
    click.echo()

    if mode == "malicious-server":
        from src.attack.client_downgrade_tester import run_malicious_server_test

        click.echo(f"  Starting malicious TLS server on port {port}")
        click.echo(f"  Duration: {duration}s per test scenario")
        click.echo(f"  Direct IoT devices to connect to THIS machine's IP, port {port}")
        click.echo()
        click.echo("  Waiting for IoT device connections...")
        click.echo("  (Use Ctrl+C to stop early)\n")

        try:
            report = run_malicious_server_test(
                listen_port=port, duration=duration, output_dir=output,
            )
        except KeyboardInterrupt:
            click.echo("\nStopped by user.")
            return

        click.echo(f"\n{'='*60}")
        click.echo(f"  RESULTS")
        click.echo(f"{'='*60}")
        click.echo(f"  Total connections:        {report.total_client_connections}")
        click.echo(f"  Vulnerable (no sentinel): {report.clients_vulnerable_to_sentinel_omission}")
        click.echo(f"  Protected:                {report.clients_protected}")
        click.echo(f"  Clients sent SCSV:        {report.clients_sending_scsv}")
        for f in report.findings:
            click.echo(f"  -> {f}")

    elif mode == "mitm":
        if not target:
            click.echo("ERROR: --target is required for mitm mode (e.g. --target api.vendor.com:443)")
            sys.exit(1)

        from src.attack.client_downgrade_tester import run_mitm_proxy_test

        if ":" in target:
            thost, tport = target.rsplit(":", 1)
            tport = int(tport)
        else:
            thost, tport = target, 443

        dg_version = version_map.get(downgrade_to, 0x0301)

        click.echo(f"  MITM Proxy: :{port} -> {thost}:{tport}")
        click.echo(f"  Downgrading to: {downgrade_to}")
        click.echo(f"  Duration: {duration}s")
        click.echo(f"  Route IoT device traffic through THIS machine, port {port}")
        click.echo()
        click.echo("  Waiting for IoT device connections...")
        click.echo("  (Use Ctrl+C to stop early)\n")

        try:
            report = run_mitm_proxy_test(
                target_host=thost, target_port=tport,
                proxy_port=port, downgrade_to=dg_version,
                duration=duration, output_dir=output,
            )
        except KeyboardInterrupt:
            click.echo("\nStopped by user.")
            return

        click.echo(f"\n{'='*60}")
        click.echo(f"  RESULTS")
        click.echo(f"{'='*60}")
        click.echo(f"  Total connections:           {report.total_client_connections}")
        click.echo(f"  Successful downgrades:       {report.clients_vulnerable_to_version_downgrade}")
        click.echo(f"  Blocked by server/client:    {report.clients_protected}")
        for f in report.findings:
            click.echo(f"  -> {f}")

    click.echo(f"\nReport saved to: {os.path.abspath(output)}/")
    click.echo("Launch dashboard: python dashboard.py")


# ── MODE 6: Virtual IoT Lab (No Hardware Required) ───────────

@cli.command()
@click.option("--base-port", default=17000, help="Starting port for virtual IoT servers")
@click.option("--stacks-port", default=17100, help="Port for client stack testing")
@click.option("--output", "-o", default="sample_results", help="Output directory")
@click.option("--server-only", is_flag=True, help="Only run server-side scans")
@click.option("--client-only", is_flag=True, help="Only run client stack tests")
@click.option("--profiles-only", is_flag=True, help="Only run cipher preference experiment")
def lab(base_port, stacks_port, output, server_only, client_only, profiles_only):
    """Run a complete virtual IoT lab -- no hardware required.

    \b
    Spawns virtual TLS servers that faithfully replicate real IoT device
    firmware TLS configurations (Hikvision, Dahua, Synology, WD MyCloud,
    TP-Link, medical devices, etc.), then runs the full scan pipeline
    against them.

    \b
    The lab runs three phases:
      Phase 1: Server TLS scan (versions, ciphers, downgrade detection)
      Phase 2: Three-profile cipher preference (Modern/Mixed/Legacy)
      Phase 3: Client stack sentinel testing (Paper 1 methodology)

    \b
    Why this works: the TLS library and configuration -- not the hardware --
    determine protocol behavior. A Hikvision camera running OpenSSL 1.0.2k
    produces identical handshakes to software configured the same way.

    \b
    Examples:
      python scan.py lab                      # Full lab
      python scan.py lab --server-only        # Server scans only
      python scan.py lab --profiles-only      # Cipher preference only
      python scan.py lab --client-only        # Client stacks only
    """
    from src.emulation.virtual_lab import run_lab
    from src.emulation.iot_profiles import get_all_server_profiles

    do_server = True
    do_profiles = True
    do_clients = True

    if server_only or client_only or profiles_only:
        do_server = server_only
        do_profiles = profiles_only
        do_clients = client_only

    profiles = get_all_server_profiles()

    click.echo(f"\n{'='*60}")
    click.echo(f"  Virtual IoT Lab -- No Hardware Required")
    click.echo(f"{'='*60}")
    click.echo(f"\n  {len(profiles)} device profiles loaded:")
    for p in profiles:
        tag = "IoT" if p.category != "web_baseline" else "Web"
        click.echo(f"    [{tag:>3}] {p.name} ({p.firmware_tls_library})")

    phases = []
    if do_server:
        phases.append("Server scan")
    if do_profiles:
        phases.append("Cipher profiles")
    if do_clients:
        phases.append("Client stacks")
    click.echo(f"\n  Phases: {', '.join(phases)}")
    click.echo(f"  Server ports: {base_port}-{base_port + len(profiles) - 1}")
    click.echo(f"  Client test port: {stacks_port}")
    click.echo()

    def on_progress(msg):
        click.echo(f"  {msg}")

    report = run_lab(
        base_port=base_port,
        stacks_port=stacks_port,
        output_dir=output,
        run_server_scan=do_server,
        run_profiles=do_profiles,
        run_client_stacks=do_clients,
        on_progress=on_progress,
    )

    click.echo(f"\n{'='*60}")
    click.echo(f"  LAB RESULTS")
    click.echo(f"{'='*60}")
    click.echo(f"\n  Duration: {report.duration_seconds}s")
    click.echo(f"  Profiles tested: {report.profiles_used}")

    if report.server_scan_results:
        reachable = [r for r in report.server_scan_results if r.get("reachable")]
        click.echo(f"\n  Server scan: {len(reachable)}/{len(report.server_scan_results)} reachable")
        for r in reachable:
            grade = r.get("overall_grade", "?")
            risk = r.get("overall_risk", "?")
            click.echo(f"    {r['label']:<40} Grade: {grade}  Risk: {risk}")

    if report.profile_comparison:
        pc = report.profile_comparison
        click.echo(f"\n  Cipher preference experiment:")
        click.echo(f"    IoT weak selection:  {pc.get('iot_weak_selection_pct', 0)}%")
        click.echo(f"    Web weak selection:  {pc.get('web_weak_selection_pct', 0)}%")
        click.echo(f"    IoT PFS rate:        {pc.get('iot_pfs_with_mixed_pct', 0)}%")
        click.echo(f"    Web PFS rate:        {pc.get('web_pfs_with_mixed_pct', 0)}%")

    if report.client_stack_report:
        cs = report.client_stack_report
        click.echo(f"\n  Client stack testing:")
        click.echo(f"    Tested:     {cs.get('stacks_tested', 0)}")
        click.echo(f"    Vulnerable: {cs.get('stacks_vulnerable', 0)}")
        click.echo(f"    Protected:  {cs.get('stacks_protected', 0)}")

    if report.findings:
        click.echo(f"\n  Key findings:")
        for f in report.findings:
            click.echo(f"    -> {f}")

    click.echo(f"\n  Report: {os.path.abspath(output)}/virtual_lab_report.json")
    click.echo("  Launch dashboard: python dashboard.py")


if __name__ == "__main__":
    cli()

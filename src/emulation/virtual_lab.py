"""
Virtual IoT Lab Orchestrator

Runs a complete TLS security analysis without physical hardware:
  Phase 1: Server TLS scan (versions, ciphers, downgrade detection)
  Phase 2: Three-profile cipher preference experiment (Modern/Mixed/Legacy)
  Phase 3: Client stack sentinel testing (Paper 1 methodology)

All targets are software-emulated TLS servers configured to faithfully
replicate documented IoT device firmware TLS behavior.
"""

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from src.emulation.iot_profiles import (
    get_all_server_profiles,
    get_iot_client_profiles,
    get_iot_server_profiles,
    get_web_baseline_profiles,
)
from src.emulation.virtual_iot_server import VirtualServerFleet
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class LabReport:
    lab_time: str = ""
    duration_seconds: float = 0.0
    profiles_used: int = 0
    server_scan_results: List[Dict] = field(default_factory=list)
    profile_comparison: Optional[Dict] = None
    client_stack_report: Optional[Dict] = None
    methodology_note: str = (
        "All targets are software-emulated TLS servers configured to faithfully "
        "replicate documented IoT device firmware TLS behavior. The TLS library "
        "and configuration -- not the hardware -- determine protocol behavior. "
        "Results are structurally identical to scans of physical devices."
    )
    findings: List[str] = field(default_factory=list)


def run_lab(
    base_port: int = 17000,
    stacks_port: int = 17100,
    output_dir: str = "sample_results",
    run_server_scan: bool = True,
    run_profiles: bool = True,
    run_client_stacks: bool = True,
    on_progress: Optional[Callable[[str], None]] = None,
) -> LabReport:
    """Run the complete virtual IoT lab.

    Returns a LabReport with all results and findings.
    """
    report = LabReport(
        lab_time=datetime.now(timezone.utc).isoformat(),
    )
    t0 = time.time()

    profiles = get_all_server_profiles()
    report.profiles_used = len(profiles)
    os.makedirs(output_dir, exist_ok=True)

    def _log(msg: str):
        log.info(msg)
        if on_progress:
            on_progress(msg)

    fleet = None

    # Start virtual servers if needed for phases 1 or 2
    if run_server_scan or run_profiles:
        _log(f"Starting {len(profiles)} virtual TLS servers on ports "
             f"{base_port}-{base_port + len(profiles) - 1}...")
        fleet = VirtualServerFleet(profiles, base_port=base_port)
        fleet.start_all()
        time.sleep(2)
        scan_targets = fleet.get_scan_targets()

    # ── Phase 1: Server TLS Scan ──────────────────────────────
    if run_server_scan:
        _log("")
        _log("=" * 50)
        _log("PHASE 1: Server TLS Scan (versions, ciphers, downgrade)")
        _log("=" * 50)

        from src.scanner.tls_scanner import scan_target, _to_dict

        for target in scan_targets:
            host = target["host"]
            port = target["port"]
            label = target["label"]
            _log(f"Scanning {label} ({host}:{port})...")

            try:
                result = scan_target(host, port, label, timeout=10)
                result_dict = _to_dict(result)
                result_dict["simulated"] = True
                report.server_scan_results.append(result_dict)

                safe_name = label.replace(" ", "_").replace("(", "").replace(")", "").lower()
                filepath = os.path.join(output_dir, f"vlab_{safe_name}.json")
                with open(filepath, "w") as f:
                    json.dump(result_dict, f, indent=2, default=str)

            except Exception as exc:
                _log(f"  Scan failed for {label}: {exc}")
                report.server_scan_results.append({
                    "label": label, "host": host, "port": port,
                    "reachable": False, "error": str(exc),
                })

    # ── Phase 2: Three-Profile Cipher Preference ──────────────
    if run_profiles:
        _log("")
        _log("=" * 50)
        _log("PHASE 2: Three-Profile Cipher Preference Experiment")
        _log("=" * 50)

        from src.scanner.profile_tester import run_profile_experiment

        profile_targets = []
        for t in scan_targets:
            profile_targets.append({
                "host": t["host"],
                "port": t["port"],
                "label": t["label"],
                "type": t["type"],
            })

        try:
            profile_report = run_profile_experiment(profile_targets, timeout=10.0)
            profile_dict = asdict(profile_report)
            report.profile_comparison = profile_dict

            filepath = os.path.join(output_dir, "vlab_profile_comparison.json")
            with open(filepath, "w") as f:
                json.dump(profile_dict, f, indent=2, default=str)

            _log(f"IoT weak selection: {profile_report.iot_weak_selection_pct}%")
            _log(f"Web weak selection: {profile_report.web_weak_selection_pct}%")
        except Exception as exc:
            _log(f"Profile experiment failed: {exc}")

    # Stop fleet after server-side phases
    if fleet:
        fleet.stop_all()
        _log("Virtual servers stopped.")

    # ── Phase 3: Client Stack Sentinel Testing ────────────────
    if run_client_stacks:
        _log("")
        _log("=" * 50)
        _log("PHASE 3: Automated Client Stack Testing (Paper 1)")
        _log("=" * 50)

        from src.attack.automated_client_tester import run_automated_test, save_report

        try:
            test_report = run_automated_test(
                listen_port=stacks_port,
                on_progress=on_progress,
            )
            save_report(test_report, output_dir)
            report.client_stack_report = asdict(test_report)

            _log(f"Stacks tested: {test_report.stacks_tested}")
            _log(f"Vulnerable: {test_report.stacks_vulnerable}")
            _log(f"Protected: {test_report.stacks_protected}")
        except Exception as exc:
            _log(f"Client stack testing failed: {exc}")

    # ── Generate findings ─────────────────────────────────────
    if report.server_scan_results:
        poor = [r for r in report.server_scan_results
                if r.get("overall_grade", "?") in ("D", "F")]
        if poor:
            report.findings.append(
                f"{len(poor)}/{len(report.server_scan_results)} servers received "
                f"grade D or F."
            )

    if report.profile_comparison:
        pc = report.profile_comparison
        iot_weak = pc.get("iot_weak_selection_pct", 0)
        web_weak = pc.get("web_weak_selection_pct", 0)
        if iot_weak > web_weak:
            report.findings.append(
                f"IoT devices chose weak ciphers {iot_weak}% vs "
                f"{web_weak}% for web servers."
            )

        iot_pfs = pc.get("iot_pfs_with_mixed_pct", 0)
        web_pfs = pc.get("web_pfs_with_mixed_pct", 0)
        if iot_pfs < web_pfs:
            report.findings.append(
                f"Forward secrecy (mixed client): IoT {iot_pfs}% vs Web {web_pfs}%."
            )

    if report.client_stack_report:
        vuln = report.client_stack_report.get("stacks_vulnerable", 0)
        tested = report.client_stack_report.get("stacks_tested", 0)
        if vuln > 0:
            report.findings.append(
                f"{vuln}/{tested} client stacks are vulnerable to "
                f"TLS version downgrade attacks."
            )

    # ── Finalize ──────────────────────────────────────────────
    report.duration_seconds = round(time.time() - t0, 1)

    lab_path = os.path.join(output_dir, "virtual_lab_report.json")
    with open(lab_path, "w") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    _log(f"Lab report saved to {lab_path}")

    return report

"""
Main TLS Scanner Orchestrator

Combines version probing, cipher suite enumeration, and downgrade detection
into a single scan pipeline. Results are serialised to JSON for the dashboard.
"""

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.scanner.cipher_probe import CipherScanResult, scan_ciphers
from src.scanner.constants import TLSVersion
from src.scanner.downgrade_detector import DowngradeReport, analyze_downgrade
from src.scanner.version_probe import VersionScanResult, scan_versions
from src.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class TargetScanResult:
    host: str
    port: int
    label: str
    scan_time: str
    reachable: bool = True
    version_scan: Optional[Dict] = None
    cipher_scan: Optional[Dict] = None
    downgrade_report: Optional[Dict] = None
    overall_risk: str = "Unknown"
    overall_grade: str = "?"
    scan_duration_ms: float = 0.0


def _to_dict(obj: Any) -> Dict:
    """Recursively convert dataclasses to plain dicts."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    return obj


def scan_target(host: str, port: int, label: str = "",
                timeout: float = 10.0) -> TargetScanResult:
    """Run the full scan pipeline on a single target."""
    t0 = time.time()
    result = TargetScanResult(
        host=host, port=port, label=label or f"{host}:{port}",
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    # Phase 1: Version scan
    log.info("=" * 60)
    log.info("PHASE 1: Version scan for %s:%d (%s)", host, port, label)
    log.info("=" * 60)
    try:
        vscan = scan_versions(host, port, label, timeout)
        result.version_scan = _to_dict(vscan)
    except Exception as exc:
        log.error("Version scan failed: %s", exc)
        result.reachable = False
        result.scan_duration_ms = (time.time() - t0) * 1000
        return result

    # Determine supported versions for later phases
    supported_codes = []
    for v in vscan.versions:
        if v.supported:
            supported_codes.append(v.version_code)

    if not supported_codes:
        log.warning("No TLS versions supported by %s:%d – host may be unreachable.", host, port)
        result.reachable = False
        result.scan_duration_ms = (time.time() - t0) * 1000
        return result

    # Phase 2: Cipher suite scan (on highest supported version)
    best_version = max(supported_codes)
    version_label = {
        TLSVersion.SSL_3_0: "SSLv3", TLSVersion.TLS_1_0: "TLSv1.0",
        TLSVersion.TLS_1_1: "TLSv1.1", TLSVersion.TLS_1_2: "TLSv1.2",
        TLSVersion.TLS_1_3: "TLSv1.3",
    }.get(best_version, "TLSv1.2")

    log.info("=" * 60)
    log.info("PHASE 2: Cipher suite scan (%s) for %s:%d", version_label, host, port)
    log.info("=" * 60)
    try:
        cscan = scan_ciphers(host, port, label, version_label, timeout)
        result.cipher_scan = _to_dict(cscan)
        result.overall_grade = cscan.overall_grade
    except Exception as exc:
        log.error("Cipher scan failed: %s", exc)

    # Also scan TLS 1.2 ciphers if highest is 1.3 (since 1.3 has separate suites)
    if best_version == TLSVersion.TLS_1_3 and TLSVersion.TLS_1_2 in supported_codes:
        log.info("Also scanning TLS 1.2 cipher suites ...")
        try:
            cscan12 = scan_ciphers(host, port, label, "TLSv1.2", timeout)
            if result.cipher_scan:
                result.cipher_scan["tls12_ciphers"] = _to_dict(cscan12).get("accepted_ciphers", [])
        except Exception:
            pass

    # Phase 3: Downgrade analysis
    log.info("=" * 60)
    log.info("PHASE 3: Downgrade vulnerability analysis for %s:%d", host, port)
    log.info("=" * 60)
    try:
        dreport = analyze_downgrade(host, port, label, supported_codes, timeout)
        result.downgrade_report = _to_dict(dreport)
        result.overall_risk = dreport.risk_level
    except Exception as exc:
        log.error("Downgrade analysis failed: %s", exc)

    result.scan_duration_ms = round((time.time() - t0) * 1000, 1)
    log.info("Scan of %s:%d completed in %.1f ms", host, port, result.scan_duration_ms)
    return result


def scan_targets(targets: List[Dict], timeout: float = 10.0,
                 output_dir: str = "sample_results") -> List[Dict]:
    """Scan multiple targets and save results."""
    os.makedirs(output_dir, exist_ok=True)
    all_results = []

    for target in targets:
        host = target["host"]
        port = target.get("port", 443)
        label = target.get("label", f"{host}:{port}")

        result = scan_target(host, port, label, timeout)
        result_dict = _to_dict(result)
        all_results.append(result_dict)

        # Save individual result
        safe_name = f"{host}_{port}".replace(".", "_")
        filepath = os.path.join(output_dir, f"{safe_name}.json")
        with open(filepath, "w") as f:
            json.dump(result_dict, f, indent=2, default=str)
        log.info("Saved result to %s", filepath)

    # Save combined results
    combined_path = os.path.join(output_dir, "combined_results.json")
    combined = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "targets_scanned": len(targets),
            "tool": "TLS Downgrade & Cipher Suite Analyzer",
            "version": "1.0.0",
        },
        "results": all_results,
    }
    with open(combined_path, "w") as f:
        json.dump(combined, f, indent=2, default=str)
    log.info("Combined results saved to %s", combined_path)

    return all_results

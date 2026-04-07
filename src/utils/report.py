"""Report generation utilities -- terminal table and summary output."""

from typing import Any, Dict, List

from colorama import Fore, Style
from tabulate import tabulate


def print_version_table(version_scan: Dict) -> str:
    """Format version scan results as a table."""
    rows = []
    for v in version_scan.get("versions", []):
        status = f"{Fore.GREEN}[+] Supported{Style.RESET_ALL}" if v["supported"] else f"{Fore.RED}[-] Not supported{Style.RESET_ALL}"
        cipher = v.get("negotiated_cipher", "-") or "-"
        latency = f"{v.get('latency_ms', 0):.0f} ms"
        rows.append([v["version_name"], status, cipher, latency])
    return tabulate(rows, headers=["Version", "Status", "Negotiated Cipher", "Latency"],
                    tablefmt="grid")


def print_cipher_table(cipher_scan: Dict) -> str:
    """Format cipher scan results as a colour-coded table."""
    rows = []
    for c in cipher_scan.get("accepted_ciphers", []):
        grade = c.get("grade", "?")
        color = {
            "A+": Fore.GREEN, "A": Fore.GREEN, "B": Fore.CYAN,
            "C": Fore.YELLOW, "D": Fore.RED, "F": Fore.RED + Style.BRIGHT,
        }.get(grade, "")
        rows.append([
            f"{color}{c['name']}{Style.RESET_ALL}",
            c.get("kex", "?"),
            c.get("enc", "?"),
            c.get("mac", "?"),
            f"{color}{grade}{Style.RESET_ALL}",
            c.get("notes", ""),
        ])
    return tabulate(rows, headers=["Cipher Suite", "Key Exch", "Encryption", "MAC", "Grade", "Notes"],
                    tablefmt="grid")


def print_downgrade_report(report: Dict) -> str:
    """Format downgrade analysis as readable output."""
    lines = []
    risk = report.get("risk_level", "Unknown")
    score = report.get("risk_score", 0)

    color = Fore.GREEN
    if risk in ("Critical", "High"):
        color = Fore.RED + Style.BRIGHT
    elif risk == "Medium":
        color = Fore.YELLOW
    elif risk == "Low":
        color = Fore.CYAN

    lines.append(f"\n{'='*60}")
    lines.append(f"  DOWNGRADE VULNERABILITY REPORT")
    lines.append(f"  Risk Level: {color}{risk} ({score}/100){Style.RESET_ALL}")
    lines.append(f"{'='*60}")

    # SCSV
    scsv = report.get("fallback_scsv")
    if scsv:
        icon = "[+]" if scsv.get("scsv_supported") else "[-]"
        lines.append(f"\n  FALLBACK_SCSV: {icon}  {scsv.get('details', '')}")

    # Sentinel
    sentinel = report.get("downgrade_sentinel")
    if sentinel:
        icon = "[+]" if sentinel.get("sentinel_present") else "[-]"
        lines.append(f"  Downgrade Sentinel: {icon}  {sentinel.get('details', '')}")

    # Version intolerance
    vi = report.get("version_intolerance")
    if vi:
        icon = "[-]" if vi.get("intolerant") else "[+]"
        lines.append(f"  Version Intolerance: {icon}  {vi.get('details', '')}")

    # Findings
    findings = report.get("findings", [])
    if findings:
        lines.append(f"\n  {Fore.RED}Findings:{Style.RESET_ALL}")
        for f in findings:
            lines.append(f"    * {f}")

    # Recommendations
    recs = report.get("recommendations", [])
    if recs:
        lines.append(f"\n  {Fore.GREEN}Recommendations:{Style.RESET_ALL}")
        for r in recs:
            lines.append(f"    -> {r}")

    lines.append("")
    return "\n".join(lines)


def print_full_report(result: Dict) -> str:
    """Print the complete scan report for a target."""
    parts = []
    label = result.get("label", result.get("host", "?"))
    host = result.get("host", "?")
    port = result.get("port", "?")

    parts.append(f"\n{'#'*60}")
    parts.append(f"  TARGET: {label} ({host}:{port})")
    parts.append(f"  Grade: {result.get('overall_grade', '?')}  |  Risk: {result.get('overall_risk', '?')}")
    parts.append(f"  Duration: {result.get('scan_duration_ms', 0):.0f} ms")
    parts.append(f"{'#'*60}")

    vs = result.get("version_scan")
    if vs:
        parts.append(f"\n  [Version Support]")
        parts.append(print_version_table(vs))

    cs = result.get("cipher_scan")
    if cs:
        parts.append(f"\n  [Accepted Cipher Suites - {cs.get('tls_version_tested', '?')}]")
        parts.append(print_cipher_table(cs))
        pref = "Yes (server-side)" if cs.get("server_preference_enforced") else "No (client-side)"
        parts.append(f"  Cipher preference: {pref}")
        parts.append(f"  Forward secrecy: {'Yes' if cs.get('forward_secrecy_support') else 'No'}")
        parts.append(f"  AEAD ciphers: {'Yes' if cs.get('aead_support') else 'No'}")

    dr = result.get("downgrade_report")
    if dr:
        parts.append(print_downgrade_report(dr))

    return "\n".join(parts)

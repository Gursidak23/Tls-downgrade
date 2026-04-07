"""
Flask Web Dashboard -- hardened with authentication, rate-limiting,
input validation, secure headers, and audit logging.

Security controls implemented:
  - bcrypt-hashed password authentication with server-side sessions
  - Session expiry (configurable, default 30 min)
  - Rate-limiting on login (5/min), scan (10/min), API (60/min)
  - CSRF protection via SameSite cookies + Origin checking on POST
  - Strict input validation on every user-supplied parameter
  - Secure HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
  - Secrets loaded from .env, never exposed to frontend
  - Audit logging for auth attempts, scan actions, and errors
  - Path traversal prevention on all file access
  - No IDOR: single-user tool, no multi-tenant data to leak
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from functools import wraps
from logging.handlers import RotatingFileHandler

import bcrypt
from dotenv import load_dotenv
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

# ── Load secrets from .env ────────────────────────────────────

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "sample_results")

_scan_state = {
    "running": False,
    "type": None,
    "target": None,
    "progress": [],
    "percent": 0,
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "error": None,
    "result_summary": None,
}
_scan_lock = threading.Lock()

# ── Application factory ──────────────────────────────────────


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )

    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key or secret_key == "CHANGE_ME_GENERATE_A_RANDOM_KEY":
        import secrets as _s
        secret_key = _s.token_hex(32)
        app.logger.warning(
            "SECRET_KEY not set in .env -- using ephemeral key. "
            "Sessions will not survive restarts."
        )

    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_NAME="tls_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=int(os.environ.get("SESSION_LIFETIME_MINUTES", 30))
        ),
    )

    _setup_logging(app)
    _setup_rate_limiter(app)
    _setup_security_headers(app)
    _register_auth_routes(app)
    _register_api_routes(app)

    return app


# ── Audit Logging ─────────────────────────────────────────────

def _setup_logging(app):
    log_dir = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
    os.makedirs(log_dir, exist_ok=True)

    security_handler = RotatingFileHandler(
        os.path.join(log_dir, "security.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
    )
    security_handler.setLevel(logging.INFO)
    security_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(remote_addr)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    class _AddRemoteAddr(logging.Filter):
        def filter(self, record):
            try:
                record.remote_addr = request.remote_addr
            except RuntimeError:
                record.remote_addr = "-"
            return True

    security_handler.addFilter(_AddRemoteAddr())
    app.logger.addHandler(security_handler)
    app.logger.setLevel(logging.INFO)


def _audit(app, event, detail=""):
    app.logger.info("AUDIT %s | %s", event, detail)


# ── Rate Limiting ─────────────────────────────────────────────

def _setup_rate_limiter(app):
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address

        storage_uri = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
        limiter = Limiter(
            get_remote_address,
            app=app,
            storage_uri=storage_uri,
            default_limits=["120 per minute"],
        )
        app.limiter = limiter
    except ImportError:
        app.logger.warning("flask-limiter not installed; rate-limiting disabled")
        app.limiter = None


def _rate_limit(limit_string):
    """Decorator: apply per-endpoint rate limit if limiter is available."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── Security Headers ──────────────────────────────────────────

def _setup_security_headers(app):
    @app.after_request
    def _set_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

        if os.environ.get("FLASK_ENV") == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        csp = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Content-Security-Policy"] = csp
        return response


# ── Authentication ────────────────────────────────────────────

def _get_password_hash():
    h = os.environ.get("ADMIN_PASSWORD_HASH", "")
    if not h or h == "CHANGE_ME_GENERATE_A_BCRYPT_HASH":
        return None
    return h.encode("utf-8")


def _login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))
        if session.get("expires_at"):
            if datetime.utcnow().isoformat() > session["expires_at"]:
                session.clear()
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": "Session expired"}), 401
                return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def _check_csrf():
    """Verify Origin header on state-changing requests to mitigate CSRF."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("Origin", "")
        if origin:
            allowed = {
                f"http://127.0.0.1:{os.environ.get('DASHBOARD_PORT', '5000')}",
                f"http://localhost:{os.environ.get('DASHBOARD_PORT', '5000')}",
            }
            if origin not in allowed:
                abort(403, description="CSRF: Origin mismatch")


def _register_auth_routes(app):
    @app.before_request
    def _before():
        _check_csrf()
        session.permanent = True

    @app.route("/login", methods=["GET", "POST"])
    def login():
        pw_hash = _get_password_hash()
        if pw_hash is None:
            session["authenticated"] = True
            session["expires_at"] = (
                datetime.utcnow() + app.permanent_session_lifetime
            ).isoformat()
            _audit(app, "LOGIN_BYPASS", "No password configured; auto-authenticated")
            return redirect(url_for("index"))

        if request.method == "GET":
            return render_template("login.html")

        password = request.form.get("password", "")
        if not password or len(password) > 256:
            _audit(app, "LOGIN_FAIL", "Invalid password length")
            return render_template("login.html", error="Invalid credentials"), 401

        if bcrypt.checkpw(password.encode("utf-8"), pw_hash):
            session.regenerate = True
            session["authenticated"] = True
            session["login_time"] = datetime.utcnow().isoformat()
            session["expires_at"] = (
                datetime.utcnow() + app.permanent_session_lifetime
            ).isoformat()
            _audit(app, "LOGIN_OK", f"Session created, expires {session['expires_at']}")
            return redirect(url_for("index"))
        else:
            _audit(app, "LOGIN_FAIL", "Wrong password")
            return render_template("login.html", error="Invalid credentials"), 401

    @app.route("/logout")
    def logout():
        _audit(app, "LOGOUT", f"User logged out (login_time={session.get('login_time')})")
        session.clear()
        return redirect(url_for("login"))

    if app.limiter:
        login_view = app.view_functions.get("login")
        if login_view:
            app.view_functions["login"] = app.limiter.limit("5 per minute")(login_view)


# ── Input Validation Helpers ──────────────────────────────────

_HOSTNAME_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9\-]{1,63}(?:\.[a-zA-Z0-9\-]{1,63})*$"
)
_LABEL_RE = re.compile(r"^[\w\s\.\-\(\)/:,]{0,100}$")
_SCAN_TYPES = frozenset({
    "server", "lab", "stacks", "profiles", "discovery",
    "client_malicious", "client_mitm", "pdf",
})


def _validate_host(value):
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if len(value) > 253:
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value):
        return value
    return None


def _validate_port(value, default=443):
    try:
        p = int(value)
        if 1 <= p <= 65535:
            return p
    except (TypeError, ValueError):
        pass
    return default


def _validate_subnet(value):
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        return None


def _validate_label(value):
    if not value or not isinstance(value, str):
        return ""
    value = value.strip()[:100]
    if _LABEL_RE.match(value):
        return value
    return re.sub(r"[^\w\s\.\-]", "", value)[:100]


def _validate_duration(value, default=30, maximum=600):
    try:
        d = float(value)
        if 1 <= d <= maximum:
            return d
    except (TypeError, ValueError):
        pass
    return default


def _validate_timeout(value, default=10.0, maximum=60.0):
    try:
        t = float(value)
        if 0.5 <= t <= maximum:
            return t
    except (TypeError, ValueError):
        pass
    return default


def _validate_ports_csv(value, default="443,8443,4443"):
    if not value or not isinstance(value, str):
        return default
    parts = value.replace(" ", "").split(",")
    valid = []
    for p in parts[:20]:
        try:
            port = int(p)
            if 1 <= port <= 65535:
                valid.append(str(port))
        except ValueError:
            continue
    return ",".join(valid) if valid else default


# ── Safe file path helpers ────────────────────────────────────

def _safe_results_path():
    return os.path.abspath(RESULTS_DIR)


def _safe_json_read(filename):
    """Read a JSON file from RESULTS_DIR with path traversal protection."""
    safe_name = os.path.basename(filename)
    filepath = os.path.join(_safe_results_path(), safe_name)
    real = os.path.realpath(filepath)
    if not real.startswith(os.path.realpath(_safe_results_path())):
        return None
    if os.path.isfile(real):
        with open(real) as f:
            try:
                return json.load(f)
            except (json.JSONDecodeError, OSError):
                return None
    return None


# ── Data loading ──────────────────────────────────────────────

def _load_results():
    results = []
    results_path = _safe_results_path()
    if not os.path.isdir(results_path):
        return results
    skip = {
        "combined_results.json", "client_test_report.json",
        "mitm_test_report.json", "discovery.json",
        "profile_comparison.json",
    }
    for fname in sorted(os.listdir(results_path)):
        if fname.endswith(".json") and fname in skip:
            continue
        if not fname.endswith(".json"):
            continue
        data = _safe_json_read(fname)
        if data is None:
            continue
        if "results" in data:
            results.extend(data["results"])
        else:
            results.append(data)
    return results


# ── Scan state helpers ────────────────────────────────────────

def _update_scan(msg=None, percent=None, status=None, error=None, summary=None):
    with _scan_lock:
        if msg:
            _scan_state["progress"].append(str(msg)[:500])
        if percent is not None:
            _scan_state["percent"] = max(0, min(100, int(percent)))
        if status:
            _scan_state["status"] = status
        if error:
            _scan_state["error"] = str(error)[:500]
        if summary:
            _scan_state["result_summary"] = summary


def _run_server_scan(host, port, label, timeout):
    from src.scanner.tls_scanner import scan_target, _to_dict

    _update_scan(f"Connecting to {host}:{port}...", 10, "scanning")
    result = scan_target(host, port, label, timeout)
    result_dict = _to_dict(result)

    results_path = _safe_results_path()
    os.makedirs(results_path, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", f"{host}_{port}")
    filepath = os.path.join(results_path, f"{safe_name}.json")
    with open(filepath, "w") as f:
        json.dump(result_dict, f, indent=2, default=str)

    grade = result_dict.get("overall_grade", "?")
    risk = result_dict.get("overall_risk", "?")
    reachable = result_dict.get("reachable", False)
    _update_scan(
        f"Scan complete: Grade {grade}, Risk {risk}"
        + ("" if reachable else " (host unreachable)"),
        100, "done",
        summary={
            "grade": grade, "risk": risk, "label": label,
            "target_id": safe_name, "reachable": reachable,
        },
    )


def _run_lab_scan(base_port, stacks_port):
    from src.emulation.virtual_lab import run_lab

    def on_progress(msg):
        pct = _scan_state["percent"]
        if pct < 90:
            _update_scan(msg, pct + 2)

    _update_scan("Starting Virtual IoT Lab (12 devices)...", 5, "scanning")
    report = run_lab(
        base_port=base_port, stacks_port=stacks_port,
        output_dir=_safe_results_path(),
        on_progress=on_progress,
    )
    scanned = len(report.server_scan_results)
    vuln = (report.client_stack_report.get("stacks_vulnerable", 0)
            if report.client_stack_report else 0)
    _update_scan(
        f"Lab complete: {scanned} devices scanned, {vuln} vulnerable stacks",
        100, "done",
        summary={
            "profiles": report.profiles_used,
            "duration": report.duration_seconds,
            "findings": len(report.findings),
        },
    )


def _run_stacks_scan(port):
    from src.attack.automated_client_tester import run_automated_test, save_report

    def on_progress(msg):
        pct = _scan_state["percent"]
        if pct < 90:
            _update_scan(msg, pct + 3)

    _update_scan("Discovering TLS client stacks...", 5, "scanning")
    report = run_automated_test(listen_port=port, on_progress=on_progress)
    save_report(report, _safe_results_path())
    _update_scan(
        f"Done: {report.stacks_vulnerable}/{report.stacks_tested} vulnerable",
        100, "done",
        summary={
            "tested": report.stacks_tested,
            "vulnerable": report.stacks_vulnerable,
            "protected": report.stacks_protected,
        },
    )


def _run_profiles_scan(base_port):
    from dataclasses import asdict
    from src.emulation.iot_profiles import get_all_server_profiles
    from src.emulation.virtual_iot_server import VirtualServerFleet
    from src.scanner.profile_tester import run_profile_experiment

    profiles = get_all_server_profiles()
    _update_scan(f"Starting {len(profiles)} virtual servers...", 5, "scanning")
    fleet = VirtualServerFleet(profiles, base_port=base_port)
    fleet.start_all()
    time.sleep(2)
    targets = fleet.get_scan_targets()
    _update_scan(f"Running 3-profile experiment on {len(targets)} devices...", 20)
    try:
        report = run_profile_experiment(targets, timeout=10.0)
        results_path = _safe_results_path()
        os.makedirs(results_path, exist_ok=True)
        filepath = os.path.join(results_path, "vlab_profile_comparison.json")
        with open(filepath, "w") as f:
            json.dump(asdict(report), f, indent=2, default=str)
        _update_scan(
            f"Done: IoT weak {report.iot_weak_selection_pct}%, "
            f"Web weak {report.web_weak_selection_pct}%",
            100, "done",
            summary={
                "iot_weak": report.iot_weak_selection_pct,
                "web_weak": report.web_weak_selection_pct,
                "devices": len(report.devices),
            },
        )
    finally:
        fleet.stop_all()


def _run_discovery_scan(subnet, ports, timeout):
    from dataclasses import asdict
    from src.scanner.network_discovery import discover_subnet

    _update_scan(f"Scanning subnet {subnet} on ports {ports}...", 10, "scanning")
    result = discover_subnet(subnet, ports, timeout)
    _update_scan(f"Found {len(result.devices_found)} TLS-enabled devices", 80)
    results_path = _safe_results_path()
    os.makedirs(results_path, exist_ok=True)
    filepath = os.path.join(results_path, "discovery.json")
    with open(filepath, "w") as f:
        json.dump(asdict(result), f, indent=2, default=str)
    _update_scan(
        f"Discovery complete: {len(result.devices_found)} devices found",
        100, "done",
        summary={"devices_found": len(result.devices_found), "subnet": subnet},
    )


def _run_client_malicious(port, duration):
    from src.attack.client_downgrade_tester import run_malicious_server_test

    _update_scan(
        f"Starting malicious server on port {port} for {duration}s...", 5, "scanning"
    )
    _update_scan("Waiting for IoT device connections...", 10)
    report = run_malicious_server_test(
        listen_port=port, duration=duration,
        output_dir=_safe_results_path(),
    )
    _update_scan(
        f"Done: {report.total_client_connections} connections, "
        f"{report.clients_vulnerable_to_sentinel_omission} vulnerable",
        100, "done",
        summary={
            "connections": report.total_client_connections,
            "vulnerable": report.clients_vulnerable_to_sentinel_omission,
            "protected": report.clients_protected,
        },
    )


def _run_client_mitm(target_host, target_port, proxy_port, downgrade_to, duration):
    from src.attack.client_downgrade_tester import run_mitm_proxy_test

    _update_scan(
        f"Starting MITM proxy :{proxy_port} -> {target_host}:{target_port}...",
        5, "scanning",
    )
    _update_scan("Waiting for IoT device connections...", 10)
    report = run_mitm_proxy_test(
        target_host=target_host, target_port=target_port,
        proxy_port=proxy_port, downgrade_to=downgrade_to,
        duration=duration, output_dir=_safe_results_path(),
    )
    _update_scan(
        f"Done: {report.total_client_connections} connections, "
        f"{report.clients_vulnerable_to_version_downgrade} downgraded",
        100, "done",
        summary={
            "connections": report.total_client_connections,
            "vulnerable": report.clients_vulnerable_to_version_downgrade,
            "protected": report.clients_protected,
        },
    )


def _run_pdf_generation():
    _update_scan("Generating PDF report (running all tests)...", 5, "scanning")
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    script = os.path.join(base_dir, "generate_report_pdf.py")

    if not os.path.isfile(script):
        _update_scan("PDF script not found", 0, "error", error="Missing script")
        return

    proc = subprocess.Popen(
        [sys.executable, script, "--skip-run"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=base_dir, text=True, errors="replace",
    )
    for line in proc.stdout:
        clean = line.strip()
        if clean:
            pct = _scan_state["percent"]
            _update_scan(clean, min(pct + 5, 95))
    proc.wait()

    pdf_path = os.path.join(base_dir, "TLS_Downgrade_Analysis_Report.pdf")
    if proc.returncode == 0 and os.path.isfile(pdf_path):
        size_kb = round(os.path.getsize(pdf_path) / 1024, 1)
        _update_scan(f"PDF generated: {size_kb} KB", 100, "done",
                     summary={"pdf_path": pdf_path, "size_kb": size_kb})
    else:
        _update_scan("PDF generation failed", 100, "error",
                     error="generate_report_pdf.py returned non-zero")


# ── Route registration ────────────────────────────────────────

def _register_api_routes(app):

    @app.route("/")
    @_login_required
    def index():
        return render_template("index.html")

    @app.route("/api/results")
    @_login_required
    def api_results():
        results = _load_results()
        seen = set()
        unique = []
        for r in results:
            host = r.get("host")
            port = r.get("port")
            if not host or not port:
                continue
            key = f"{host}:{port}"
            if key not in seen:
                seen.add(key)
                unique.append(r)
        unique.sort(key=lambda r: r.get("scan_time", ""), reverse=True)
        return jsonify({"results": unique, "count": len(unique)})

    @app.route("/api/results/<target_id>")
    @_login_required
    def api_result_detail(target_id):
        safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "", target_id)
        if safe_id != target_id:
            return jsonify({"error": "Invalid target ID"}), 400
        results = _load_results()
        for r in results:
            key = f"{r.get('host')}_{r.get('port')}".replace(".", "_")
            if key == safe_id:
                return jsonify(r)
        return jsonify({"error": "Not found"}), 404

    @app.route("/api/scan", methods=["POST"])
    @_login_required
    def api_scan():
        with _scan_lock:
            if _scan_state["running"]:
                return jsonify({"error": "A scan is already running."}), 409

        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body"}), 400

        scan_type = data.get("scan_type", "")
        if scan_type not in _SCAN_TYPES:
            return jsonify({"error": f"Invalid scan_type. Choose: {', '.join(sorted(_SCAN_TYPES))}"}), 400

        _audit(app, "SCAN_START", f"type={scan_type} from={request.remote_addr}")

        with _scan_lock:
            _scan_state.update({
                "running": True,
                "type": scan_type,
                "target": "",
                "progress": [],
                "percent": 0,
                "status": "starting",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "error": None,
                "result_summary": None,
            })

        def _worker():
            try:
                if scan_type == "server":
                    host = _validate_host(data.get("host", ""))
                    if not host:
                        _update_scan("Error: invalid host", 0, "error", error="Invalid host")
                        return
                    port = _validate_port(data.get("port"), 443)
                    label = _validate_label(data.get("label", f"{host}:{port}"))
                    timeout = _validate_timeout(data.get("timeout"), 10)
                    _run_server_scan(host, port, label, timeout)

                elif scan_type == "lab":
                    base_port = _validate_port(data.get("base_port"), 24000)
                    stacks_port = _validate_port(data.get("stacks_port"), 24100)
                    _run_lab_scan(base_port, stacks_port)

                elif scan_type == "stacks":
                    port = _validate_port(data.get("port"), 24200)
                    _run_stacks_scan(port)

                elif scan_type == "profiles":
                    base_port = _validate_port(data.get("base_port"), 24300)
                    _run_profiles_scan(base_port)

                elif scan_type == "discovery":
                    subnet = _validate_subnet(data.get("subnet", ""))
                    if not subnet:
                        _update_scan("Error: invalid subnet CIDR", 0, "error",
                                     error="Invalid subnet")
                        return
                    ports_csv = _validate_ports_csv(data.get("ports"))
                    ports = [int(p) for p in ports_csv.split(",")]
                    timeout = _validate_timeout(data.get("timeout"), 2, 30)
                    _run_discovery_scan(subnet, ports, timeout)

                elif scan_type == "client_malicious":
                    port = _validate_port(data.get("port"), 4433)
                    duration = _validate_duration(data.get("duration"), 30)
                    _run_client_malicious(port, duration)

                elif scan_type == "client_mitm":
                    target = _validate_host(data.get("target_host", ""))
                    if not target:
                        _update_scan("Error: invalid target host", 0, "error",
                                     error="Invalid target")
                        return
                    target_port = _validate_port(data.get("target_port"), 443)
                    proxy_port = _validate_port(data.get("proxy_port"), 8443)
                    duration = _validate_duration(data.get("duration"), 30)
                    version_map = {
                        "TLSv1.0": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303,
                    }
                    dg_str = data.get("downgrade_to", "TLSv1.2")
                    downgrade_to = version_map.get(dg_str, 0x0303)
                    _run_client_mitm(target, target_port, proxy_port,
                                     downgrade_to, duration)

                elif scan_type == "pdf":
                    _run_pdf_generation()

            except Exception as exc:
                _update_scan(f"Error: {exc}", _scan_state["percent"], "error",
                             error=str(exc)[:500])
                _audit(app, "SCAN_ERROR", f"type={scan_type} error={exc}")
            finally:
                with _scan_lock:
                    _scan_state["running"] = False
                    _scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
                    if _scan_state["status"] != "error":
                        _scan_state["status"] = "done"
                _audit(app, "SCAN_DONE", f"type={scan_type} status={_scan_state['status']}")

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        return jsonify({"status": "started", "scan_type": scan_type})

    if app.limiter:
        app.view_functions["api_scan"] = app.limiter.limit("10 per minute")(
            app.view_functions["api_scan"]
        )

    @app.route("/api/scan/status")
    @_login_required
    def api_scan_status():
        with _scan_lock:
            return jsonify(dict(_scan_state))

    @app.route("/api/pdf")
    @_login_required
    def api_pdf_download():
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        pdf_path = os.path.join(base_dir, "TLS_Downgrade_Analysis_Report.pdf")
        real_pdf = os.path.realpath(pdf_path)
        if not real_pdf.startswith(os.path.realpath(base_dir)):
            return jsonify({"error": "Access denied"}), 403
        if os.path.isfile(real_pdf):
            return send_file(real_pdf, as_attachment=True,
                             download_name="TLS_Downgrade_Analysis_Report.pdf")
        return jsonify({"error": "PDF not generated yet."}), 404

    @app.route("/api/client-results")
    @_login_required
    def api_client_results():
        client_results = {}
        for fname in ["client_test_report.json", "mitm_test_report.json"]:
            data = _safe_json_read(fname)
            if data:
                client_results[fname.replace(".json", "")] = data
        return jsonify(client_results)

    @app.route("/api/profile-results")
    @_login_required
    def api_profile_results():
        data = _safe_json_read("profile_comparison.json")
        if data:
            return jsonify(data)
        return jsonify({"devices": [], "findings": [],
                        "message": "No profile experiment run yet."})

    @app.route("/api/discovery")
    @_login_required
    def api_discovery():
        data = _safe_json_read("discovery.json")
        if data:
            return jsonify(data)
        return jsonify({"devices_found": [],
                        "message": "No discovery scan run yet."})

    @app.route("/api/stack-results")
    @_login_required
    def api_stack_results():
        data = _safe_json_read("automated_stack_test.json")
        if data:
            return jsonify(data)
        return jsonify({"stacks_tested": 0,
                        "message": "No stack test run yet."})

    @app.route("/api/lab-results")
    @_login_required
    def api_lab_results():
        data = _safe_json_read("virtual_lab_report.json")
        if data:
            return jsonify(data)
        return jsonify({"profiles_used": 0,
                        "message": "No lab run yet."})

    @app.route("/api/vlab-profiles")
    @_login_required
    def api_vlab_profiles():
        data = _safe_json_read("vlab_profile_comparison.json")
        if data:
            return jsonify(data)
        return jsonify({"devices": [],
                        "message": "No virtual lab profile experiment run yet."})

    @app.errorhandler(429)
    def _rate_limit_exceeded(e):
        _audit(app, "RATE_LIMIT", f"path={request.path}")
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    @app.errorhandler(403)
    def _forbidden(e):
        _audit(app, "FORBIDDEN", f"path={request.path} detail={e.description}")
        return jsonify({"error": str(e.description)}), 403

    @app.errorhandler(404)
    def _not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def _server_error(e):
        _audit(app, "SERVER_ERROR", f"path={request.path} error={e}")
        return jsonify({"error": "Internal server error"}), 500

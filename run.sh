#!/usr/bin/env bash
# ============================================================
#  TLS Downgrade & Cipher Suite Analyzer -- Run Script
#  Usage:
#    ./run.sh              # Full virtual lab (default)
#    ./run.sh lab          # Full virtual lab
#    ./run.sh stacks       # Client stack testing only
#    ./run.sh server       # Scan a real server (prompts for target)
#    ./run.sh profiles     # Cipher preference experiment only
#    ./run.sh demo         # Run the full demonstration
#    ./run.sh dashboard    # Launch the web dashboard
#    ./run.sh all          # Run everything then launch dashboard
#    ./run.sh install      # Install dependencies only
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${PYTHON:-python}"
PIP="${PIP:-pip}"
OUTPUT_DIR="sample_results"
BASE_PORT=17000
STACKS_PORT=17100

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}  TLS Downgrade & Cipher Suite Analyzer${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""
}

info()    { echo -e "  ${CYAN}[*]${NC} $1"; }
success() { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "  ${RED}[-]${NC} $1"; }

check_python() {
    if ! command -v "$PYTHON" &>/dev/null; then
        fail "Python not found. Set PYTHON env var or install Python 3.9+."
        exit 1
    fi
    PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    info "Python $PY_VERSION ($("$PYTHON" --version 2>&1))"
}

install_deps() {
    info "Installing dependencies from requirements.txt..."
    "$PIP" install -r requirements.txt
    success "Dependencies installed."
}

check_deps() {
    MISSING=0
    for pkg in flask cryptography click yaml colorama tabulate jinja2; do
        if ! "$PYTHON" -c "import $pkg" 2>/dev/null; then
            warn "Missing: $pkg"
            MISSING=1
        fi
    done
    if [ "$MISSING" -eq 1 ]; then
        warn "Some dependencies missing. Installing..."
        install_deps
    else
        success "All dependencies satisfied."
    fi
}

run_lab() {
    echo ""
    echo -e "${BOLD}  Running Virtual IoT Lab (no hardware required)${NC}"
    echo -e "  This spawns 12 virtual IoT/web servers and runs the full"
    echo -e "  scan pipeline: version probe, cipher scan, downgrade"
    echo -e "  detection, cipher preference, and client stack testing."
    echo ""
    "$PYTHON" scan.py lab \
        --base-port "$BASE_PORT" \
        --stacks-port "$STACKS_PORT" \
        --output "$OUTPUT_DIR"
}

run_lab_server_only() {
    info "Running lab -- server scans only..."
    "$PYTHON" scan.py lab --server-only --base-port "$BASE_PORT" --output "$OUTPUT_DIR"
}

run_lab_profiles_only() {
    info "Running lab -- cipher preference experiment only..."
    "$PYTHON" scan.py lab --profiles-only --base-port "$BASE_PORT" --output "$OUTPUT_DIR"
}

run_lab_client_only() {
    info "Running lab -- client stack testing only..."
    "$PYTHON" scan.py lab --client-only --stacks-port "$STACKS_PORT" --output "$OUTPUT_DIR"
}

run_stacks() {
    echo ""
    echo -e "${BOLD}  Running Automated Client Stack Testing (Paper 1)${NC}"
    echo -e "  Tests every available TLS client library for downgrade"
    echo -e "  sentinel validation (RFC 8446 S4.1.3)."
    echo ""
    "$PYTHON" scan.py stacks --port "$STACKS_PORT" --output "$OUTPUT_DIR"
}

run_server_scan() {
    local TARGET="${1:-}"
    if [ -z "$TARGET" ]; then
        echo ""
        echo -e "  ${BOLD}Server TLS Scan${NC}"
        echo -e "  Enter target in host:port format (e.g. www.google.com:443)"
        read -rp "  Target: " TARGET
    fi
    if [ -z "$TARGET" ]; then
        fail "No target specified."
        return 1
    fi
    echo ""
    info "Scanning $TARGET..."
    "$PYTHON" scan.py server --target "$TARGET" --output "$OUTPUT_DIR"
}

run_profiles() {
    echo ""
    echo -e "${BOLD}  Running Three-Profile Cipher Selection Experiment${NC}"
    echo ""
    "$PYTHON" scan.py lab --profiles-only --base-port "$BASE_PORT" --output "$OUTPUT_DIR"
}

run_demo() {
    echo ""
    echo -e "${BOLD}  Running Full Demonstration (all phases)${NC}"
    echo -e "  Phase 0: Three-profile cipher experiment"
    echo -e "  Phase 1: Simulated IoT server scans"
    echo -e "  Phase 2: Client-side downgrade testing"
    echo -e "  Phase 3: MITM proxy test"
    echo -e "  Phase 4: Automated client stack testing"
    echo ""
    "$PYTHON" run_demo.py
}

run_dashboard() {
    echo ""
    echo -e "${BOLD}  Launching Web Dashboard${NC}"
    echo -e "  Open ${CYAN}http://127.0.0.1:5000${NC} in your browser"
    echo ""
    "$PYTHON" dashboard.py
}

run_all() {
    info "Running full lab..."
    run_lab
    echo ""
    success "All tests complete. Launching dashboard..."
    run_dashboard
}

usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  lab              Run the full virtual IoT lab (default)"
    echo "  lab-server       Lab: server scans only"
    echo "  lab-profiles     Lab: cipher preference experiment only"
    echo "  lab-clients      Lab: client stack testing only"
    echo "  stacks           Standalone client stack sentinel testing"
    echo "  server [target]  Scan a real TLS server (e.g. server 192.168.1.100:443)"
    echo "  profiles         Three-profile cipher selection experiment"
    echo "  demo             Run the full demonstration (run_demo.py)"
    echo "  dashboard        Launch the Flask web dashboard"
    echo "  all              Run full lab then launch dashboard"
    echo "  install          Install Python dependencies"
    echo "  help             Show this message"
    echo ""
    echo "Examples:"
    echo "  ./run.sh                           # Full virtual lab"
    echo "  ./run.sh stacks                    # Test client stacks"
    echo "  ./run.sh server www.google.com:443 # Scan Google"
    echo "  ./run.sh all                       # Everything + dashboard"
}

banner
check_python
check_deps

COMMAND="${1:-lab}"
shift 2>/dev/null || true

case "$COMMAND" in
    lab)            run_lab ;;
    lab-server)     run_lab_server_only ;;
    lab-profiles)   run_lab_profiles_only ;;
    lab-clients)    run_lab_client_only ;;
    stacks)         run_stacks ;;
    server)         run_server_scan "$@" ;;
    profiles)       run_profiles ;;
    demo)           run_demo ;;
    dashboard)      run_dashboard ;;
    all)            run_all ;;
    install)        install_deps ;;
    help|--help|-h) usage ;;
    *)
        fail "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac

echo ""
success "Done. Results in: $(cd "$OUTPUT_DIR" 2>/dev/null && pwd || echo "$OUTPUT_DIR")/"
echo ""

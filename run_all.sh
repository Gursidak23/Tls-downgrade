#!/usr/bin/env bash
# ============================================================
#  TLS Downgrade & Cipher Suite Analyzer -- Run All Tests
#  Executes every component in sequence, reports pass/fail.
#  Usage: ./run_all.sh
# ============================================================

set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${PYTHON:-python}"
OUTPUT_DIR="sample_results"
PASSED=0
FAILED=0
TOTAL_START=$(date +%s)

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
GRAY='\033[0;90m'
NC='\033[0m'

declare -a TEST_NAMES
declare -a TEST_STATUS
declare -a TEST_TIMES

header()  { echo -e "\n${BOLD}============================================================${NC}\n  ${BOLD}$1${NC}\n${BOLD}============================================================${NC}\n"; }
info()    { echo -e "  ${CYAN}[....]${NC} $1"; }
pass()    { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail()    { echo -e "  ${RED}[FAIL]${NC} $1"; }

run_test() {
    local name="$1"
    shift
    info "$name"
    local t0=$(date +%s)
    "$@" > /dev/null 2>&1
    local code=$?
    local elapsed=$(( $(date +%s) - t0 ))

    TEST_NAMES+=("$name")
    TEST_TIMES+=("${elapsed}s")

    if [ $code -eq 0 ]; then
        pass "$name  (${elapsed}s)"
        TEST_STATUS+=("PASS")
        ((PASSED++))
    else
        fail "$name  (exit code $code)"
        TEST_STATUS+=("FAIL")
        ((FAILED++))
    fi
}

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  TLS Downgrade & Cipher Suite Analyzer${NC}"
echo -e "${BOLD}  Complete Test Suite${NC}"
echo -e "${BOLD}============================================================${NC}"

header "Step 0: Check Dependencies"
if "$PYTHON" -c "import flask, cryptography, click, yaml, colorama, tabulate, jinja2" 2>/dev/null; then
    pass "All Python dependencies installed"
else
    info "Installing dependencies..."
    "$PYTHON" -m pip install -r requirements.txt
fi

header "Test 1/5: Virtual IoT Lab (12 devices, 3 phases)"
run_test "Virtual IoT Lab" "$PYTHON" scan.py lab --base-port 22000 --stacks-port 22100 --output "$OUTPUT_DIR"

header "Test 2/5: Standalone Client Stack Testing"
run_test "Client Stack Testing" "$PYTHON" scan.py stacks --port 22200 --output "$OUTPUT_DIR"

header "Test 3/5: Server Scan (www.google.com)"
run_test "Server Scan (Google)" "$PYTHON" scan.py server --target www.google.com:443 --output "$OUTPUT_DIR"

header "Test 4/5: Full Demo (run_demo.py)"
run_test "Full Demo" "$PYTHON" run_demo.py

header "Test 5/5: Dashboard API Endpoints"
DASH_RESULT=$("$PYTHON" -c "
from datetime import datetime, timedelta
from src.dashboard.app import create_app
app = create_app()
c = app.test_client()
with c.session_transaction() as s:
    s['authenticated'] = True
    s['expires_at'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
eps = ['/', '/api/results', '/api/client-results', '/api/profile-results',
       '/api/discovery', '/api/stack-results', '/api/lab-results', '/api/vlab-profiles']
ok = sum(1 for e in eps if c.get(e).status_code == 200)
print(f'{ok}/{len(eps)}')
" 2>/dev/null)

TEST_NAMES+=("Dashboard API")
TEST_TIMES+=("-")
if [ "$DASH_RESULT" = "8/8" ]; then
    pass "Dashboard API (8/8 endpoints return 200)"
    TEST_STATUS+=("PASS")
    ((PASSED++))
else
    fail "Dashboard API ($DASH_RESULT endpoints OK)"
    TEST_STATUS+=("FAIL")
    ((FAILED++))
fi

TOTAL_TIME=$(( $(date +%s) - TOTAL_START ))

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  TEST RESULTS${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

for i in "${!TEST_NAMES[@]}"; do
    if [ "${TEST_STATUS[$i]}" = "PASS" ]; then
        printf "  ${GREEN}[PASS]${NC} %-30s %8s\n" "${TEST_NAMES[$i]}" "${TEST_TIMES[$i]}"
    else
        printf "  ${RED}[FAIL]${NC} %-30s %8s\n" "${TEST_NAMES[$i]}" "${TEST_TIMES[$i]}"
    fi
done

TOTAL=$((PASSED + FAILED))
echo ""
echo -e "  ${GRAY}--------------------------------------------------${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "  ${GREEN}Total: $TOTAL tests, $PASSED passed, $FAILED failed${NC}"
    echo -e "  ${GRAY}Duration: ${TOTAL_TIME}s${NC}"
    echo ""
    echo -e "  ${GREEN}ALL TESTS PASSED${NC}"
else
    echo -e "  ${RED}Total: $TOTAL tests, $PASSED passed, $FAILED failed${NC}"
    echo -e "  ${GRAY}Duration: ${TOTAL_TIME}s${NC}"
    echo ""
    echo -e "  ${RED}SOME TESTS FAILED${NC}"
fi

echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "  ${CYAN}  View results:    ./run.sh dashboard${NC}"
echo -e "  ${CYAN}  Re-run lab:      ./run.sh lab${NC}"
echo -e "  ${CYAN}  Scan a device:   ./run.sh server <host>:<port>${NC}"
echo ""

exit $FAILED

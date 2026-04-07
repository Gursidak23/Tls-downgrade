# ============================================================
#  TLS Downgrade & Cipher Suite Analyzer -- Run All Tests
#  Executes every component in sequence, reports pass/fail.
#  Usage: .\run_all.ps1
# ============================================================

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$OutputDir = "sample_results"
$Passed = 0
$Failed = 0
$Results = @()
$StartTime = Get-Date

function Write-Header($msg) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor White
    Write-Host "  $msg" -ForegroundColor White
    Write-Host ("=" * 60) -ForegroundColor White
    Write-Host ""
}

function Write-Ok($msg)   { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Info($msg)  { Write-Host "  [....] $msg" -ForegroundColor Cyan }

function Run-Test {
    param([string]$Name, [string]$Command)

    Write-Info "$Name"
    $t0 = Get-Date
    $output = Invoke-Expression $Command 2>&1 | Out-String
    $code = $LASTEXITCODE
    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)

    if ($code -eq 0) {
        Write-Ok "$Name  (${elapsed}s)"
        $script:Passed++
        $status = "PASS"
    } else {
        Write-Fail "$Name  (exit code $code)"
        $script:Failed++
        $status = "FAIL"
    }
    $script:Results += [PSCustomObject]@{
        Test     = $Name
        Status   = $status
        Time     = "${elapsed}s"
        ExitCode = $code
    }
    return $output
}

# ── Banner ───────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor White
Write-Host "  TLS Downgrade & Cipher Suite Analyzer" -ForegroundColor White
Write-Host "  Complete Test Suite" -ForegroundColor White
Write-Host ("=" * 60) -ForegroundColor White

# ── Check dependencies ───────────────────────────────────────
Write-Header "Step 0: Check Dependencies"
$depCheck = & $Python -c "import flask, cryptography, click, yaml, colorama, tabulate, jinja2; print('OK')" 2>&1
if ($depCheck -match "OK") {
    Write-Ok "All Python dependencies installed"
} else {
    Write-Info "Installing dependencies..."
    & pip install -r requirements.txt
}

# ── Test 1: Full Virtual IoT Lab ─────────────────────────────
Write-Header "Test 1/5: Virtual IoT Lab (12 devices, 3 phases)"
$labOut = Run-Test "Virtual IoT Lab" "$Python scan.py lab --base-port 22000 --stacks-port 22100 --output $OutputDir"

# ── Test 2: Standalone Client Stack Testing ───────────────────
Write-Header "Test 2/5: Standalone Client Stack Testing"
$stacksOut = Run-Test "Client Stack Testing" "$Python scan.py stacks --port 22200 --output $OutputDir"

# ── Test 3: Server Scan (real target) ─────────────────────────
Write-Header "Test 3/5: Server Scan (www.google.com)"
$serverOut = Run-Test "Server Scan (Google)" "$Python scan.py server --target www.google.com:443 --output $OutputDir"

# ── Test 4: Full Demo ─────────────────────────────────────────
Write-Header "Test 4/5: Full Demo (run_demo.py)"
$demoOut = Run-Test "Full Demo" "$Python run_demo.py"

# ── Test 5: Dashboard API ─────────────────────────────────────
Write-Header "Test 5/5: Dashboard API Endpoints"
$dashOut = & $Python -c @"
from src.dashboard.app import create_app
c = create_app().test_client()
eps = ['/', '/api/results', '/api/client-results', '/api/profile-results',
       '/api/discovery', '/api/stack-results', '/api/lab-results', '/api/vlab-profiles']
ok = 0
for e in eps:
    code = c.get(e).status_code
    ok += 1 if code == 200 else 0
print(f'{ok}/{len(eps)}')
"@ 2>&1 | Out-String

if ($dashOut.Trim() -eq "8/8") {
    Write-Ok "Dashboard API (8/8 endpoints return 200)"
    $Passed++
    $Results += [PSCustomObject]@{ Test = "Dashboard API"; Status = "PASS"; Time = "-"; ExitCode = 0 }
} else {
    Write-Fail "Dashboard API ($($dashOut.Trim()) endpoints OK)"
    $Failed++
    $Results += [PSCustomObject]@{ Test = "Dashboard API"; Status = "FAIL"; Time = "-"; ExitCode = 1 }
}

# ── Summary ──────────────────────────────────────────────────
$TotalTime = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor White
Write-Host "  TEST RESULTS" -ForegroundColor White
Write-Host ("=" * 60) -ForegroundColor White
Write-Host ""

$Results | ForEach-Object {
    $color = if ($_.Status -eq "PASS") { "Green" } else { "Red" }
    $icon  = if ($_.Status -eq "PASS") { "[PASS]" } else { "[FAIL]" }
    Write-Host ("  {0,-6} {1,-30} {2,8}" -f $icon, $_.Test, $_.Time) -ForegroundColor $color
}

Write-Host ""
Write-Host ("  " + "-" * 50) -ForegroundColor Gray

$totalColor = if ($Failed -eq 0) { "Green" } else { "Red" }
Write-Host ""
Write-Host "  Total: $($Passed + $Failed) tests, $Passed passed, $Failed failed" -ForegroundColor $totalColor
Write-Host "  Duration: ${TotalTime}s" -ForegroundColor Gray
Write-Host "  Results: $(Resolve-Path $OutputDir)" -ForegroundColor Gray

if ($Failed -eq 0) {
    Write-Host ""
    Write-Host "  ALL TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  SOME TESTS FAILED" -ForegroundColor Red
}

Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    View results:    .\run.ps1 dashboard" -ForegroundColor Cyan
Write-Host "    Re-run lab:      .\run.ps1 lab" -ForegroundColor Cyan
Write-Host "    Scan a device:   .\run.ps1 server <host>:<port>" -ForegroundColor Cyan
Write-Host ""

exit $Failed

# ============================================================
#  TLS Downgrade & Cipher Suite Analyzer -- PowerShell Script
#  Usage:
#    .\run.ps1              # Full virtual lab (default)
#    .\run.ps1 lab          # Full virtual lab
#    .\run.ps1 stacks       # Client stack testing only
#    .\run.ps1 server       # Scan a real server (prompts for target)
#    .\run.ps1 profiles     # Cipher preference experiment only
#    .\run.ps1 demo         # Run the full demonstration
#    .\run.ps1 dashboard    # Launch the web dashboard
#    .\run.ps1 all          # Run everything then launch dashboard
#    .\run.ps1 install      # Install dependencies only
# ============================================================

param(
    [Parameter(Position=0)]
    [string]$Command = "lab",

    [Parameter(Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$Pip = if ($env:PIP) { $env:PIP } else { "pip" }
$OutputDir = "sample_results"
$BasePort = 17000
$StacksPort = 17100

function Write-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor White
    Write-Host "  TLS Downgrade & Cipher Suite Analyzer" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host ""
}

function Write-Info($msg)    { Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)    { Write-Host "  [-] $msg" -ForegroundColor Red }

function Test-Python {
    try {
        $ver = & $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        Write-Info "Python $ver"
    } catch {
        Write-Fail "Python not found. Install Python 3.9+ or set `$env:PYTHON."
        exit 1
    }
}

function Install-Deps {
    Write-Info "Installing dependencies from requirements.txt..."
    & $Pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Fail "pip install failed."; exit 1 }
    Write-Ok "Dependencies installed."
}

function Test-Deps {
    $missing = $false
    foreach ($pkg in @("flask", "cryptography", "click", "yaml", "colorama", "tabulate", "jinja2")) {
        $result = & $Python -c "import $pkg" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Missing: $pkg"
            $missing = $true
        }
    }
    if ($missing) {
        Write-Warn "Some dependencies missing. Installing..."
        Install-Deps
    } else {
        Write-Ok "All dependencies satisfied."
    }
}

function Invoke-Lab {
    Write-Host ""
    Write-Host "  Running Virtual IoT Lab (no hardware required)" -ForegroundColor White
    Write-Host "  Spawns 12 virtual IoT/web servers and runs the full"
    Write-Host "  scan pipeline: version probe, cipher scan, downgrade"
    Write-Host "  detection, cipher preference, and client stack testing."
    Write-Host ""
    & $Python scan.py lab --base-port $BasePort --stacks-port $StacksPort --output $OutputDir
    if ($LASTEXITCODE -ne 0) { Write-Fail "Lab run failed."; exit 1 }
}

function Invoke-LabServerOnly {
    Write-Info "Running lab -- server scans only..."
    & $Python scan.py lab --server-only --base-port $BasePort --output $OutputDir
}

function Invoke-LabProfilesOnly {
    Write-Info "Running lab -- cipher preference experiment only..."
    & $Python scan.py lab --profiles-only --base-port $BasePort --output $OutputDir
}

function Invoke-LabClientOnly {
    Write-Info "Running lab -- client stack testing only..."
    & $Python scan.py lab --client-only --stacks-port $StacksPort --output $OutputDir
}

function Invoke-Stacks {
    Write-Host ""
    Write-Host "  Running Automated Client Stack Testing (Paper 1)" -ForegroundColor White
    Write-Host "  Tests every available TLS client library for downgrade"
    Write-Host "  sentinel validation (RFC 8446 S4.1.3)."
    Write-Host ""
    & $Python scan.py stacks --port $StacksPort --output $OutputDir
    if ($LASTEXITCODE -ne 0) { Write-Fail "Stacks test failed."; exit 1 }
}

function Invoke-ServerScan {
    $target = if ($ExtraArgs.Count -gt 0) { $ExtraArgs[0] } else { $null }
    if (-not $target) {
        Write-Host ""
        Write-Host "  Server TLS Scan" -ForegroundColor White
        $target = Read-Host "  Enter target (host:port, e.g. www.google.com:443)"
    }
    if (-not $target) { Write-Fail "No target specified."; return }
    Write-Host ""
    Write-Info "Scanning $target..."
    & $Python scan.py server --target $target --output $OutputDir
}

function Invoke-Profiles {
    Write-Host ""
    Write-Host "  Running Three-Profile Cipher Selection Experiment" -ForegroundColor White
    Write-Host ""
    & $Python scan.py lab --profiles-only --base-port $BasePort --output $OutputDir
}

function Invoke-Demo {
    Write-Host ""
    Write-Host "  Running Full Demonstration (all phases)" -ForegroundColor White
    Write-Host "  Phase 0: Three-profile cipher experiment"
    Write-Host "  Phase 1: Simulated IoT server scans"
    Write-Host "  Phase 2: Client-side downgrade testing"
    Write-Host "  Phase 3: MITM proxy test"
    Write-Host "  Phase 4: Automated client stack testing"
    Write-Host ""
    & $Python run_demo.py
    if ($LASTEXITCODE -ne 0) { Write-Fail "Demo failed."; exit 1 }
}

function Invoke-Dashboard {
    Write-Host ""
    Write-Host "  Launching Web Dashboard" -ForegroundColor White
    Write-Host "  Open http://127.0.0.1:5000 in your browser" -ForegroundColor Cyan
    Write-Host ""
    & $Python dashboard.py
}

function Invoke-All {
    Write-Info "Running full lab..."
    Invoke-Lab
    Write-Host ""
    Write-Ok "All tests complete. Launching dashboard..."
    Invoke-Dashboard
}

function Show-Usage {
    Write-Host "Usage: .\run.ps1 [command] [options]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  lab              Run the full virtual IoT lab (default)"
    Write-Host "  lab-server       Lab: server scans only"
    Write-Host "  lab-profiles     Lab: cipher preference experiment only"
    Write-Host "  lab-clients      Lab: client stack testing only"
    Write-Host "  stacks           Standalone client stack sentinel testing"
    Write-Host "  server [target]  Scan a real TLS server (e.g. server www.google.com:443)"
    Write-Host "  profiles         Three-profile cipher selection experiment"
    Write-Host "  demo             Run the full demonstration (run_demo.py)"
    Write-Host "  dashboard        Launch the Flask web dashboard"
    Write-Host "  all              Run full lab then launch dashboard"
    Write-Host "  install          Install Python dependencies"
    Write-Host "  help             Show this message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run.ps1                           # Full virtual lab"
    Write-Host "  .\run.ps1 stacks                    # Test client stacks"
    Write-Host "  .\run.ps1 server www.google.com:443 # Scan Google"
    Write-Host "  .\run.ps1 all                       # Everything + dashboard"
}

Write-Banner
Test-Python
Test-Deps

switch ($Command.ToLower()) {
    "lab"          { Invoke-Lab }
    "lab-server"   { Invoke-LabServerOnly }
    "lab-profiles" { Invoke-LabProfilesOnly }
    "lab-clients"  { Invoke-LabClientOnly }
    "stacks"       { Invoke-Stacks }
    "server"       { Invoke-ServerScan }
    "profiles"     { Invoke-Profiles }
    "demo"         { Invoke-Demo }
    "dashboard"    { Invoke-Dashboard }
    "all"          { Invoke-All }
    "install"      { Install-Deps }
    "help"         { Show-Usage }
    "--help"       { Show-Usage }
    "-h"           { Show-Usage }
    default {
        Write-Fail "Unknown command: $Command"
        Show-Usage
        exit 1
    }
}

Write-Host ""
Write-Ok "Done. Results in: $(Resolve-Path $OutputDir -ErrorAction SilentlyContinue)"
Write-Host ""

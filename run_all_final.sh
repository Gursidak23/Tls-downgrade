#!/usr/bin/env bash
# Run the full TLS test suite using the project virtual environment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

resolve_python() {
    if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
        echo "$SCRIPT_DIR/.venv/bin/python"
        return 0
    fi

    if [ -x "$SCRIPT_DIR/../.venv/bin/python" ]; then
        echo "$SCRIPT_DIR/../.venv/bin/python"
        return 0
    fi

    if command -v python3 >/dev/null 2>&1; then
        command -v python3
        return 0
    fi

    echo "ERROR: Python not found. Create a venv at ../.venv or set PYTHON." >&2
    exit 1
}

PYTHON="${PYTHON:-$(resolve_python)}"
export PYTHON
export PATH="$(dirname "$PYTHON"):$PATH"

echo "[*] Using Python: $PYTHON"
echo "[*] Running full test suite..."

exec bash "$SCRIPT_DIR/run_all.sh"

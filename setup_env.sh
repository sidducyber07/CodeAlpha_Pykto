#!/usr/bin/env bash
# Creates the Pykto virtual environment at Snifx/venv and installs requirements.txt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/Snifx/venv"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
PYTHON_BIN="${PYTHON_BIN:-python3}"
RECREATE=false

usage() {
    cat <<EOF
Usage: $(basename "$0") [--recreate] [--help]

Creates the Python virtual environment at Snifx/venv and installs dependencies
from requirements.txt.

Options:
  --recreate    Remove an existing Snifx/venv before creating a fresh one
  --help        Show this help message and exit
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --recreate)
            RECREATE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "[!] '$PYTHON_BIN' was not found. Please install Python 3.10+ first." >&2
    exit 1
fi

if [[ ! -f "$REQ_FILE" ]]; then
    echo "[!] Requirements file not found at: $REQ_FILE" >&2
    exit 1
fi

echo "[*] Checking Python version..."
if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    PY_VER="$("$PYTHON_BIN" -V 2>&1)"
    echo "[!] Python 3.10+ is required, found: $PY_VER" >&2
    exit 1
fi
echo "    Found $("$PYTHON_BIN" -V 2>&1)"

if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    echo "[!] Python 'venv' module is missing. On Ubuntu/Debian, install it with:" >&2
    echo "    sudo apt update && sudo apt install -y python3-venv" >&2
    exit 1
fi

if ! "$PYTHON_BIN" -c "import tkinter" >/dev/null 2>&1; then
    echo "[!] Warning: 'tkinter' is not installed for $PYTHON_BIN." >&2
    echo "    The GUI (Snifx/app.py) requires Tkinter. On Ubuntu/Debian, install it with:" >&2
    echo "    sudo apt update && sudo apt install -y python3-tk" >&2
fi

if [[ "$RECREATE" == true && -d "$VENV_DIR" ]]; then
    echo "[*] Removing existing virtual environment at $VENV_DIR..."
    rm -rf "$VENV_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
    echo "[*] Creating virtual environment at $VENV_DIR..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
else
    echo "[*] Using existing virtual environment at $VENV_DIR..."
fi

VENV_PYTHON="$VENV_DIR/bin/python"

echo "[*] Upgrading pip..."
"$VENV_PYTHON" -m pip install --upgrade pip

echo "[*] Installing packages from $REQ_FILE..."
"$VENV_PYTHON" -m pip install -r "$REQ_FILE"

echo "[*] Verifying installed environment..."
"$VENV_PYTHON" -c "import scapy; print(f'    scapy {scapy.__version__} ready')"
if "$VENV_PYTHON" -c "import tkinter" >/dev/null 2>&1; then
    echo "    tkinter ready"
fi

cat <<EOF

[+] Environment setup complete!

Activate the environment:
  source Snifx/venv/bin/activate

Run tests:
  ./Snifx/venv/bin/python Snifx/test_snifx.py

Launch Pykto GUI (requires raw socket privileges on Linux):
  sudo -E ./Snifx/venv/bin/python Snifx/app.py
EOF

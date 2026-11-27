#!/usr/bin/env python3
"""
Automatic virtual environment and dependency bootstrapper for Pykto.

Ensures `Snifx/venv` exists, installs missing or updated packages from
`requirements.txt`, and re-execs the running application inside `Snifx/venv`
when launched with a different Python interpreter.
"""

import hashlib
import importlib.metadata
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Optional

SNIFX_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SNIFX_DIR.parent
VENV_DIR = SNIFX_DIR / "venv"
REQ_FILE = PROJECT_ROOT / "requirements.txt"
MARKER_FILE = VENV_DIR / ".requirements.sha256"

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)")


def get_venv_python(venv_dir: Path = VENV_DIR) -> Path:
    """Return the path to the Python interpreter inside `venv_dir`."""
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _parse_requirement_names(req_file: Path) -> list[str]:
    """Extract top-level package names from a requirements.txt file."""
    names: list[str] = []
    for raw_line in req_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQ_NAME_RE.match(line)
        if match:
            names.append(match.group(1))
    return names


def _requirements_hash(req_file: Path) -> str:
    """Compute a stable SHA-256 digest of requirements.txt."""
    return hashlib.sha256(req_file.read_bytes()).hexdigest()


def _packages_present_in_current_python(names: list[str]) -> bool:
    """Check whether all named distributions are installed in the current Python."""
    for name in names:
        try:
            importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            return False
    return True


def _packages_present_in_venv(venv_python: Path, names: list[str]) -> bool:
    """Check whether all named distributions are installed inside `venv_python`."""
    if not names:
        return True
    if Path(sys.prefix).resolve() == VENV_DIR.resolve():
        return _packages_present_in_current_python(names)

    check_script = (
        "import importlib.metadata, sys; "
        "names = sys.argv[1:]; "
        "[importlib.metadata.distribution(n) for n in names]"
    )
    result = subprocess.run(
        [str(venv_python), "-c", check_script, *names],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _requirements_satisfied(venv_python: Path, req_file: Path) -> bool:
    """Return True if requirements.txt matches marker or all packages are installed."""
    if not req_file.is_file():
        return True

    expected_hash = _requirements_hash(req_file)
    names = _parse_requirement_names(req_file)

    if MARKER_FILE.is_file():
        recorded_hash = MARKER_FILE.read_text(encoding="utf-8").strip()
        if recorded_hash != expected_hash:
            return False
        return _packages_present_in_venv(venv_python, names)

    if _packages_present_in_venv(venv_python, names):
        try:
            MARKER_FILE.write_text(expected_hash + "\n", encoding="utf-8")
        except OSError:
            pass
        return True
    return False


def ensure_environment(
    script_path: Optional[Path] = None,
    auto_reexec: bool = True,
) -> None:
    """
    Create `Snifx/venv`, install `requirements.txt` if needed, and switch to it.

    Set `PYKTO_NO_AUTO_VENV=1` to skip automatic setup/re-exec.
    """
    if os.environ.get("PYKTO_NO_AUTO_VENV") == "1":
        return

    venv_python = get_venv_python(VENV_DIR)

    if not venv_python.exists():
        print(f"[Pykto] Creating virtual environment at {VENV_DIR}...", file=sys.stderr)
        proc = subprocess.run(
            [sys.executable, "-m", "venv", str(VENV_DIR)],
            check=False,
        )
        if proc.returncode != 0 or not venv_python.exists():
            print(
                "[Pykto] Warning: Could not create Snifx/venv automatically. "
                "On Ubuntu/Debian install `python3-venv` or run ./setup_env.sh.",
                file=sys.stderr,
            )
            return

    if REQ_FILE.is_file() and not _requirements_satisfied(venv_python, REQ_FILE):
        print(f"[Pykto] Installing requirements from {REQ_FILE}...", file=sys.stderr)
        pip_proc = subprocess.run(
            [str(venv_python), "-m", "pip", "install", "-r", str(REQ_FILE)],
            check=False,
        )
        if pip_proc.returncode == 0:
            try:
                MARKER_FILE.write_text(
                    _requirements_hash(REQ_FILE) + "\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
        else:
            print(
                "[Pykto] Warning: Failed to install requirements (check network/pip). "
                "Continuing with available packages.",
                file=sys.stderr,
            )

    in_project_venv = Path(sys.prefix).resolve() == VENV_DIR.resolve()
    if (
        auto_reexec
        and not in_project_venv
        and venv_python.exists()
        and os.environ.get("PYKTO_BOOTSTRAPPED") != "1"
    ):
        target = Path(script_path).resolve() if script_path else Path(sys.argv[0]).resolve()
        os.environ["PYKTO_BOOTSTRAPPED"] = "1"
        argv = [str(venv_python), str(target), *sys.argv[1:]]
        if os.name == "nt":
            raise SystemExit(subprocess.call(argv))
        os.execv(str(venv_python), argv)

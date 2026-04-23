from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def find_trivy_executable() -> str | None:
    executable = shutil.which("trivy")
    if executable is not None:
        return executable

    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None

    winget_packages = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
    if not winget_packages.exists():
        return None

    for candidate in winget_packages.glob("AquaSecurity.Trivy_*/trivy.exe"):
        if candidate.is_file():
            return str(candidate)
    return None


def trivy_version() -> str | None:
    executable = find_trivy_executable()
    if executable is None:
        return None
    try:
        completed = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "unknown"


def run_trivy_config(target: Path, output_path: Path) -> tuple[bool, int, str | None]:
    executable = find_trivy_executable()
    if executable is None:
        return False, 0, "trivy.exe was not found; Dockerfile scan skipped."

    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = [executable, "config", "--format", "json", "--output", str(output_path), str(target)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return False, 0, f"Trivy timed out for {target}."
    except OSError as exc:
        return False, 0, f"Trivy failed for {target}: {exc}"

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "Trivy scan failed."
        return False, 0, detail
    return True, count_trivy_findings(output_path), None


def count_trivy_findings(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    total = 0
    for result in data.get("Results", []):
        total += len(result.get("Misconfigurations", []) or [])
        total += len(result.get("Vulnerabilities", []) or [])
        total += len(result.get("Secrets", []) or [])
    return total

from __future__ import annotations

import platform
import shutil
import subprocess
import sys

from ssafer.core.trivy import trivy_version


TRIVY_WINGET_ID = "AquaSecurity.Trivy"


def collect_doctor_status() -> dict:
    trivy = trivy_version()
    docker_version = _command_first_line(["docker", "--version"])
    compose_version = _command_first_line(["docker", "compose", "version"])
    checks = [
        {"name": "Python", "ok": sys.version_info >= (3, 10), "detail": platform.python_version()},
        {"name": "Windows", "ok": platform.system() == "Windows", "detail": platform.system()},
        {"name": "trivy.exe", "ok": trivy is not None, "detail": trivy or "not found"},
        {"name": "Docker", "ok": docker_version is not None, "detail": docker_version or "not found"},
        {"name": "docker compose", "ok": compose_version is not None, "detail": compose_version or "not found"},
        {"name": "PATH", "ok": bool(shutil.which("python")), "detail": "python found" if shutil.which("python") else "python missing"},
    ]
    return {"checks": checks, "trivyFound": trivy is not None}


def _command_first_line(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    text = completed.stdout.strip() or completed.stderr.strip()
    return text.splitlines()[0] if text else "ok"


def install_trivy_with_winget() -> tuple[bool, str]:
    if platform.system() != "Windows":
        return False, "Automatic Trivy installation is only supported on Windows."

    current_version = trivy_version()
    if current_version is not None:
        return True, f"Trivy is already installed: {current_version}"

    if shutil.which("winget") is None:
        return False, "winget was not found. Install Trivy manually: winget install AquaSecurity.Trivy"

    command = [
        "winget",
        "install",
        "--id",
        TRIVY_WINGET_ID,
        "-e",
        "--accept-package-agreements",
        "--accept-source-agreements",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return False, "Timed out while installing Trivy with winget."
    except OSError as exc:
        return False, f"Failed to run winget: {exc}"

    combined_output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    output = combined_output.splitlines()
    detail = output[-1] if output else "winget did not return output."
    if completed.returncode != 0:
        if _winget_output_means_already_installed(combined_output) or _winget_package_is_listed(TRIVY_WINGET_ID):
            installed_version = trivy_version()
            if installed_version is not None:
                return True, f"Trivy is already installed: {installed_version}"
            return True, (
                "winget reports Trivy is already installed, but this terminal cannot find 'trivy'. "
                "Restart PowerShell and run 'trivy --version'."
            )
        return False, f"winget failed: {detail}"

    installed_version = trivy_version()
    if installed_version is not None:
        return True, f"Trivy installed: {installed_version}"
    return True, "Trivy installation finished. Restart the terminal if 'trivy' is not on PATH yet."


def _winget_output_means_already_installed(detail: str) -> bool:
    normalized = detail.casefold()
    known_messages = [
        "no newer package versions are available",
        "already installed",
        "already exists",
    ]
    return any(message in normalized for message in known_messages)


def _winget_package_is_listed(package_id: str) -> bool:
    try:
        completed = subprocess.run(
            ["winget", "list", "--id", package_id, "-e"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    combined_output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).casefold()
    return package_id.casefold() in combined_output

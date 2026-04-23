from pathlib import Path

from ssafer.core import trivy


def test_find_trivy_executable_prefers_path(monkeypatch):
    monkeypatch.setattr(trivy.shutil, "which", lambda name: "C:\\Tools\\trivy.exe" if name == "trivy" else None)

    assert trivy.find_trivy_executable() == "C:\\Tools\\trivy.exe"


def test_find_trivy_executable_checks_winget_package_dir(tmp_path: Path, monkeypatch):
    package_dir = tmp_path / "Microsoft" / "WinGet" / "Packages" / "AquaSecurity.Trivy_Source"
    package_dir.mkdir(parents=True)
    executable = package_dir / "trivy.exe"
    executable.write_text("", encoding="utf-8")

    monkeypatch.setattr(trivy.shutil, "which", lambda name: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert trivy.find_trivy_executable() == str(executable)


def test_find_trivy_executable_returns_none_when_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(trivy.shutil, "which", lambda name: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert trivy.find_trivy_executable() is None

from __future__ import annotations

import json
import platform
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from ssafer import __version__
from ssafer.core.compose import build_compose_sets, render_effective_config
from ssafer.core.env_parser import parse_env_metadata
from ssafer.core.finder import discover_project_files
from ssafer.core.hashing import hash_file, hash_text, load_or_create_project_salt
from ssafer.core.sanitize import sanitize_compose_yaml
from ssafer.core.trivy import run_trivy_config, trivy_version


def run_scan(
    project_root: Path,
    save_raw: bool = False,
    on_step: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    def _step(msg: str) -> None:
        if on_step:
            on_step(msg)

    warnings: list[str] = []
    project_root = project_root.resolve()
    _step("프로젝트 파일 탐색 중...")
    files = discover_project_files(project_root)
    salt = load_or_create_project_salt(project_root)

    scan_id = f"local-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    ssafer_dir = project_root / ".ssafer"
    sanitized_dir = ssafer_dir / "effective" / "sanitized"
    raw_dir = ssafer_dir / "effective" / "raw"
    trivy_dir = ssafer_dir / "trivy"
    results_dir = ssafer_dir / "results"
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    trivy_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    if save_raw:
        raw_dir.mkdir(parents=True, exist_ok=True)

    artifacts: list[dict[str, Any]] = []
    source_hashes = _source_hashes(project_root, [*files.env_files, *files.dockerfiles, *files.compose_files], warnings)
    effective_hashes: dict[str, str] = {}
    _step("Compose 세트 구성 중...")
    compose_sets = build_compose_sets(files.compose_files, warnings)

    for compose_set in compose_sets:
        _step(f"Compose 설정 렌더링 중: {compose_set.name}")
        ok, raw_config, error = render_effective_config(compose_set)
        if not ok:
            warnings.append(error or f"Failed to render compose set '{compose_set.name}'.")
            continue

        _step(f"민감정보 마스킹 중: {compose_set.name}")
        sanitized = sanitize_compose_yaml(raw_config)
        safe_name = _safe_artifact_name(compose_set.name)
        sanitized_path = sanitized_dir / f"{safe_name}.compose.yml"
        sanitized_path.write_text(sanitized, encoding="utf-8")
        effective_hashes[compose_set.name] = hash_text(sanitized)
        if save_raw:
            (raw_dir / f"{safe_name}.compose.yml").write_text(raw_config, encoding="utf-8")

        artifacts.append(
            {
                "type": "sanitized-effective-compose",
                "composeSet": compose_set.name,
                "hash": effective_hashes[compose_set.name],
                "content": sanitized,
            }
        )

    _step("환경변수 파일 파싱 중...")
    env_metadata = parse_env_metadata(files.env_files, salt, project_root, warnings)
    for env_item in env_metadata:
        artifacts.append(
            {
                "type": "env-metadata",
                "target": env_item["path"],
                "hash": hash_text(json.dumps(env_item, sort_keys=True)),
                "content": env_item,
            }
        )

    trivy_findings = 0
    trivy_version_value = trivy_version()
    for dockerfile in files.dockerfiles:
        _step(f"Trivy 취약점 스캔 중: {dockerfile.name}")
        output_path = trivy_dir / f"{_safe_artifact_name(str(dockerfile.relative_to(project_root)))}.json"
        ok, count, error = run_trivy_config(dockerfile, output_path)
        if not ok:
            warnings.append(error or f"Trivy failed for {dockerfile}.")
            continue
        trivy_findings += count
        try:
            content = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            content = {}
        artifacts.append(
            {
                "type": "trivy-json",
                "target": str(dockerfile.relative_to(project_root)),
                "hash": hash_file(output_path),
                "content": content,
            }
        )

    status = _analysis_status(artifacts, warnings)
    result = {
        "scanId": scan_id,
        "toolVersion": __version__,
        "os": platform.system().lower(),
        "analysisStatus": status,
        "toolVersions": {
            "trivy": trivy_version_value,
            "dockerCompose": _docker_compose_version(),
        },
        "warnings": warnings,
        "sourceFileHashes": source_hashes,
        "effectiveConfigHashes": effective_hashes,
        "targets": {
            "envFiles": [str(path.relative_to(project_root)) for path in files.env_files],
            "dockerfiles": [str(path.relative_to(project_root)) for path in files.dockerfiles],
            "composeSets": [_compose_set_manifest(item, project_root) for item in compose_sets],
        },
        "artifacts": artifacts,
        "cliSummary": {
            "composeSets": len(compose_sets),
            "envFiles": len(files.env_files),
            "dockerfiles": len(files.dockerfiles),
            "trivyFindings": trivy_findings,
            "warnings": len(warnings),
        },
        "analysisSummary": None,
    }

    _step("결과 저장 중...")
    result_path = results_dir / f"{scan_id}.json"
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    (results_dir / "last_scan.txt").write_text(result_path.name, encoding="utf-8")
    return result


def load_last_scan(project_root: Path) -> dict[str, Any] | None:
    results_dir = project_root / ".ssafer" / "results"
    marker = results_dir / "last_scan.txt"
    if marker.exists():
        scan_path = results_dir / marker.read_text(encoding="utf-8").strip()
    else:
        candidates = sorted(results_dir.glob("local-scan-*.json")) if results_dir.exists() else []
        scan_path = candidates[-1] if candidates else None
    if not scan_path or not scan_path.exists():
        return None
    return json.loads(scan_path.read_text(encoding="utf-8"))


def _source_hashes(root: Path, paths: list[Path], warnings: list[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in paths:
        try:
            hashes[str(path.relative_to(root))] = hash_file(path)
        except OSError as exc:
            warnings.append(f"Failed to hash {path}: {exc}")
    return hashes


def _analysis_status(artifacts: list[dict[str, Any]], warnings: list[str]) -> str:
    if not artifacts:
        return "FAILED"
    if warnings:
        return "PARTIAL"
    return "SUCCESS"


def _compose_set_manifest(compose_set: Any, root: Path) -> dict[str, Any]:
    return {
        "name": compose_set.name,
        "files": [str(path.relative_to(root)) for path in compose_set.files],
        "envFiles": [str(path.relative_to(root)) for path in compose_set.env_files],
        "independent": compose_set.independent,
    }


def _safe_artifact_name(name: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in name)


def _docker_compose_version() -> str | None:
    from ssafer.core.doctor import _command_first_line

    return _command_first_line(["docker", "compose", "version"])

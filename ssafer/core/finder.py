from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ssafer.core.constants import BASE_COMPOSE, EXCLUDED_DIRS, OVERRIDE_COMPOSE


@dataclass(frozen=True)
class ProjectFiles:
    env_files: list[Path]
    dockerfiles: list[Path]
    compose_files: list[Path]


def discover_project_files(root: Path) -> ProjectFiles:
    env_files: list[Path] = []
    dockerfiles: list[Path] = []
    compose_files: list[Path] = []

    for current, dirs, files in os.walk(root):
        dirs[:] = [item for item in dirs if item not in EXCLUDED_DIRS]
        current_path = Path(current)
        for file_name in files:
            path = current_path / file_name
            lower_name = file_name.lower()
            if file_name == ".env" or file_name.startswith(".env."):
                env_files.append(path)
            elif file_name in {"Dockerfile", "Containerfile"}:
                dockerfiles.append(path)
            elif _is_compose_file(lower_name):
                compose_files.append(path)

    return ProjectFiles(
        env_files=sorted(env_files),
        dockerfiles=sorted(dockerfiles),
        compose_files=sorted(compose_files),
    )


def _is_compose_file(lower_name: str) -> bool:
    if lower_name in BASE_COMPOSE or lower_name in OVERRIDE_COMPOSE:
        return True
    return (
        lower_name.startswith("docker-compose.")
        and (lower_name.endswith(".yml") or lower_name.endswith(".yaml"))
    ) or (
        lower_name.startswith("compose.")
        and (lower_name.endswith(".yml") or lower_name.endswith(".yaml"))
    )

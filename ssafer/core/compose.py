from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ssafer.core.constants import BASE_COMPOSE, OVERRIDE_COMPOSE


@dataclass(frozen=True)
class ComposeSet:
    name: str
    directory: Path
    files: list[Path]
    env_files: list[Path]
    independent: bool = False


ENV_PATTERN = re.compile(r"^(docker-compose|compose)\.(?P<env>.+)\.(yml|yaml)$")


def build_compose_sets(compose_files: list[Path], warnings: list[str]) -> list[ComposeSet]:
    by_dir: dict[Path, list[Path]] = {}
    for file in compose_files:
        by_dir.setdefault(file.parent, []).append(file)

    sets: list[ComposeSet] = []
    for directory, files in sorted(by_dir.items()):
        names = {file.name.lower(): file for file in files}
        base_files = [names[name] for name in BASE_COMPOSE if name in names]
        override_files = [names[name] for name in OVERRIDE_COMPOSE if name in names]
        env_files = _env_compose_files(files)

        if base_files:
            base = sorted(base_files)[0]
            default_files = [base, *sorted(override_files)]
            sets.append(ComposeSet("default", directory, default_files, _matching_env_files(directory, "default")))
            for env_name, env_compose in env_files:
                sets.append(
                    ComposeSet(env_name, directory, [base, env_compose], _matching_env_files(directory, env_name))
                )
        else:
            for env_name, env_compose in env_files:
                warnings.append(f"Base compose file not found for {env_compose}; created independent set '{env_name}'.")
                sets.append(
                    ComposeSet(env_name, directory, [env_compose], _matching_env_files(directory, env_name), True)
                )

    return sets


def render_effective_config(compose_set: ComposeSet) -> tuple[bool, str, str | None]:
    command = ["docker", "compose"]
    for env_file in compose_set.env_files:
        command.extend(["--env-file", str(env_file)])
    for compose_file in compose_set.files:
        command.extend(["-f", str(compose_file)])
    command.append("config")

    try:
        completed = subprocess.run(
            command,
            cwd=compose_set.directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except FileNotFoundError:
        return False, "", "Docker CLI was not found."
    except subprocess.TimeoutExpired:
        return False, "", f"docker compose config timed out for compose set '{compose_set.name}'."

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "docker compose config failed."
        return False, "", detail
    return True, completed.stdout, None


def _env_compose_files(files: list[Path]) -> list[tuple[str, Path]]:
    pairs: list[tuple[str, Path]] = []
    for file in files:
        name = file.name.lower()
        if name in BASE_COMPOSE or name in OVERRIDE_COMPOSE:
            continue
        match = ENV_PATTERN.match(name)
        if not match:
            continue
        env_name = match.group("env")
        if env_name == "override":
            continue
        pairs.append((env_name, file))
    return sorted(pairs, key=lambda item: item[0])


def _matching_env_files(directory: Path, set_name: str) -> list[Path]:
    candidates = [directory / ".env"]
    if set_name != "default":
        candidates.append(directory / f".env.{set_name}")
    return [path for path in candidates if path.exists()]

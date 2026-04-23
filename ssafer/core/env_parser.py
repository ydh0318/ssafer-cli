from __future__ import annotations

from pathlib import Path

from ssafer.core.hashing import hash_value
from ssafer.core.sanitize import classify_value, is_placeholder, is_secret_key, mask_value


def parse_env_metadata(env_files: list[Path], project_salt: str, root: Path, warnings: list[str]) -> list[dict]:
    metadata: list[dict] = []
    for env_file in env_files:
        keys: list[dict] = []
        try:
            lines = env_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            warnings.append(f"Failed to read env file {env_file}: {exc}")
            continue

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = _strip_quotes(value.strip())
            secret_like = is_secret_key(key) or classify_value(value) == "secret-like"
            keys.append(
                {
                    "key": key,
                    "valueMasked": mask_value(value) if value else "",
                    "valueHash": hash_value(project_salt, value) if value else None,
                    "valueClass": "secret-like" if secret_like else classify_value(value),
                    "isEmpty": value == "",
                    "isPlaceholder": is_placeholder(value),
                }
            )
        metadata.append({"path": str(env_file.relative_to(root)), "keys": keys})
    return metadata


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value

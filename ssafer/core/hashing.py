from __future__ import annotations

import hashlib
import secrets
from pathlib import Path


def load_or_create_project_salt(project_root: Path) -> str:
    ssafer_dir = project_root / ".ssafer"
    ssafer_dir.mkdir(exist_ok=True)
    salt_path = ssafer_dir / "project.salt"
    if salt_path.exists():
        return salt_path.read_text(encoding="utf-8").strip()
    salt = secrets.token_hex(32)
    salt_path.write_text(salt, encoding="utf-8")
    return salt


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def hash_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def hash_value(project_salt: str, value: str) -> str:
    normalized = value.strip()
    return f"sha256:{hashlib.sha256((project_salt + normalized).encode('utf-8')).hexdigest()}"

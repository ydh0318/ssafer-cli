from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from ssafer.core.result_store import load_last_scan


DEFAULT_API_URL = "http://localhost:8080"


def upload_last_scan(project_root: Path, api_url: str | None = None) -> dict[str, Any]:
    scan = load_last_scan(project_root)
    if scan is None:
        raise RuntimeError("No local scan package found. Run 'ssafer run' first.")

    base_url = (api_url or DEFAULT_API_URL).rstrip("/")
    with httpx.Client(timeout=30) as client:
        response = client.post(f"{base_url}/api/scans", json=scan)
        response.raise_for_status()
        data = response.json()
    return data

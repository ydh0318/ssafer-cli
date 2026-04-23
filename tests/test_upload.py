from pathlib import Path
from typing import Any

import httpx
import pytest

from ssafer.core import upload


def _write_scan(project_root: Path, scan: dict[str, Any]) -> None:
    results_dir = project_root / ".ssafer" / "results"
    results_dir.mkdir(parents=True)
    scan_path = results_dir / "local-scan-test.json"
    scan_path.write_text('{"scanId": "local-scan-test", "artifacts": []}', encoding="utf-8")
    (results_dir / "last_scan.txt").write_text(scan_path.name, encoding="utf-8")


def test_upload_last_scan_posts_latest_scan(tmp_path: Path, monkeypatch):
    scan = {"scanId": "local-scan-test", "artifacts": []}
    _write_scan(tmp_path, scan)
    calls: list[tuple[str, dict[str, Any]]] = []

    class FakeClient:
        def __init__(self, timeout: int):
            assert timeout == 30

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url: str, json: dict[str, Any]):
            calls.append((url, json))
            request = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={"scanId": "remote-scan-1", "viewUrl": "http://example.test/scans/1"},
                request=request,
            )

    monkeypatch.setattr(upload.httpx, "Client", FakeClient)

    response = upload.upload_last_scan(tmp_path, api_url="http://backend.test/")

    assert response == {"scanId": "remote-scan-1", "viewUrl": "http://example.test/scans/1"}
    assert calls == [("http://backend.test/api/scans", scan)]


def test_upload_last_scan_uses_default_api_url(tmp_path: Path, monkeypatch):
    scan = {"scanId": "local-scan-test", "artifacts": []}
    _write_scan(tmp_path, scan)
    posted_urls: list[str] = []

    class FakeClient:
        def __init__(self, timeout: int):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def post(self, url: str, json: dict[str, Any]):
            posted_urls.append(url)
            request = httpx.Request("POST", url)
            return httpx.Response(200, json={"scanId": "remote-scan-1"}, request=request)

    monkeypatch.setattr(upload.httpx, "Client", FakeClient)

    upload.upload_last_scan(tmp_path)

    assert posted_urls == ["http://localhost:8080/api/scans"]


def test_upload_last_scan_requires_existing_scan(tmp_path: Path):
    with pytest.raises(RuntimeError, match="No local scan package found"):
        upload.upload_last_scan(tmp_path)

from pathlib import Path

from ssafer.core.env_parser import parse_env_metadata


def test_env_metadata_never_contains_raw_values(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("PUBLIC_MODE=dev\nDB_PASSWORD=super-secret\nEMPTY=\n", encoding="utf-8")

    warnings: list[str] = []
    metadata = parse_env_metadata([env_file], "salt", tmp_path, warnings)

    text = str(metadata)
    assert "dev" not in text
    assert "super-secret" not in text
    assert metadata[0]["keys"][0]["valueMasked"] == "***MASKED***"
    assert metadata[0]["keys"][1]["valueMasked"] == "***MASKED***"
    assert metadata[0]["keys"][2]["valueMasked"] == ""
    assert not warnings

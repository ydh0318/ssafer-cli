from pathlib import Path

from ssafer.core.compose import build_compose_sets


def test_build_compose_sets_with_override_and_env(tmp_path: Path):
    base = tmp_path / "docker-compose.yml"
    override = tmp_path / "docker-compose.override.yml"
    dev = tmp_path / "docker-compose.dev.yml"
    for path in (base, override, dev):
        path.write_text("services: {}\n", encoding="utf-8")

    warnings: list[str] = []
    sets = build_compose_sets([base, override, dev], warnings)

    by_name = {item.name: item for item in sets}
    assert "default" in by_name
    assert "dev" in by_name
    assert override in by_name["default"].files
    assert override not in by_name["dev"].files
    assert not warnings


def test_independent_set_without_base(tmp_path: Path):
    dev = tmp_path / "docker-compose.dev.yml"
    dev.write_text("services: {}\n", encoding="utf-8")

    warnings: list[str] = []
    sets = build_compose_sets([dev], warnings)

    assert sets[0].name == "dev"
    assert sets[0].independent is True
    assert warnings

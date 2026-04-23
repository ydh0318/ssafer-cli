from ssafer.core.sanitize import sanitize_compose_yaml


def test_sanitize_environment_and_url_credentials():
    raw = """
services:
  app:
    image: my-app:latest
    environment:
      DB_PASSWORD: super-secret
      PUBLIC_MODE: dev
    command: "--db=mysql://root:password@db:3306/app"
"""

    sanitized = sanitize_compose_yaml(raw)

    assert "super-secret" not in sanitized
    assert "root:password@" not in sanitized
    assert "DB_PASSWORD: '***MASKED***'" in sanitized or "DB_PASSWORD: ***MASKED***" in sanitized
    assert "image: my-app:latest" in sanitized

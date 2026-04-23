from __future__ import annotations

BASE_COMPOSE = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}

OVERRIDE_COMPOSE = {
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
    "compose.override.yml",
    "compose.override.yaml",
}

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".ssafer",
}

SECRET_KEYWORDS = {
    "SECRET",
    "PASSWORD",
    "PASS",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "DB_PASSWORD",
    "MYSQL_ROOT_PASSWORD",
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
}

DB_PORTS = {3306, 5432, 6379, 27017, 1433, 1521}
MASK = "***MASKED***"

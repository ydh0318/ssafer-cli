from __future__ import annotations

import re
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml

from ssafer.core.constants import MASK, SECRET_KEYWORDS

SECRET_VALUE_RE = re.compile(
    r"(?i)(secret|token|api[_-]?key|password|passwd|pwd|private[_-]?key|access[_-]?key)"
)
URL_CREDENTIAL_RE = re.compile(r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:\s/@]+):(?P<password>[^@\s]+)@")


def sanitize_compose_yaml(raw_yaml: str) -> str:
    try:
        document = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError:
        return conservative_mask_text(raw_yaml)
    sanitized = sanitize_obj(document)
    return yaml.safe_dump(sanitized, sort_keys=False, allow_unicode=False)


def sanitize_obj(value: Any, key_hint: str | None = None) -> Any:
    if isinstance(value, dict):
        sanitized: dict[Any, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if is_secret_key(key_text):
                sanitized[key] = MASK
            elif key_text in {"environment", "labels"}:
                sanitized[key] = sanitize_mapping_or_list(child)
            elif key_text in {"command", "entrypoint"}:
                sanitized[key] = sanitize_command(child)
            elif key_text == "args":
                sanitized[key] = sanitize_mapping_or_list(child)
            else:
                sanitized[key] = sanitize_obj(child, key_text)
        return sanitized
    if isinstance(value, list):
        return [sanitize_obj(item, key_hint) for item in value]
    if isinstance(value, str):
        if key_hint and is_secret_key(key_hint):
            return MASK
        return sanitize_string(value)
    return deepcopy(value)


def sanitize_mapping_or_list(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            result[key] = MASK if is_secret_key(key_text) else sanitize_obj(child, key_text)
        return result
    if isinstance(value, list):
        result: list[Any] = []
        for item in value:
            if isinstance(item, str) and "=" in item:
                key, child = item.split("=", 1)
                result.append(f"{key}={MASK if is_secret_key(key) else sanitize_string(child)}")
            else:
                result.append(sanitize_obj(item))
        return result
    return sanitize_obj(value)


def sanitize_command(value: Any) -> Any:
    if isinstance(value, str):
        masked = sanitize_url_credentials(value)
        if SECRET_VALUE_RE.search(masked):
            return "***MASKED_COMMAND_CONTAINS_SECRET***"
        return masked
    if isinstance(value, list):
        joined = " ".join(str(item) for item in value)
        if SECRET_VALUE_RE.search(joined):
            return ["***MASKED_COMMAND_CONTAINS_SECRET***"]
        return [sanitize_string(str(item)) for item in value]
    return sanitize_obj(value)


def sanitize_string(value: str) -> str:
    return sanitize_url_credentials(value)


def sanitize_url_credentials(value: str) -> str:
    return URL_CREDENTIAL_RE.sub(lambda match: f"{match.group('scheme')}{match.group('user')}:{MASK}@", value)


def conservative_mask_text(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if SECRET_VALUE_RE.search(line):
            lines.append(MASK)
        else:
            lines.append(sanitize_url_credentials(line))
    return "\n".join(lines)


def is_secret_key(key: str) -> bool:
    normalized = key.upper().replace("-", "_")
    return any(keyword in normalized for keyword in SECRET_KEYWORDS)


def classify_value(value: str) -> str:
    if not value:
        return "empty"
    if is_placeholder(value):
        return "placeholder"
    if SECRET_VALUE_RE.search(value):
        return "secret-like"
    if len(value) >= 32 and re.search(r"[A-Za-z]", value) and re.search(r"\d", value):
        return "secret-like"
    return "plain"


def is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized in {"changeme", "change-me", "todo", "example", "password", "admin", "root", "test"} or (
        normalized.startswith("${") and normalized.endswith("}")
    )


def mask_value(_: str) -> str:
    return MASK

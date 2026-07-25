from __future__ import annotations

from typing import Any


def normalize_cookie_jar(value: object) -> list[dict[str, Any]]:
    """Normalize a browser-style cookie jar while preserving cookie scope."""
    if not isinstance(value, (list, tuple)):
        return []
    normalized: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in value:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        cookie_value = str(raw.get("value") or "").strip()
        if not name or not cookie_value:
            continue
        domain = str(raw.get("domain") or "").strip().lower()
        path = str(raw.get("path") or "/").strip() or "/"
        item: dict[str, Any] = {
            "name": name,
            "value": cookie_value,
            "domain": domain,
            "path": path,
            "secure": bool(raw.get("secure")),
            "httpOnly": bool(raw.get("httpOnly", raw.get("http_only", False))),
        }
        expires = raw.get("expires")
        if isinstance(expires, (int, float)) and expires > 0:
            item["expires"] = int(expires)
        same_site = str(raw.get("sameSite", raw.get("same_site", "")) or "").strip()
        if same_site:
            item["sameSite"] = same_site
        normalized[(name, domain, path)] = item
    return list(normalized.values())


def flatten_cookie_jar(value: object) -> dict[str, str]:
    return {item["name"]: item["value"] for item in normalize_cookie_jar(value)}


def snapshot_session_cookie_jar(session: Any) -> list[dict[str, Any]]:
    jar = getattr(getattr(session, "cookies", None), "jar", None)
    if jar is None:
        return []
    items: list[dict[str, Any]] = []
    for cookie in jar:
        name = str(getattr(cookie, "name", "") or "").strip()
        value = str(getattr(cookie, "value", "") or "").strip()
        if not name or not value:
            continue
        rest = getattr(cookie, "_rest", {})
        http_only = isinstance(rest, dict) and any(str(key).lower() == "httponly" for key in rest)
        item: dict[str, Any] = {
            "name": name,
            "value": value,
            "domain": str(getattr(cookie, "domain", "") or "").strip().lower(),
            "path": str(getattr(cookie, "path", "/") or "/"),
            "secure": bool(getattr(cookie, "secure", False)),
            "httpOnly": http_only,
        }
        expires = getattr(cookie, "expires", None)
        if isinstance(expires, (int, float)) and expires > 0:
            item["expires"] = int(expires)
        items.append(item)
    return normalize_cookie_jar(items)


def apply_cookie_jar(session: Any, value: object) -> int:
    """Restore cookie scope supported by curl_cffi/requests cookie containers."""
    setter = getattr(getattr(session, "cookies", None), "set", None)
    if not callable(setter):
        return 0
    applied = 0
    for item in normalize_cookie_jar(value):
        kwargs = {
            "domain": item.get("domain") or "",
            "path": item.get("path") or "/",
            "secure": bool(item.get("secure")),
        }
        try:
            setter(item["name"], item["value"], **kwargs)
            applied += 1
        except TypeError:
            kwargs.pop("secure", None)
            setter(item["name"], item["value"], **kwargs)
            applied += 1
    return applied


__all__ = [
    "apply_cookie_jar",
    "flatten_cookie_jar",
    "normalize_cookie_jar",
    "snapshot_session_cookie_jar",
]

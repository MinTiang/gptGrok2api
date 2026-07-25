from __future__ import annotations

import asyncio
from typing import Any

from services.account_service import account_service
from services.grok_runtime import grok_runtime
from services.register.grok_account_store import grok_account_store
from services.xai_cli_oauth_store import xai_cli_oauth_store


STAT_KEYS = (
    "total",
    "cumulative_total",
    "active",
    "limited",
    "abnormal",
    "disabled",
    "total_quota",
    "unlimited_quota_count",
    "unknown_quota_count",
    "total_success",
    "total_fail",
)
PROVIDER_STATS_TIMEOUT_SECONDS = 5.0


def _number(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _empty(provider: str, *, source_available: bool = True) -> dict[str, Any]:
    return {
        **{key: 0 for key in STAT_KEYS},
        "provider": provider,
        "by_type": {},
        "source_available": source_available,
        "healthy": False,
    }


def _normalize(stats: object, provider: str, *, source_available: bool = True) -> dict[str, Any]:
    if not isinstance(stats, dict):
        return _empty(provider, source_available=source_available)
    normalized = _empty(provider, source_available=source_available)
    for key in STAT_KEYS:
        normalized[key] = _number(stats.get(key))
    by_type = stats.get("by_type")
    if isinstance(by_type, dict):
        normalized["by_type"] = {
            str(key): _number(value)
            for key, value in by_type.items()
            if str(key).strip()
        }
    quota_by_mode = stats.get("quota_by_mode")
    if isinstance(quota_by_mode, dict):
        normalized["quota_by_mode"] = {
            str(key): _number(value)
            for key, value in quota_by_mode.items()
            if str(key).strip()
        }
    normalized["healthy"] = bool(
        normalized["active"]
        or normalized["unlimited_quota_count"]
        or normalized["unknown_quota_count"]
    )
    return normalized


def _oauth_stats(items: object) -> dict[str, Any]:
    records = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    statuses = {"active": 0, "limited": 0, "disabled": 0, "abnormal": 0}
    total_quota = 0
    unknown_quota_count = 0
    for item in records:
        status = str(item.get("status") or "active").strip().lower()
        probe = item.get("probe") if isinstance(item.get("probe"), dict) else {}
        probe_status = str(probe.get("status") or "").strip().lower()
        if status == "disabled":
            statuses["disabled"] += 1
            continue
        if status in {"expired", "invalid"} or probe_status == "invalid":
            statuses["abnormal"] += 1
            continue
        bucket = "limited" if probe_status == "limited" else "active"
        statuses[bucket] += 1
        quota = item.get("quota") if isinstance(item.get("quota"), dict) else {}
        if quota.get("remaining_percent") is None:
            unknown_quota_count += 1
    return {
        "total": len(records),
        "cumulative_total": len(records),
        "active": statuses["active"],
        "limited": statuses["limited"],
        "abnormal": statuses["abnormal"],
        "disabled": statuses["disabled"],
        "total_quota": total_quota,
        "unlimited_quota_count": 0,
        "unknown_quota_count": unknown_quota_count,
        "total_success": sum(_number(item.get("use_count")) for item in records),
        "total_fail": sum(_number(item.get("fail_count")) for item in records),
        "by_type": {"oauth": len(records)} if records else {},
    }


def _aggregate(provider: str, sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    result = _empty(provider, source_available=any(item.get("source_available") for item in sources.values()))
    for key in STAT_KEYS:
        result[key] = sum(_number(item.get(key)) for item in sources.values())
    by_type: dict[str, int] = {}
    for source_name, item in sources.items():
        source_types = item.get("by_type")
        if not isinstance(source_types, dict):
            continue
        for type_name, count in source_types.items():
            by_type[f"{source_name}:{type_name}"] = _number(count)
    result["by_type"] = by_type
    result["healthy"] = bool(
        result["active"]
        or result["unlimited_quota_count"]
        or result["unknown_quota_count"]
    )
    return result


async def _load_gpt_stats() -> dict[str, Any]:
    try:
        return _normalize(await asyncio.to_thread(account_service.get_stats), "gpt")
    except Exception:
        return _empty("gpt", source_available=False)


async def _load_grok_runtime_stats() -> dict[str, Any]:
    if not grok_runtime.available:
        return _empty("grok_runtime", source_available=False)
    try:
        return _normalize(await grok_runtime.account_stats(), "grok_runtime")
    except Exception:
        return _empty("grok_runtime", source_available=False)


def _runtime_linked_emails(items: object) -> set[str]:
    records = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    linked: set[str] = set()
    for item in records:
        runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
        email = str(item.get("email") or "").strip().lower()
        if email and runtime and runtime.get("present") is not False:
            linked.add(email)
    return linked


async def _load_grok_oauth_stats() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        items, registered = await asyncio.gather(
            asyncio.to_thread(xai_cli_oauth_store.list_accounts, redacted=False),
            asyncio.to_thread(grok_account_store.list_accounts, redacted=False),
        )
        linked_emails = _runtime_linked_emails(registered)
        unlinked_items = [
            item
            for item in items
            if str(item.get("email") or "").strip().lower() not in linked_emails
        ]
        return (
            _normalize(_oauth_stats(items), "grok_oauth"),
            _normalize(_oauth_stats(unlinked_items), "grok_oauth_unlinked"),
        )
    except Exception:
        return (
            _empty("grok_oauth", source_available=False),
            _empty("grok_oauth_unlinked", source_available=False),
        )


async def _load_with_timeout(loader: Any, provider: str) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(loader(), timeout=PROVIDER_STATS_TIMEOUT_SECONDS)
    except TimeoutError:
        return _empty(provider, source_available=False)


async def get_provider_account_stats() -> dict[str, Any]:
    gpt, grok_runtime_stats, grok_oauth_breakdown = await asyncio.gather(
        _load_with_timeout(_load_gpt_stats, "gpt"),
        _load_with_timeout(_load_grok_runtime_stats, "grok_runtime"),
        _load_with_timeout(_load_grok_oauth_stats, "grok_oauth"),
    )
    if isinstance(grok_oauth_breakdown, tuple) and len(grok_oauth_breakdown) == 2:
        grok_oauth, grok_oauth_unlinked = grok_oauth_breakdown
    else:
        grok_oauth = _empty("grok_oauth", source_available=False)
        grok_oauth_unlinked = _empty("grok_oauth_unlinked", source_available=False)
    oauth_for_logical_accounts = (
        grok_oauth_unlinked if grok_runtime_stats.get("source_available") else grok_oauth
    )
    grok = _aggregate(
        "grok",
        {"runtime": grok_runtime_stats, "oauth": oauth_for_logical_accounts},
    )
    # Usage counters belong to each credential path and are not account counts.
    # Retain linked OAuth traffic even though the logical account is counted once.
    grok["total_success"] = _number(grok_runtime_stats.get("total_success")) + _number(
        grok_oauth.get("total_success")
    )
    grok["total_fail"] = _number(grok_runtime_stats.get("total_fail")) + _number(
        grok_oauth.get("total_fail")
    )
    total = _aggregate("all", {"gpt": gpt, "grok": grok})
    total["providers"] = {
        "gpt": gpt,
        "grok": grok,
        "grok_runtime": grok_runtime_stats,
        "grok_oauth": grok_oauth,
    }
    return total


async def get_image_account_stats() -> dict[str, Any]:
    gpt, grok_runtime_stats = await asyncio.gather(
        _load_with_timeout(_load_gpt_stats, "gpt"),
        _load_with_timeout(_load_grok_runtime_stats, "grok_runtime"),
    )
    total = _aggregate("image", {"gpt": gpt, "grok": grok_runtime_stats})
    total["providers"] = {"gpt": gpt, "grok": grok_runtime_stats}
    return total


__all__ = ["get_image_account_stats", "get_provider_account_stats"]

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import shutil
import sqlite3
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.register.grok_account_store import grok_account_store
from services.sub2api_service import build_xai_oauth_export_account
from services.xai_cli_oauth_service import XaiCliOAuthService
from services.xai_cli_oauth_store import XAI_CLI_OAUTH_SCHEMA_VERSION, xai_cli_oauth_store


DATA_DIR = ROOT / "data"
OAUTH_FILE = DATA_DIR / "xai_cli_oauth_accounts.json"
GROK_FILE = DATA_DIR / "grok_accounts.json"
RUNTIME_DB = DATA_DIR / "grok_runtime" / "accounts.db"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean(value: object) -> str:
    return str(value or "").strip()


def secure_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def secure_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def copy_secure(source: Path, target: Path) -> None:
    shutil.copy2(source, target)
    os.chmod(target, 0o600)


def sqlite_backup(source: Path, target: Path) -> None:
    with sqlite3.connect(source) as source_db, sqlite3.connect(target) as target_db:
        source_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        source_db.backup(target_db)
    os.chmod(target, 0o600)


class MemoryOAuthStore:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self._lock = threading.RLock()
        self._order = [clean(item.get("id")) for item in items]
        self._items = {clean(item.get("id")): copy.deepcopy(item) for item in items}

    def get_accounts_by_ids(self, ids: list[str]) -> list[dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(self._items[item_id]) for item_id in ids if item_id in self._items]

    def update_tokens(
        self,
        account_id: str,
        *,
        access_token: str,
        refresh_token: str | None = None,
        id_token: str | None = None,
        expires_at: str = "",
        expires_in: int | None = None,
        email: str | None = None,
        models: list[str] | None = None,
    ) -> dict[str, Any] | None:
        del expires_in
        with self._lock:
            item = self._items.get(account_id)
            if item is None:
                return None
            item["access_token"] = clean(access_token)
            if refresh_token:
                item["refresh_token"] = clean(refresh_token)
            if id_token is not None:
                item["id_token"] = clean(id_token)
            if expires_at:
                item["expires_at"] = clean(expires_at)
            if email:
                item["email"] = clean(email)
            if models is not None:
                item["models"] = list(dict.fromkeys(clean(model) for model in models if clean(model)))
            item["last_refresh_at"] = now_iso()
            item["updated_at"] = now_iso()
            return copy.deepcopy(item)

    def set_status(self, ids: list[str], status: str) -> dict[str, int]:
        updated = 0
        with self._lock:
            for account_id in ids:
                item = self._items.get(account_id)
                if item is None or clean(item.get("status")) == status:
                    continue
                item["status"] = status
                item["updated_at"] = now_iso()
                updated += 1
        return {"updated": updated, "count": len(self._items)}

    def items(self) -> list[dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(self._items[item_id]) for item_id in self._order]


async def probe_ids(
    service: XaiCliOAuthService,
    account_ids: list[str],
    *,
    concurrency: int,
    batch_size: int,
    pass_label: str,
) -> dict[str, dict[str, Any]]:
    all_results: list[dict[str, Any]] = []
    latest: dict[str, dict[str, Any]] = {}
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(account_id: str) -> dict[str, Any]:
        async with semaphore:
            return await service.probe_account(account_id, persist=False)

    for offset in range(0, len(account_ids), batch_size):
        batch = account_ids[offset : offset + batch_size]
        results = await asyncio.gather(*(probe(account_id) for account_id in batch))
        all_results.extend(results)
        latest.update({clean(item.get("account_id")): item for item in results})
        counts = Counter(clean(item.get("status")).lower() or "unknown" for item in all_results)
        print(
            f"[{pass_label}] {min(offset + len(batch), len(account_ids))}/{len(account_ids)} "
            f"valid={counts['valid']} limited={counts['limited']} "
            f"invalid={counts['invalid']} unknown={counts['unknown']}",
            flush=True,
        )
    return latest


async def run_probe(
    *,
    concurrency: int,
    batch_size: int,
    unknown_retries: int,
) -> tuple[MemoryOAuthStore, dict[str, dict[str, Any]], Counter[str]]:
    initial_items = xai_cli_oauth_store.list_accounts(redacted=False)
    memory_store = MemoryOAuthStore(initial_items)
    service = XaiCliOAuthService(memory_store)  # type: ignore[arg-type]
    account_ids = [clean(item.get("id")) for item in initial_items]
    latest = await probe_ids(
        service,
        account_ids,
        concurrency=concurrency,
        batch_size=batch_size,
        pass_label="full",
    )

    for retry in range(1, unknown_retries + 1):
        unknown_ids = [account_id for account_id, item in latest.items() if clean(item.get("status")).lower() == "unknown"]
        if not unknown_ids:
            break
        print(f"[retry-{retry}] retrying unknown={len(unknown_ids)}", flush=True)
        await asyncio.sleep(min(5, retry * 2))
        latest.update(await probe_ids(
            service,
            unknown_ids,
            concurrency=concurrency,
            batch_size=batch_size,
            pass_label=f"retry-{retry}",
        ))

    counts = Counter(clean(item.get("status")).lower() or "unknown" for item in latest.values())
    return memory_store, latest, counts


def persist_probe_results(
    memory_store: MemoryOAuthStore,
    latest: dict[str, dict[str, Any]],
) -> None:
    with xai_cli_oauth_store._lock:
        xai_cli_oauth_store._save_unlocked(memory_store.items())
    xai_cli_oauth_store.update_probe_results(list(latest.values()))


def export_and_prune(export_dir: Path, stamp: str) -> dict[str, Any]:
    oauth_items = xai_cli_oauth_store.list_accounts(redacted=False)
    grok_items = grok_account_store.list_accounts(redacted=False)
    valid_oauth = [item for item in oauth_items if clean((item.get("probe") or {}).get("status")).lower() == "valid"]
    valid_oauth_ids = {clean(item.get("id")) for item in valid_oauth}
    removed_oauth = [item for item in oauth_items if clean(item.get("id")) not in valid_oauth_ids]
    valid_emails = {clean(item.get("email")).lower() for item in valid_oauth if clean(item.get("email"))}
    kept_grok = [item for item in grok_items if clean(item.get("email")).lower() in valid_emails]
    removed_grok = [item for item in grok_items if clean(item.get("email")).lower() not in valid_emails]

    classification = Counter(clean((item.get("probe") or {}).get("status")).lower() or "unknown" for item in removed_oauth)
    exported_at = now_iso()
    export_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(export_dir, 0o700)

    copy_secure(OAUTH_FILE, export_dir / "restore-full-xai-cli-oauth-accounts.json")
    copy_secure(GROK_FILE, export_dir / "restore-full-grok-accounts.json")
    sqlite_backup(RUNTIME_DB, export_dir / "restore-full-grok-runtime-accounts.db")
    copy_secure(OAUTH_FILE, DATA_DIR / f"xai_cli_oauth_accounts.before-grok45-prune-{stamp}.json")
    copy_secure(GROK_FILE, DATA_DIR / f"grok_accounts.before-grok45-prune-{stamp}.json")
    sqlite_backup(RUNTIME_DB, DATA_DIR / "grok_runtime" / f"accounts.before-grok45-prune-{stamp}.db")

    secure_json(
        export_dir / "grok-oauth-removed.json",
        {
            "schema_version": XAI_CLI_OAUTH_SCHEMA_VERSION,
            "exported_at": exported_at,
            "reason": "grok-4.5 probe status was not valid",
            "items": removed_oauth,
        },
    )
    secure_json(
        export_dir / "grok-oauth-removed-sub2api.json",
        {
            "exported_at": exported_at,
            "proxies": [],
            "accounts": [build_xai_oauth_export_account(item) for item in removed_oauth],
        },
    )
    secure_json(
        export_dir / "grok-registered-removed.json",
        {"exported_at": exported_at, "items": removed_grok},
    )
    lines = [
        f"{clean(item.get('email'))}----{clean(item.get('password'))}----{clean(item.get('sso'))}"
        for item in removed_grok
        if clean(item.get("email")) or clean(item.get("sso"))
    ]
    secure_text(export_dir / "grok-registered-removed.txt", "\n".join(lines) + ("\n" if lines else ""))

    oauth_delete = xai_cli_oauth_store.delete_accounts([clean(item.get("id")) for item in removed_oauth])
    grok_delete = grok_account_store.delete_accounts([clean(item.get("id")) for item in removed_grok])
    keep_tokens = {clean(item.get("sso")) for item in kept_grok if clean(item.get("sso"))}
    with sqlite3.connect(RUNTIME_DB) as database:
        before_runtime = int(database.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])
        if keep_tokens:
            placeholders = ",".join("?" for _ in keep_tokens)
            database.execute(f"DELETE FROM accounts WHERE token NOT IN ({placeholders})", tuple(keep_tokens))
        else:
            database.execute("DELETE FROM accounts")
        database.commit()
        after_runtime = int(database.execute("SELECT COUNT(*) FROM accounts").fetchone()[0])

    summary = {
        "exported_at": exported_at,
        "probe": {
            "total": len(oauth_items),
            "valid": len(valid_oauth),
            "limited": classification["limited"],
            "invalid": classification["invalid"],
            "unknown": classification["unknown"],
        },
        "oauth": {"before": len(oauth_items), "removed": oauth_delete["removed"], "after": oauth_delete["count"]},
        "registered": {"before": len(grok_items), "removed": grok_delete["removed"], "after": grok_delete["count"]},
        "runtime": {"before": before_runtime, "removed": before_runtime - after_runtime, "after": after_runtime},
    }
    secure_json(export_dir / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe Grok 4.5 OAuth quota and prune non-valid accounts")
    parser.add_argument("--concurrency", type=int, default=25)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--unknown-retries", type=int, default=2)
    parser.add_argument("--desktop", type=Path, default=Path.home() / "Desktop")
    args = parser.parse_args()

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    print(f"starting accounts={xai_cli_oauth_store.count()}", flush=True)
    memory_store, latest, counts = asyncio.run(
        run_probe(
            concurrency=max(1, min(25, args.concurrency)),
            batch_size=max(1, min(500, args.batch_size)),
            unknown_retries=max(0, min(5, args.unknown_retries)),
        )
    )
    total = sum(counts.values())
    print(f"final probe total={total} counts={dict(counts)}", flush=True)
    if counts["valid"] == 0:
        print("ABORT: no valid account was confirmed", file=sys.stderr, flush=True)
        return 2
    if total and counts["unknown"] / total > 0.25:
        print("ABORT: more than 25% accounts remain unknown", file=sys.stderr, flush=True)
        return 3

    persist_probe_results(memory_store, latest)
    export_dir = args.desktop / f"Grok-4.5-无额度账号-{stamp}"
    summary = export_and_prune(export_dir, stamp)
    print(f"export_dir={export_dir}", flush=True)
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

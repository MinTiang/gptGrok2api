from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from services import provider_account_stats


class ProviderAccountStatsTest(unittest.IsolatedAsyncioTestCase):
    async def test_unified_stats_include_gpt_runtime_and_oauth_accounts(self) -> None:
        fake_runtime = type(
            "FakeRuntime",
            (),
            {
                "available": True,
                "account_stats": AsyncMock(
                    return_value={
                        "total": 3,
                        "active": 2,
                        "limited": 1,
                        "total_quota": 90,
                        "total_success": 7,
                        "total_fail": 2,
                        "by_type": {"basic": 3},
                    }
                ),
            },
        )()
        with (
            patch.object(
                provider_account_stats.account_service,
                "get_stats",
                return_value={
                    "total": 2,
                    "active": 1,
                    "disabled": 1,
                    "total_quota": 40,
                    "total_success": 4,
                    "total_fail": 1,
                    "by_type": {"Plus": 2},
                },
            ),
            patch.object(provider_account_stats, "grok_runtime", fake_runtime),
            patch.object(provider_account_stats.grok_account_store, "list_accounts", return_value=[]),
            patch.object(
                provider_account_stats.xai_cli_oauth_store,
                "list_accounts",
                return_value=[
                    {"status": "active", "use_count": 5, "fail_count": 1},
                    {"status": "invalid", "use_count": 1, "fail_count": 3},
                ],
            ),
        ):
            stats = await provider_account_stats.get_provider_account_stats()

        self.assertEqual(stats["total"], 7)
        self.assertEqual(stats["active"], 4)
        self.assertEqual(stats["limited"], 1)
        self.assertEqual(stats["abnormal"], 1)
        self.assertEqual(stats["disabled"], 1)
        self.assertEqual(stats["total_quota"], 130)
        self.assertEqual(stats["providers"]["gpt"]["total"], 2)
        self.assertEqual(stats["providers"]["grok"]["total"], 5)
        self.assertEqual(stats["providers"]["grok_oauth"]["total_quota"], 0)

    async def test_unified_stats_deduplicate_runtime_linked_oauth_accounts(self) -> None:
        fake_runtime = type(
            "FakeRuntime",
            (),
            {
                "available": True,
                "account_stats": AsyncMock(
                    return_value={
                        "total": 2,
                        "active": 2,
                        "total_success": 7,
                        "total_fail": 1,
                    }
                ),
            },
        )()
        oauth_items = [
            {
                "email": "linked@example.com",
                "status": "active",
                "use_count": 5,
                "fail_count": 2,
                "quota": {"remaining_percent": 65},
            },
            {
                "email": "oauth-only@example.com",
                "status": "active",
                "use_count": 3,
                "fail_count": 0,
                "quota": {"remaining_percent": 100},
            },
        ]
        registered = [
            {
                "email": "linked@example.com",
                "runtime": {"present": True, "status": "active"},
            }
        ]
        with (
            patch.object(provider_account_stats.account_service, "get_stats", return_value={}),
            patch.object(provider_account_stats, "grok_runtime", fake_runtime),
            patch.object(provider_account_stats.grok_account_store, "list_accounts", return_value=registered),
            patch.object(provider_account_stats.xai_cli_oauth_store, "list_accounts", return_value=oauth_items),
        ):
            stats = await provider_account_stats.get_provider_account_stats()

        self.assertEqual(stats["providers"]["grok"]["total"], 3)
        self.assertEqual(stats["providers"]["grok"]["active"], 3)
        self.assertEqual(stats["providers"]["grok_oauth"]["total"], 2)
        self.assertEqual(stats["providers"]["grok"]["total_success"], 15)
        self.assertEqual(stats["providers"]["grok"]["total_fail"], 3)

    async def test_image_stats_exclude_text_only_oauth_accounts(self) -> None:
        fake_runtime = type(
            "FakeRuntime",
            (),
            {
                "available": True,
                "account_stats": AsyncMock(return_value={"total": 4, "active": 4, "total_quota": 120}),
            },
        )()
        with (
            patch.object(
                provider_account_stats.account_service,
                "get_stats",
                return_value={"total": 2, "active": 2, "total_quota": 20},
            ),
            patch.object(provider_account_stats, "grok_runtime", fake_runtime),
            patch.object(provider_account_stats.xai_cli_oauth_store, "list_accounts") as oauth_list,
        ):
            stats = await provider_account_stats.get_image_account_stats()

        self.assertEqual(stats["total"], 6)
        self.assertEqual(stats["total_quota"], 140)
        self.assertEqual(set(stats["providers"]), {"gpt", "grok"})
        oauth_list.assert_not_called()

    async def test_slow_runtime_stats_degrade_without_blocking_other_sources(self) -> None:
        async def slow_stats():
            await asyncio.sleep(1)

        fake_runtime = type(
            "FakeRuntime",
            (),
            {
                "available": True,
                "account_stats": AsyncMock(side_effect=slow_stats),
            },
        )()
        with (
            patch.object(provider_account_stats, "PROVIDER_STATS_TIMEOUT_SECONDS", 0.01),
            patch.object(
                provider_account_stats.account_service,
                "get_stats",
                return_value={"total": 2, "active": 2, "total_quota": 20},
            ),
            patch.object(provider_account_stats, "grok_runtime", fake_runtime),
            patch.object(provider_account_stats.grok_account_store, "list_accounts", return_value=[]),
            patch.object(provider_account_stats.xai_cli_oauth_store, "list_accounts", return_value=[]),
        ):
            stats = await provider_account_stats.get_provider_account_stats()

        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["providers"]["gpt"]["active"], 2)
        self.assertFalse(stats["providers"]["grok_runtime"]["source_available"])


if __name__ == "__main__":
    unittest.main()

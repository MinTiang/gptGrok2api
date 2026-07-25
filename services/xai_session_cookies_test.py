from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from services.xai_session_cookies import (
    apply_cookie_jar,
    flatten_cookie_jar,
    normalize_cookie_jar,
    snapshot_session_cookie_jar,
)


class XaiSessionCookiesTest(unittest.TestCase):
    def test_normalize_preserves_scope_and_deduplicates_by_scope(self) -> None:
        jar = normalize_cookie_jar(
            [
                {"name": "sso", "value": "old", "domain": ".x.ai", "path": "/", "secure": True},
                {"name": "sso", "value": "new", "domain": ".x.ai", "path": "/", "secure": True},
                {"name": "sso", "value": "grok", "domain": ".grok.com", "path": "/"},
            ]
        )

        self.assertEqual(len(jar), 2)
        self.assertEqual(flatten_cookie_jar(jar)["sso"], "grok")
        self.assertEqual(jar[0]["value"], "new")

    def test_snapshot_and_apply_keep_domain_path_and_secure(self) -> None:
        cookie = SimpleNamespace(
            name="cf_clearance",
            value="secret",
            domain="accounts.x.ai",
            path="/oauth2",
            secure=True,
            expires=1_900_000_000,
            _rest={"HttpOnly": None},
        )
        source = SimpleNamespace(cookies=SimpleNamespace(jar=[cookie]))
        jar = snapshot_session_cookie_jar(source)
        target = SimpleNamespace(cookies=SimpleNamespace(set=MagicMock()))

        applied = apply_cookie_jar(target, jar)

        self.assertEqual(applied, 1)
        self.assertTrue(jar[0]["httpOnly"])
        target.cookies.set.assert_called_once_with(
            "cf_clearance",
            "secret",
            domain="accounts.x.ai",
            path="/oauth2",
            secure=True,
        )


if __name__ == "__main__":
    unittest.main()

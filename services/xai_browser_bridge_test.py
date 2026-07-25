from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from services.xai_browser_bridge import XaiBrowserBridge


class XaiBrowserBridgeTest(unittest.TestCase):
    def test_persistent_session_contract_carries_proxy_and_session_id(self) -> None:
        bridge = XaiBrowserBridge(
            {
                "api_base": "http://127.0.0.1:8877/",
                "api_key": "solver-key",
                "request_timeout": 10,
            },
            proxy="http://proxy.example:8080",
        )
        responses = iter(
            [
                {"ok": True, "session_id": "xai-session"},
                {"ok": True, "grpc_status": "0"},
                {"ok": True, "reason": "confirmed"},
            ]
        )
        calls: list[tuple[str, dict, dict]] = []

        def post(url, *, json, headers, timeout):
            calls.append((url, json, headers))
            return SimpleNamespace(status_code=200, json=lambda: next(responses))

        bridge.session.post = MagicMock(side_effect=post)
        bridge.start(signup_url="https://accounts.x.ai/sign-up?redirect=grok-com")
        bridge.send_email_validation_code("person@example.com")
        bridge.authorize_device(
            verification_url="https://accounts.x.ai/sign-in?redirect=device",
            user_code="ABCD-EFGH",
            timeout_s=120,
        )
        bridge.session_id = ""
        bridge.close()

        self.assertEqual(calls[0][0], "http://127.0.0.1:8877/xai/session/start")
        self.assertEqual(calls[0][1]["proxy"], "http://proxy.example:8080")
        self.assertEqual(calls[1][1]["session_id"], "xai-session")
        self.assertEqual(calls[2][1]["session_id"], "xai-session")
        self.assertEqual(calls[0][2]["Authorization"], "Bearer solver-key")

    def test_signup_keeps_legacy_metadata_in_transport_contract(self) -> None:
        bridge = XaiBrowserBridge({"api_base": "http://127.0.0.1:8877"})
        bridge.session_id = "xai-session"
        calls: list[tuple[str, dict]] = []

        def post(url, *, json, headers, timeout):
            del headers, timeout
            calls.append((url, json))
            return SimpleNamespace(status_code=200, json=lambda: {"ok": True, "sso": "browser-sso"})

        bridge.session.post = MagicMock(side_effect=post)
        result = bridge.signup(
            email="person@example.com",
            password="Secret123!",
            code="ABC-123",
            given_name="测试",
            family_name="用户",
            turnstile_token="turnstile-token",
            action_id="legacy-action-id",
            next_router_state_tree="legacy-router-state",
        )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0], "http://127.0.0.1:8877/xai/session/signup")
        self.assertEqual(calls[0][1]["session_id"], "xai-session")
        self.assertEqual(calls[0][1]["action_id"], "legacy-action-id")
        self.assertEqual(calls[0][1]["next_router_state_tree"], "legacy-router-state")


if __name__ == "__main__":
    unittest.main()

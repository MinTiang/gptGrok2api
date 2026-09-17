from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from utils import sentinel_vm


class SentinelVmTest(unittest.TestCase):
    def test_builds_primary_token_from_official_vm_results(self) -> None:
        session = MagicMock()
        actions = [
            {"request_p": "requirements-proof"},
            {"final_p": "sdk-proof", "t": "sdk-turnstile", "so": '{"so":"x","c":"challenge-token","id":"device-id","flow":"authorize_continue"}'},
        ]
        with (
            patch.object(sentinel_vm, "_ensure_sdk", return_value=(Path("/tmp/sdk.js"), "https://sentinel.openai.com")),
            patch.object(sentinel_vm, "_run_action", side_effect=actions),
            patch.object(
                sentinel_vm,
                "_fetch_challenge",
                return_value=({"token": "challenge-token"}, "real-oai-sc"),
            ),
        ):
            bundle = sentinel_vm.get_sentinel_token_via_vm(session, "device-id", "authorize_continue")

        self.assertIsNotNone(bundle)
        token, oai_sc, so = bundle or ("", "", "")
        payload = json.loads(token)
        self.assertEqual(payload["p"], "sdk-proof")
        self.assertEqual(payload["t"], "sdk-turnstile")
        self.assertEqual(payload["c"], "challenge-token")
        self.assertEqual(oai_sc, "real-oai-sc")
        self.assertEqual(json.loads(so)["so"], "x")

    def test_returns_none_when_vm_does_not_return_turnstile_value(self) -> None:
        session = MagicMock()
        actions = [
            {"request_p": "requirements-proof"},
            {"final_p": "sdk-proof", "t": None},
        ]
        with (
            patch.object(sentinel_vm, "_ensure_sdk", return_value=(Path("/tmp/sdk.js"), "https://sentinel.openai.com")),
            patch.object(sentinel_vm, "_run_action", side_effect=actions),
            patch.object(
                sentinel_vm,
                "_fetch_challenge",
                return_value=({"token": "challenge-token"}, "real-oai-sc"),
            ),
        ):
            token = sentinel_vm.get_sentinel_token_via_vm(session, "device-id", "authorize_continue")

        self.assertIsNone(token)

    def test_replaces_malformed_vm_turnstile_with_protocol_solver(self) -> None:
        session = MagicMock()
        actions = [
            {"request_p": "requirements-proof"},
            {"final_p": "sdk-proof", "t": "1"},
        ]
        challenge = {
            "token": "challenge-token",
            "turnstile": {"required": True, "dx": "turnstile-dx"},
        }
        with (
            patch.object(sentinel_vm, "_ensure_sdk", return_value=(Path("/tmp/sdk.js"), "https://sentinel.openai.com")),
            patch.object(sentinel_vm, "_run_action", side_effect=actions),
            patch.object(
                sentinel_vm,
                "_fetch_challenge",
                return_value=(challenge, "real-oai-sc"),
            ),
            patch.object(
                sentinel_vm,
                "solve_turnstile_token",
                return_value="protocol-turnstile-token",
            ) as solve_turnstile,
        ):
            bundle = sentinel_vm.get_sentinel_token_via_vm(
                session,
                "device-id",
                "checkout_session_approval",
            )

        self.assertIsNotNone(bundle)
        token, _oai_sc, _so = bundle or ("", "", "")
        self.assertEqual(json.loads(token)["t"], "protocol-turnstile-token")
        solve_turnstile.assert_called_once_with("turnstile-dx", "requirements-proof")

    def test_extracts_oai_sc_from_set_cookie_instead_of_challenge_token(self) -> None:
        response = MagicMock()
        response.headers = {
            "set-cookie": "oai-sc=0server-cookie; Domain=.chatgpt.com; Path=/\n__cflb=other; Path=/"
        }

        self.assertEqual(
            sentinel_vm._response_cookie_value(response, "oai-sc"),
            "0server-cookie",
        )

    def test_missing_so_envelope_is_tolerated(self) -> None:
        session = MagicMock()
        actions = [
            {"request_p": "requirements-proof"},
            {"final_p": "sdk-proof", "t": "sdk-turnstile"},
        ]
        with (
            patch.object(sentinel_vm, "_ensure_sdk", return_value=(Path("/tmp/sdk.js"), "https://sentinel.openai.com")),
            patch.object(sentinel_vm, "_run_action", side_effect=actions),
            patch.object(
                sentinel_vm,
                "_fetch_challenge",
                return_value=({"token": "challenge-token"}, "real-oai-sc"),
            ),
        ):
            bundle = sentinel_vm.get_sentinel_token_via_vm(session, "device-id", "authorize_continue")

        self.assertIsNotNone(bundle)
        _token, _oai_sc, so = bundle or ("", "", "")
        self.assertEqual(so, "")

    @staticmethod
    def _bootstrap_response(url: str, body: str) -> MagicMock:
        response = MagicMock()
        response.status_code = 200
        response.text = body
        response.url = url
        return response

    def test_ensure_sdk_discovers_sentinel_openai_origin_and_version(self) -> None:
        session = MagicMock()
        sdk_response = MagicMock()
        sdk_response.status_code = 200
        sdk_response.content = b"var SentinelSDK=1;"
        session.get.side_effect = [
            self._bootstrap_response(
                "https://sentinel.openai.com/backend-api/sentinel/sdk.js",
                "window.__boot=function(){};var s=document.createElement('script');"
                "s.src='https://sentinel.openai.com/sentinel/20260810913b/sdk.js';",
            ),
            sdk_response,
        ]

        with patch.object(sentinel_vm, "_cache_file", return_value=Path("/tmp/not-cached-sdk.js")) as cache_file, (
            patch.object(Path, "write_bytes")
        ):
            cache_file.is_file = lambda: False
            sdk_file, origin = sentinel_vm._ensure_sdk(session, timeout_seconds=5)

        self.assertEqual(origin, "https://sentinel.openai.com")
        self.assertEqual(sdk_file, Path("/tmp/not-cached-sdk.js"))
        first_url = session.get.call_args_list[0].args[0]
        self.assertTrue(first_url.startswith("https://sentinel.openai.com/"))
        versioned_url = session.get.call_args_list[1].args[0]
        self.assertEqual(versioned_url, "https://sentinel.openai.com/sentinel/20260810913b/sdk.js")

    def test_ensure_sdk_falls_back_to_chatgpt_origin(self) -> None:
        session = MagicMock()
        failing = MagicMock(status_code=403)
        sdk_response = MagicMock()
        sdk_response.status_code = 200
        sdk_response.content = b"var SentinelSDK=1;"
        session.get.side_effect = [
            failing,
            self._bootstrap_response(
                "https://chatgpt.com/backend-api/sentinel/sdk.js",
                "load('https://chatgpt.com/sentinel/19991231aa/sdk.js')",
            ),
            sdk_response,
        ]

        with patch.object(sentinel_vm, "_cache_file", return_value=Path("/tmp/not-cached-sdk.js")) as cache_file:
            cache_file.is_file = lambda: False
            with patch.object(Path, "write_bytes"):
                _sdk_file, origin = sentinel_vm._ensure_sdk(session, timeout_seconds=5)

        self.assertEqual(origin, "https://chatgpt.com")
        versioned_url = session.get.call_args_list[2].args[0]
        self.assertTrue(versioned_url.startswith("https://chatgpt.com/sentinel/19991231aa"))


if __name__ == "__main__":
    unittest.main()

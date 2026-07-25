from __future__ import annotations

import inspect
import unittest
from unittest.mock import AsyncMock, patch

from xai_browser import flow


class FakeContext:
    async def cookies(self):
        return [
            {
                "name": "sso",
                "value": "browser-sso",
                "domain": ".x.ai",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Lax",
                "expires": 2_000_000_000,
            }
        ]


class FakeField:
    def __init__(self):
        self.value = ""

    async def fill(self, value):
        self.value = value


class FakePage:
    def __init__(self):
        self.context = FakeContext()
        self.url = "https://accounts.x.ai/sign-up?redirect=grok-com"


class FakeBrowser:
    async def close(self):
        return None


class XaiBrowserFlowTest(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await flow.close_all_sessions()

    def _add_session(self, page: FakePage) -> None:
        flow._sessions["test-session"] = flow.BrowserSession(
            "test-session",
            FakeBrowser(),
            page,
            page.url,
        )

    def test_registration_flow_contains_no_direct_xai_protocol_requests(self):
        source = inspect.getsource(flow)
        self.assertNotIn("CreateEmailValidationCode", source)
        self.assertNotIn("VerifyEmailValidationCode", source)
        self.assertNotIn("Next-Action", source)
        self.assertNotIn("fetch(", source)

    def test_device_done_with_access_denied_query_is_not_success(self):
        status, reason = flow._device_authorization_outcome(
            "https://accounts.x.ai/oauth2/device/done?error=access_denied",
            "You can close this window",
        )

        self.assertEqual(status, "failed")
        self.assertEqual(reason, "device_verify_failed:access_denied")

    def test_device_done_with_denied_body_is_not_success(self):
        status, reason = flow._device_authorization_outcome(
            "https://accounts.x.ai/oauth2/device/done",
            "Authorization denied. You can close this window.",
        )

        self.assertEqual(status, "failed")
        self.assertEqual(reason, "device_verify_failed:access_denied")

    def test_device_done_without_error_is_success(self):
        status, reason = flow._device_authorization_outcome(
            "https://accounts.x.ai/oauth2/device/done",
            "Device has been authorized",
        )

        self.assertEqual(status, "confirmed")
        self.assertEqual(reason, "confirmed")

    async def test_send_email_uses_chinese_ui_controls(self):
        page = FakePage()
        field = FakeField()
        self._add_session(page)

        with (
            patch.object(flow, "_first_visible", AsyncMock(side_effect=[None, field])) as first_visible,
            patch.object(flow, "_click_any", AsyncMock(side_effect=[False, True])) as click_any,
            patch.object(flow, "_click_submit", AsyncMock(return_value=True)) as click_submit,
            patch.object(flow, "_wait_for_email_verification", AsyncMock()) as wait_verify,
        ):
            result = await flow.send_email("test-session", "person@example.com")

        self.assertTrue(result["ok"])
        self.assertEqual(field.value, "person@example.com")
        self.assertEqual(click_any.await_args_list[1].args[1][0], "使用邮箱注册")
        self.assertEqual(click_submit.await_args.args[1][:2], ("注册", "继续"))
        first_visible.assert_awaited()
        wait_verify.assert_awaited_once_with(page)

    async def test_verify_email_uses_ui_code_field_and_chinese_submit(self):
        page = FakePage()
        self._add_session(page)

        with (
            patch.object(flow, "_fill_verification_code", AsyncMock(return_value=True)) as fill_code,
            patch.object(flow, "_confirm_email_submission_if_needed", AsyncMock(return_value=True)) as confirm_email,
            patch.object(flow, "_wait_for_profile_form", AsyncMock()) as wait_profile,
        ):
            result = await flow.verify_email("test-session", "person@example.com", "ABC-123")

        self.assertTrue(result["ok"])
        fill_code.assert_awaited_once_with(page, "ABC-123")
        confirm_email.assert_awaited_once_with(page)
        wait_profile.assert_awaited_once_with(page)

    async def test_confirm_email_waits_for_auto_submit_then_clicks_real_button(self):
        page = FakePage()

        with (
            patch.object(flow, "_first_visible", AsyncMock(return_value=None)),
            patch.object(flow, "_click_any", AsyncMock(return_value=True)) as click_any,
            patch.object(flow, "_pause", AsyncMock()) as pause,
        ):
            clicked = await flow._confirm_email_submission_if_needed(page)

        self.assertTrue(clicked)
        self.assertEqual(pause.await_count, 4)
        self.assertEqual(
            click_any.await_args.args[1],
            ("确认邮箱", "验证邮箱", "Confirm email", "Verify email"),
        )

    async def test_confirm_email_does_not_click_after_profile_appears(self):
        page = FakePage()

        with (
            patch.object(flow, "_first_visible", AsyncMock(return_value=FakeField())),
            patch.object(flow, "_click_any", AsyncMock()) as click_any,
            patch.object(flow, "_pause", AsyncMock()) as pause,
        ):
            clicked = await flow._confirm_email_submission_if_needed(page)

        self.assertFalse(clicked)
        click_any.assert_not_awaited()
        pause.assert_not_awaited()

    async def test_signup_fills_ui_and_returns_browser_sso(self):
        page = FakePage()
        self._add_session(page)

        async def finish_signup(_page, _token, _profile):
            page.url = "https://accounts.x.ai/account"

        with (
            patch.object(flow, "_fill_first", AsyncMock(return_value=True)) as fill_first,
            patch.object(flow, "_set_native_input_value", AsyncMock(return_value=True)) as native_value,
            patch.object(flow, "_pause", AsyncMock()),
            patch.object(flow, "_solve_turnstile_in_page", AsyncMock(return_value="same-page-token")) as solve_token,
            patch.object(flow, "_click_submit", AsyncMock(return_value=True)) as click_submit,
            patch.object(flow, "_wait_for_signup_success", AsyncMock(side_effect=finish_signup)) as wait_success,
        ):
            result = await flow.signup(
                "test-session",
                email="person@example.com",
                password="Secret123!",
                code="ABC123",
                given_name="测试",
                family_name="用户",
                turnstile_token="turnstile-token",
                action_id="legacy-action-id",
                next_router_state_tree="legacy-router-state",
            )

        self.assertEqual(fill_first.await_count, 3)
        native_value.assert_awaited_once_with(page, 'input[name="password"]', "Secret123!")
        solve_token.assert_awaited_once_with(page, "turnstile-token")
        self.assertEqual(click_submit.await_args.args[1][0], "完成注册")
        wait_success.assert_awaited_once_with(page, "turnstile-token", ("测试", "用户", "Secret123!"))
        self.assertEqual(result["sso"], "browser-sso")
        self.assertEqual(result["redirect_url"], "https://accounts.x.ai/account")
        self.assertEqual(result["setter_hops"], 0)


if __name__ == "__main__":
    unittest.main()

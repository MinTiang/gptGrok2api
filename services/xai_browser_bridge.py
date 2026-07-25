from __future__ import annotations

from typing import Any

from curl_cffi import requests


class XaiBrowserBridgeError(RuntimeError):
    def __init__(self, message: str, *, stage: str = "browser", retryable: bool = False):
        super().__init__(message)
        self.stage = str(stage or "browser")
        self.retryable = bool(retryable)


class XaiBrowserBridge:
    """Synchronous client for the solver sidecar's persistent xAI browser session."""

    def __init__(self, config: dict[str, Any], *, proxy: str = ""):
        self.config = dict(config or {})
        self.base_url = str(self.config.get("api_base") or "http://127.0.0.1:8877").strip().rstrip("/")
        self.proxy = str(proxy or "").strip()
        self.request_timeout = max(5.0, float(self.config.get("request_timeout") or 30))
        self.flow_timeout = max(30.0, float(self.config.get("captcha_timeout") or 180) + 90)
        self.session_id = ""
        self.session = requests.Session(impersonate="chrome120", trust_env=False)

    def _headers(self) -> dict[str, str]:
        headers = {
            str(key): str(value)
            for key, value in (self.config.get("custom_headers") or {}).items()
        }
        api_key = str(self.config.get("api_key") or "").strip()
        if api_key and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _post(self, path: str, payload: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        try:
            response = self.session.post(
                f"{self.base_url}{path}",
                json=payload,
                headers=self._headers() or None,
                timeout=timeout or self.request_timeout,
            )
        except Exception as exc:
            raise XaiBrowserBridgeError(
                f"xAI 浏览器桥请求失败: {type(exc).__name__}",
                stage="browser_bridge",
                retryable=True,
            ) from exc
        try:
            data = response.json()
        except Exception as exc:
            raise XaiBrowserBridgeError(
                f"xAI 浏览器桥返回非 JSON（HTTP {response.status_code}）",
                stage="browser_bridge",
                retryable=response.status_code >= 500,
            ) from exc
        if not isinstance(data, dict):
            raise XaiBrowserBridgeError("xAI 浏览器桥返回结构异常", stage="browser_bridge")
        if not 200 <= response.status_code < 300:
            detail = str(data.get("detail") or data.get("error") or f"HTTP {response.status_code}").strip()
            raise XaiBrowserBridgeError(
                detail[:500],
                stage=str(data.get("stage") or "browser_bridge"),
                retryable=response.status_code in {408, 409, 425, 429} or response.status_code >= 500,
            )
        return data

    def start(self, *, signup_url: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "signup_url": str(signup_url),
            "timeout_s": min(180, max(30, int(self.flow_timeout))),
        }
        if self.proxy and self.proxy.lower() != "direct":
            payload["proxy"] = self.proxy
        result = self._post("/xai/session/start", payload, timeout=self.flow_timeout)
        self.session_id = str(result.get("session_id") or "").strip()
        if not self.session_id:
            raise XaiBrowserBridgeError("xAI 浏览器桥未返回 session_id", stage="browser_start")
        return result

    def _session_payload(self, **values: Any) -> dict[str, Any]:
        if not self.session_id:
            raise XaiBrowserBridgeError("xAI 浏览器会话尚未启动", stage="browser_session")
        return {"session_id": self.session_id, **values}

    def send_email_validation_code(self, email: str) -> dict[str, Any]:
        return self._post(
            "/xai/session/send-email",
            self._session_payload(email=str(email)),
            timeout=self.flow_timeout,
        )

    def verify_email_validation_code(self, email: str, code: str) -> dict[str, Any]:
        return self._post(
            "/xai/session/verify-email",
            self._session_payload(email=str(email), code=str(code)),
            timeout=self.flow_timeout,
        )

    def signup(
        self,
        *,
        email: str,
        password: str,
        code: str,
        given_name: str,
        family_name: str,
        turnstile_token: str,
        action_id: str,
        next_router_state_tree: str,
    ) -> dict[str, Any]:
        return self._post(
            "/xai/session/signup",
            self._session_payload(
                email=str(email),
                password=str(password),
                code=str(code),
                given_name=str(given_name),
                family_name=str(family_name),
                turnstile_token=str(turnstile_token),
                action_id=str(action_id),
                next_router_state_tree=str(next_router_state_tree),
            ),
            timeout=self.flow_timeout,
        )

    def authorize_device(self, *, verification_url: str, user_code: str, timeout_s: float) -> dict[str, Any]:
        return self._post(
            "/xai/session/authorize-device",
            self._session_payload(
                verification_url=str(verification_url),
                user_code=str(user_code),
                timeout_s=max(15, min(600, int(timeout_s))),
            ),
            timeout=max(self.flow_timeout, float(timeout_s) + 30),
        )

    def close(self) -> None:
        session_id, self.session_id = self.session_id, ""
        if session_id:
            try:
                self._post("/xai/session/close", {"session_id": session_id}, timeout=15)
            except Exception:
                pass
        self.session.close()


__all__ = ["XaiBrowserBridge", "XaiBrowserBridgeError"]

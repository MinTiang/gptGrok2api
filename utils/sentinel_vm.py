"""Run the official Sentinel SDK's PoW/Turnstile path in a Node VM.

The VM has no network access. Python keeps ownership of the curl_cffi session,
its TLS fingerprint, proxy, and cookies; it only gives the SDK challenge data
and receives the generated ``p``/``t`` values through stdin/stdout.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from utils.turnstile import solve_turnstile_token


SENTINEL_ORIGINS = ("https://sentinel.openai.com", "https://chatgpt.com")
SENTINEL_FALLBACK_VERSION = "20260810913b"
SENTINEL_BOOTSTRAP_PATH = "/backend-api/sentinel/sdk.js"
SENTINEL_SDK_URL_RE = re.compile(
    r"https://(?:sentinel\.openai\.com|chatgpt\.com)/sentinel/([A-Za-z0-9_-]+)/sdk\.js"
)
SENTINEL_REQ_PATH = "/backend-api/sentinel/req"
RUNNER_PATH = Path(__file__).with_name("openai_sentinel_vm.js")
MAX_SDK_BYTES = 4 * 1024 * 1024
MIN_TURNSTILE_TOKEN_LENGTH = 16
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)
DEFAULT_SEC_CH_UA = '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"'


_NODE_WRAPPER = r"""
const fs = require('fs');
const sdkFile = process.env.OPENAI_SENTINEL_SDK_FILE;
const runnerFile = process.env.OPENAI_SENTINEL_VM_RUNNER;
const timeoutMs = Number(process.env.OPENAI_SENTINEL_VM_TIMEOUT_MS || '30000');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', async () => {
  try {
    globalThis.__payload_json = input;
    globalThis.__sdk_source = fs.readFileSync(sdkFile, 'utf8');
    globalThis.__vm_done = false;
    globalThis.__vm_output_json = '';
    globalThis.__vm_error = '';
    eval(fs.readFileSync(runnerFile, 'utf8'));
    const started = Date.now();
    while (!globalThis.__vm_done) {
      if (Date.now() - started > timeoutMs) throw new Error('Sentinel VM timeout');
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    if (String(globalThis.__vm_error || '').trim()) throw new Error(String(globalThis.__vm_error));
    process.stdout.write(String(globalThis.__vm_output_json || ''));
  } catch (error) {
    process.stderr.write(String((error && error.stack) || error));
    process.exit(1);
  }
});
""".strip()


def _node_binary() -> str:
    configured = str(os.getenv("OPENAI_SENTINEL_NODE_PATH") or "").strip()
    candidates = [configured, shutil.which("node") or "", "/opt/homebrew/bin/node", "/usr/local/bin/node"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("Node.js is unavailable; set OPENAI_SENTINEL_NODE_PATH")


def _cache_file(version: str) -> Path:
    folder = Path(tempfile.gettempdir()) / "chatgpt2api-sentinel" / version
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "sdk.js"


def _ensure_sdk(session: Any, *, timeout_seconds: int) -> tuple[Path, str]:
    """返回 (sdk 缓存文件, 解析出的 sentinel 源)。

    优先 sentinel.openai.com（2026-09 起官方 SDK 迁移到这里），失败时回退
    chatgpt.com 旧域名，保持对旧部署的兼容。版本号从 bootstrap 响应中
    动态发现，两个域名的 URL 都能识别。
    """
    version = SENTINEL_FALLBACK_VERSION
    origin = SENTINEL_ORIGINS[0]
    for candidate_origin in SENTINEL_ORIGINS:
        try:
            bootstrap = session.get(
                f"{candidate_origin}{SENTINEL_BOOTSTRAP_PATH}",
                headers={
                    "accept": "*/*",
                    "accept-language": "en-US,en;q=0.9",
                    "referer": f"{candidate_origin}/",
                    "sec-fetch-dest": "script",
                    "sec-fetch-mode": "no-cors",
                    "sec-fetch-site": "same-origin",
                },
                timeout=timeout_seconds,
                verify=False,
            )
        except Exception:
            continue
        if getattr(bootstrap, "status_code", 0) != 200:
            continue
        source = str(getattr(bootstrap, "text", "") or "")
        match = SENTINEL_SDK_URL_RE.search(source)
        if match:
            version = match.group(1)
            origin = urlparse(match.group(0)).scheme + "://" + urlparse(match.group(0)).netloc
            break

    cache_file = _cache_file(version)
    if cache_file.is_file() and 0 < cache_file.stat().st_size <= MAX_SDK_BYTES:
        return cache_file, origin
    response = session.get(
        f"{origin}/sentinel/{version}/sdk.js",
        headers={
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "referer": f"{origin}/backend-api/sentinel/frame.html?sv={version}",
            "sec-fetch-dest": "script",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-site": "same-origin",
        },
        timeout=timeout_seconds,
        verify=False,
    )
    if getattr(response, "status_code", 0) != 200:
        raise RuntimeError(f"sentinel_sdk_http_{getattr(response, 'status_code', 'unknown')}")
    source = bytes(getattr(response, "content", b"") or b"")
    if not source:
        source = str(getattr(response, "text", "") or "").encode("utf-8")
    if not source or len(source) > MAX_SDK_BYTES:
        raise RuntimeError("invalid_sentinel_sdk_size")
    cache_file.write_bytes(source)
    return cache_file, origin


def _run_action(*, sdk_file: Path, payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    if not RUNNER_PATH.is_file():
        raise RuntimeError("sentinel_vm_runner_missing")
    process = subprocess.run(
        [_node_binary(), "-e", _NODE_WRAPPER],
        input=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        text=True,
        capture_output=True,
        timeout=max(10, timeout_seconds + 5),
        env={
            **os.environ,
            "OPENAI_SENTINEL_SDK_FILE": str(sdk_file),
            "OPENAI_SENTINEL_VM_RUNNER": str(RUNNER_PATH),
            "OPENAI_SENTINEL_VM_TIMEOUT_MS": str(timeout_seconds * 1000),
            "TZ": os.environ.get("OPENAI_SENTINEL_TIMEZONE", "America/Sao_Paulo"),
        },
    )
    if process.returncode != 0:
        raise RuntimeError(f"sentinel_vm_failed: {(process.stderr or process.stdout or 'unknown')[:240]}")
    try:
        result = json.loads(str(process.stdout or ""))
    except json.JSONDecodeError as exc:
        raise RuntimeError("sentinel_vm_invalid_json") from exc
    if not isinstance(result, dict):
        raise RuntimeError("sentinel_vm_invalid_result")
    return result


def _fetch_challenge(
    session: Any,
    *,
    device_id: str,
    flow: str,
    request_p: str,
    user_agent: str,
    sec_ch_ua: str,
    sdk_version: str,
    origin: str,
    timeout_seconds: int,
) -> tuple[dict[str, Any], str]:
    before_cookie = ""
    try:
        before_cookie = str(session.cookies.get("oai-sc") or "")
    except Exception:
        pass
    sec_ch_ua_platform = '"macOS"' if "Macintosh" in user_agent else '"Windows"'
    response = session.post(
        f"{origin}{SENTINEL_REQ_PATH}",
        data=json.dumps({"p": request_p, "id": device_id, "flow": flow}, separators=(",", ":")),
        headers={
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "text/plain;charset=UTF-8",
            "origin": origin,
            "referer": f"{origin}/backend-api/sentinel/frame.html?sv={sdk_version}",
            "sec-ch-ua": sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": sec_ch_ua_platform,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": user_agent,
        },
        timeout=timeout_seconds,
        verify=False,
    )
    if getattr(response, "status_code", 0) != 200:
        raise RuntimeError(f"sentinel_req_http_{getattr(response, 'status_code', 'unknown')}")
    try:
        challenge = response.json()
    except Exception as exc:
        raise RuntimeError("sentinel_req_invalid_json") from exc
    if not isinstance(challenge, dict) or not str(challenge.get("token") or "").strip():
        raise RuntimeError("sentinel_req_missing_token")
    oai_sc = _response_cookie_value(response, "oai-sc")
    if not oai_sc:
        try:
            candidate = str(session.cookies.get("oai-sc") or "")
        except Exception:
            candidate = ""
        if candidate and candidate != before_cookie:
            oai_sc = candidate
    if not oai_sc:
        raise RuntimeError("sentinel_req_missing_oai_sc")
    return challenge, oai_sc


def _response_cookie_value(response: Any, name: str) -> str:
    headers = getattr(response, "headers", None)
    raw_values: list[str] = []
    if headers is not None:
        for method_name in ("get_list", "getlist"):
            method = getattr(headers, method_name, None)
            if callable(method):
                try:
                    raw_values.extend(str(value) for value in method("set-cookie") or [])
                except Exception:
                    pass
        try:
            raw = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
            if raw:
                raw_values.append(str(raw))
        except Exception:
            pass
    pattern = re.compile(rf"(?:^|[\r\n])\s*{re.escape(name)}=([^;\r\n]+)", re.IGNORECASE)
    for raw in raw_values:
        match = pattern.search(raw)
        if match:
            return match.group(1).strip()
    return ""


def get_sentinel_token_via_vm(
    session: Any,
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
    timeout_seconds: int = 30,
    log: Callable[[str], None] | None = None,
) -> tuple[str, str, str] | None:
    """Return ``(sentinel_header, oai_sc, so_header)`` from the official SDK VM.

    The third element is the ``openai-sentinel-so-token`` envelope produced by
    running the SDK's Session Observer collector/snapshot inside the same VM
    run; it is ``""`` when the SDK version has no SO path or the snapshot
    fails. ``None`` means the whole VM path failed and the caller should fall
    back to the protocol implementation.
    """
    log = log or (lambda _message: None)
    did = str(device_id or uuid.uuid4()).strip()
    ua = str(user_agent or DEFAULT_USER_AGENT).strip()
    ch_ua = str(sec_ch_ua or DEFAULT_SEC_CH_UA).strip()
    timeout_seconds = max(10, min(45, int(timeout_seconds)))
    try:
        sdk_file, origin = _ensure_sdk(session, timeout_seconds=timeout_seconds)
        sdk_version = sdk_file.parent.name
        sdk_url = f"{origin}/sentinel/{sdk_version}/sdk.js"
        frame_url = f"{origin}/backend-api/sentinel/frame.html?sv={sdk_version}"
        requirements = _run_action(
            sdk_file=sdk_file,
            payload={
                "action": "requirements",
                "device_id": did,
                "user_agent": ua,
                "sdk_url": sdk_url,
                "frame_url": frame_url,
            },
            timeout_seconds=timeout_seconds,
        )
        request_p = str(requirements.get("request_p") or "").strip()
        if not request_p:
            raise RuntimeError("sentinel_vm_missing_requirements")
        challenge, oai_sc = _fetch_challenge(
            session,
            device_id=did,
            flow=flow,
            request_p=request_p,
            user_agent=ua,
            sec_ch_ua=ch_ua,
            sdk_version=sdk_version,
            origin=origin,
            timeout_seconds=timeout_seconds,
        )
        solved = _run_action(
            sdk_file=sdk_file,
            payload={
                "action": "solve",
                "device_id": did,
                "user_agent": ua,
                "flow": flow,
                "request_p": request_p,
                "challenge": challenge,
                "sdk_url": sdk_url,
                "frame_url": frame_url,
            },
            timeout_seconds=timeout_seconds,
        )
        final_p = str(solved.get("final_p") or "").strip()
        raw_turnstile = solved.get("t")
        turnstile = "" if raw_turnstile is None else str(raw_turnstile).strip()
        if len(turnstile) < MIN_TURNSTILE_TOKEN_LENGTH:
            turnstile_data = challenge.get("turnstile") or {}
            dx = str(turnstile_data.get("dx") or "") if isinstance(turnstile_data, dict) else ""
            protocol_turnstile = solve_turnstile_token(dx, request_p) if dx else None
            if protocol_turnstile:
                turnstile = str(protocol_turnstile).strip()
                log(f"Sentinel VM replaced malformed Turnstile value (t_len={len(turnstile)})")
        challenge_token = str(challenge.get("token") or "").strip()
        if not final_p or not turnstile or not challenge_token:
            raise RuntimeError("sentinel_vm_missing_solution")
        result = json.dumps(
            {"p": final_p, "t": turnstile, "c": challenge_token, "id": did, "flow": flow},
            separators=(",", ":"),
        )
        so_envelope = str(solved.get("so") or "").strip()
        log(
            "Sentinel VM success "
            f"(sdk={sdk_version}, p_len={len(final_p)}, t_len={len(turnstile)}, "
            f"c_len={len(challenge_token)}, so_len={len(so_envelope)}, oai_sc_len={len(oai_sc)})"
        )
        return result, oai_sc, so_envelope
    except Exception as exc:
        log(f"Sentinel VM fallback: {type(exc).__name__}: {str(exc)[:160]}")
        return None

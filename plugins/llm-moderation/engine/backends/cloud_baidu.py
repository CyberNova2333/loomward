# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Baidu AIP Content Censor driver with singleflight OAuth2 token cache."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..media_sanitizer import SanitizedPacket
from ..net_guard import HttpRequester, UpstreamError, safe_http_request
from .common import BackendResult, sanitize_category

_TOKEN_LOCK = threading.Lock()
_TOKEN_CACHE: Dict[str, Tuple[str, float]] = {}

BAIDU_OAUTH_URL = "https://aip.baidubce.com/oauth/2.0/token"
BAIDU_BASE = "https://aip.baidubce.com"


def clear_baidu_token_cache() -> None:
    with _TOKEN_LOCK:
        _TOKEN_CACHE.clear()


def _get_baidu_access_token(api_key: str, secret_key: str, *, http_requester: Optional[HttpRequester] = None) -> str:
    cache_key = hashlib.sha256(f"{api_key}:{secret_key}".encode("utf-8")).hexdigest()
    now = time.monotonic()
    with _TOKEN_LOCK:
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached[1] > now:
            return cached[0]

        query = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": api_key,
            "client_secret": secret_key,
        })
        status, _h, raw = safe_http_request(
            f"{BAIDU_OAUTH_URL}?{query}",
            method="POST",
            headers={"Accept": "application/json"},
            body=b"",
            timeout_sec=10.0,
            allow_loopback_http=False,
            http_requester=http_requester,
        )
        if status < 200 or status >= 300:
            raise UpstreamError(f"Baidu OAuth HTTP {status}", status_code=status, retryable=True)
        parsed = json.loads(raw.decode("utf-8"))
        token = parsed.get("access_token")
        if not isinstance(token, str) or not token:
            raise UpstreamError("Baidu OAuth response omitted access_token.", retryable=True)
        expires_in = int(parsed.get("expires_in", 3600))
        _TOKEN_CACHE[cache_key] = (token, now + max(60, expires_in - 60))
        return token


def _post_baidu_form(
    path: str,
    *,
    form_fields: Dict[str, str],
    access_token: str,
    endpoint_override: Optional[str],
    http_requester: Optional[HttpRequester],
) -> Dict[str, Any]:
    base = (endpoint_override or BAIDU_BASE).rstrip("/")
    url = f"{base}{path}?access_token={urllib.parse.quote(access_token, safe='')}"
    body = urllib.parse.urlencode(form_fields).encode("utf-8")
    status, _h, raw = safe_http_request(
        url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        body=body,
        timeout_sec=10.0,
        allow_loopback_http=False,
        http_requester=http_requester,
    )
    if status < 200 or status >= 300:
        raise UpstreamError(f"Baidu AIP HTTP {status}", status_code=status, retryable=(status == 429 or status >= 500))
    data = json.loads(raw.decode("utf-8"))
    if "error_code" in data and data.get("error_code") != 0:
        raise UpstreamError(f"Baidu AIP API error {data.get('error_code')}", retryable=True)
    return data


def run_baidu_aip_moderation(
    combined_text: str,
    *,
    packets: List[SanitizedPacket],
    endpoint: Optional[str],
    stage: str,
    auth: Dict[str, str],
    http_requester: Optional[HttpRequester] = None,
) -> BackendResult:
    started = time.monotonic()
    api_key = auth.get("BAIDU_API_KEY")
    secret_key = auth.get("BAIDU_SECRET_KEY")
    if not api_key or not secret_key:
        raise UpstreamError("Missing BAIDU_API_KEY or BAIDU_SECRET_KEY.", status_code=401, retryable=True)

    token = _get_baidu_access_token(api_key, secret_key, http_requester=http_requester)
    decision = "allow"
    max_score = 0.04
    categories: List[str] = []
    rule_id: Optional[str] = None
    reason = ""

    def absorb(data: Dict[str, Any], default_rule: str) -> None:
        nonlocal decision, max_score, rule_id, reason
        ctype = int(data.get("conclusionType", 1))
        for item in data.get("data") or []:
            msg = str(item.get("msg") or "").strip()
            if msg:
                categories.append(sanitize_category(msg))
            prob = item.get("probability")
            if isinstance(prob, (int, float)):
                max_score = max(max_score, float(prob))
        if ctype == 4:
            raise UpstreamError("Baidu AIP returned audit failure status (conclusionType=4).", retryable=True)
        if ctype == 2:
            decision = "block"
            max_score = max(max_score, 0.92)
            rule_id = rule_id or default_rule
            reason = reason or f"Blocked by Baidu AIP content censor ({data.get('conclusion', 'non-compliant')})."
        elif ctype == 3:
            if stage in ("input", "stream_start"):
                if decision == "allow":
                    decision = "escalate"
            else:
                decision = "block"
            max_score = max(max_score, 0.72)
            rule_id = rule_id or f"{default_rule}-SUSPECT"
            reason = reason or "Flagged suspect by Baidu AIP content censor."

    if combined_text:
        resp = _post_baidu_form(
            "/rest/2.0/solution/v1/text_censor/v2/user_defined",
            form_fields={"text": combined_text},
            access_token=token,
            endpoint_override=endpoint,
            http_requester=http_requester,
        )
        absorb(resp, "CLOUD-BAIDU-TEXT")

    for pkt in packets:
        if pkt.modality == "image" and pkt.raw_bytes:
            is_gif = pkt.raw_bytes[:6] in (b"GIF87a", b"GIF89a") or (pkt.mime_type or "").lower() == "image/gif"
            resp = _post_baidu_form(
                "/rest/2.0/solution/v1/img_censor/v2/user_defined",
                form_fields={
                    "image": base64.b64encode(pkt.raw_bytes).decode("ascii"),
                    "imgType": "1" if is_gif else "0",
                },
                access_token=token,
                endpoint_override=endpoint,
                http_requester=http_requester,
            )
            absorb(resp, "CLOUD-BAIDU-IMAGE")
        elif pkt.modality == "audio" and pkt.raw_bytes:
            mime = (pkt.mime_type or "").lower()
            if pkt.raw_bytes[:4] == b"RIFF" or "wav" in mime:
                fmt = "wav"
            elif "amr" in mime:
                fmt = "amr"
            elif "m4a" in mime:
                fmt = "m4a"
            elif "aac" in mime:
                fmt = "aac"
            else:
                fmt = "mp3"
            resp = _post_baidu_form(
                "/rest/2.0/solution/v1/voice_censor/v3/user_defined",
                form_fields={
                    "base64": base64.b64encode(pkt.raw_bytes).decode("ascii"),
                    "fmt": fmt,
                    "rate": "16000",
                },
                access_token=token,
                endpoint_override=endpoint,
                http_requester=http_requester,
            )
            absorb(resp, "CLOUD-BAIDU-VOICE")
        elif pkt.modality == "video" and pkt.raw_bytes:
            raise UpstreamError(
                "Baidu video_censor/v1/video_censor requires a reachable videoUrl; inline binary bytes are not supported.",
                status_code=400,
                retryable=False,
            )

    return BackendResult(
        decision=decision,
        score=max(0.0, min(1.0, max_score)),
        categories=list(dict.fromkeys(categories)),
        rule_id=rule_id,
        reason=reason,
        engine_name="cloud-baidu",
        latency_ms=int((time.monotonic() - started) * 1000),
    )

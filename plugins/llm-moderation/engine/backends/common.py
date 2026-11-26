# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Shared structured result and HTTP JSON helpers for moderation engine backends."""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..net_guard import HttpRequester, UpstreamError, safe_http_request


@dataclass
class BackendResult:
    decision: str  # allow | redact | escalate | block
    score: float
    categories: List[str] = field(default_factory=list)
    rule_id: Optional[str] = None
    reason: str = ""
    redacted_text: Optional[str] = None
    engine_name: str = "backend"
    latency_ms: int = 0


def normalize_chat_or_explicit_url(raw_endpoint: str, default_path: str = "/v1/chat/completions", *, kind: str = "http") -> str:
    parsed = urllib.parse.urlparse(raw_endpoint.strip())
    path = parsed.path or "/"
    if kind == "ollama" and path in ("", "/", "/api"):
        return urllib.parse.urlunparse(parsed._replace(path="/api/chat"))
    if path == "/":
        return urllib.parse.urlunparse(parsed._replace(path=default_path))
    return raw_endpoint.strip()


def post_json_safe(
    url: str,
    payload: Any,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout_sec: float = 10.0,
    allow_loopback_http: bool = False,
    allow_private_network: bool = False,
    http_requester: Optional[HttpRequester] = None,
) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    merged_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **(headers or {}),
    }
    status, _resp_headers, raw = safe_http_request(
        url,
        method="POST",
        headers=merged_headers,
        body=body,
        timeout_sec=timeout_sec,
        allow_loopback_http=allow_loopback_http,
        allow_private_network=allow_private_network,
        http_requester=http_requester,
    )
    if status < 200 or status >= 300:
        retryable = status in (408, 429) or status >= 500
        raise UpstreamError(f"Upstream HTTP {status}", status_code=status, retryable=retryable)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpstreamError("Upstream returned invalid JSON moderation payload.", status_code=status, retryable=True) from exc
    if not isinstance(parsed, dict):
        raise UpstreamError("Upstream moderation response must be a JSON object.", status_code=status, retryable=True)
    return parsed


def sanitize_category(raw: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(raw or "").strip().lower())
    if not cleaned or not cleaned[0].isalpha():
        cleaned = f"mod_{cleaned or 'general'}"
    return cleaned[:48]

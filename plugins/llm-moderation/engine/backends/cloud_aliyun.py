# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Aliyun Green (Content Security v2022-03-02 ACS3-HMAC-SHA256) multimodal moderation driver."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from ..media_sanitizer import SanitizedPacket
from ..net_guard import HttpRequester, UpstreamError, safe_http_request
from .common import BackendResult, sanitize_category

_RISK_SCORE_MAP = {"none": 0.04, "low": 0.45, "medium": 0.78, "high": 0.96}


def _sign_acs3(
    *,
    method: str,
    host: str,
    action: str,
    content_type: str,
    body_bytes: bytes,
    access_key_id: str,
    access_key_secret: str,
    version: str = "2022-03-02",
) -> Dict[str, str]:
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_hex(12)
    payload_hash = hashlib.sha256(body_bytes).hexdigest()
    headers_to_sign = {
        "content-type": content_type,
        "host": host,
        "x-acs-action": action,
        "x-acs-content-sha256": payload_hash,
        "x-acs-date": now_iso,
        "x-acs-signature-nonce": nonce,
        "x-acs-version": version,
    }
    signed_keys = sorted(headers_to_sign.keys())
    canonical_headers = "".join(f"{k}:{headers_to_sign[k]}\n" for k in signed_keys)
    signed_headers = ";".join(signed_keys)
    canonical_request = f"{method.upper()}\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    hashed_req = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = f"ACS3-HMAC-SHA256\n{hashed_req}"
    signature = hmac.new(
        access_key_secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "Accept": "application/json",
        "Content-Type": content_type,
        "host": host,
        "x-acs-action": action,
        "x-acs-content-sha256": payload_hash,
        "x-acs-date": now_iso,
        "x-acs-signature-nonce": nonce,
        "x-acs-version": version,
        "Authorization": (
            f"ACS3-HMAC-SHA256 Credential={access_key_id},"
            f"SignedHeaders={signed_headers},Signature={signature}"
        ),
    }


def _call_aliyun_action(
    endpoint_url: str,
    *,
    action: str,
    payload: Dict[str, Any],
    ak_id: str,
    ak_secret: str,
    http_requester: Optional[HttpRequester],
) -> Dict[str, Any]:
    parsed = urllib.parse.urlparse(endpoint_url)
    host = parsed.netloc
    # Official Alibaba Cloud OpenAPI V3 RPC style (2022-03-02) encodes flat RPC parameters as form-urlencoded.
    content_type = "application/x-www-form-urlencoded; charset=utf-8"
    body_bytes = urllib.parse.urlencode(payload).encode("utf-8")
    headers = _sign_acs3(
        method="POST",
        host=host,
        action=action,
        content_type=content_type,
        body_bytes=body_bytes,
        access_key_id=ak_id,
        access_key_secret=ak_secret,
    )
    status, _h, raw = safe_http_request(
        endpoint_url,
        method="POST",
        headers=headers,
        body=body_bytes,
        timeout_sec=10.0,
        allow_loopback_http=False,
        http_requester=http_requester,
    )
    if status < 200 or status >= 300:
        raise UpstreamError(f"Aliyun Green HTTP {status}", status_code=status, retryable=(status == 429 or status >= 500))
    return json.loads(raw.decode("utf-8"))


def run_aliyun_green_moderation(
    combined_text: str,
    *,
    packets: List[SanitizedPacket],
    endpoint: Optional[str],
    region: Optional[str],
    stage: str,
    auth: Dict[str, str],
    http_requester: Optional[HttpRequester] = None,
) -> BackendResult:
    started = time.monotonic()
    ak_id = auth.get("ALIYUN_ACCESS_KEY_ID")
    ak_secret = auth.get("ALIYUN_ACCESS_KEY_SECRET")
    if not ak_id or not ak_secret:
        raise UpstreamError("Missing ALIYUN_ACCESS_KEY_ID or ALIYUN_ACCESS_KEY_SECRET.", status_code=401, retryable=True)

    target_url = endpoint or f"https://green-cip.{region or 'cn-shanghai'}.aliyuncs.com/"
    max_score = 0.04
    categories: List[str] = []
    flagged_rule: Optional[str] = None
    reason = ""

    def eval_response(data: Dict[str, Any], default_rule: str) -> None:
        nonlocal max_score, flagged_rule, reason
        if int(data.get("Code", 200)) >= 400:
            raise UpstreamError(f"Aliyun Green API error code {data.get('Code')}", retryable=True)
        inner = data.get("Data") or {}
        risk_level = str(inner.get("RiskLevel") or "").lower()
        items = inner.get("Result") or inner.get("Results") or []
        for item in items if isinstance(items, list) else []:
            lbl = str(item.get("Label") or item.get("Description") or "").strip()
            if lbl and lbl.lower() not in ("nonlabel", "normal", "pass"):
                categories.append(sanitize_category(lbl))
            conf = item.get("Confidence")
            if isinstance(conf, (int, float)):
                max_score = max(max_score, float(conf) / 100.0 if conf > 1 else float(conf))
        if risk_level in _RISK_SCORE_MAP:
            max_score = max(max_score, _RISK_SCORE_MAP[risk_level])
        if risk_level in ("high", "medium") or any(str(i.get("Suggestion", "")).lower() == "block" for i in (items if isinstance(items, list) else [])):
            flagged_rule = flagged_rule or default_rule
            reason = reason or f"Flagged by Aliyun Green moderation (risk={risk_level or 'high'})."

    if combined_text:
        text_resp = _call_aliyun_action(
            target_url,
            action="TextModerationPlus",
            payload={
                "Service": "llm_query_moderation" if stage in ("input", "combined") else "llm_response_moderation",
                "ServiceParameters": json.dumps({"content": combined_text}, ensure_ascii=False),
            },
            ak_id=ak_id,
            ak_secret=ak_secret,
            http_requester=http_requester,
        )
        eval_response(text_resp, "CLOUD-ALIYUN-TEXT")

    for pkt in packets:
        if pkt.modality in ("image", "audio", "video") and pkt.raw_bytes:
            # Aliyun Green 2.0 ImageModeration/VoiceModeration/VideoModeration requires DescribeUploadToken + OSS PUT or remote imageUrl/url;
            # it does not accept inline base64 directly without uploading to Aliyun carrier OSS.
            raise UpstreamError(
                f"Aliyun Green 2.0 {pkt.modality} moderation requires OSS pre-upload (DescribeUploadToken) or remote URL; inline raw bytes are unsupported directly.",
                status_code=400,
                retryable=False,
            )

    decision = "block" if flagged_rule else "allow"
    return BackendResult(
        decision=decision,
        score=max(0.0, min(1.0, max_score)),
        categories=list(dict.fromkeys(categories)),
        rule_id=flagged_rule,
        reason=reason,
        engine_name="cloud-aliyun",
        latency_ms=int((time.monotonic() - started) * 1000),
    )

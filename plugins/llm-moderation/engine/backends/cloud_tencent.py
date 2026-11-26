# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Tencent Cloud Content Moderation (TC3-HMAC-SHA256) driver for TMS/IMS/AMS/VMS."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from ..media_sanitizer import SanitizedPacket
from ..net_guard import HttpRequester, UpstreamError, safe_http_request
from .common import BackendResult, sanitize_category


def _hmac_sha256_bytes(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sign_tc3(
    *,
    service: str,
    host: str,
    action: str,
    version: str,
    region: str,
    body_bytes: bytes,
    secret_id: str,
    secret_key: str,
) -> Dict[str, str]:
    timestamp = int(time.time())
    date = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime("%Y-%m-%d")
    hashed_payload = hashlib.sha256(body_bytes).hexdigest()
    canonical_headers = f"content-type:application/json; charset=utf-8\nhost:{host}\nx-tc-action:{action.lower()}\n"
    signed_headers = "content-type;host;x-tc-action"
    canonical_request = (
        f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
    )
    credential_scope = f"{date}/{service}/tc3_request"
    hashed_canonical = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = f"TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{hashed_canonical}"
    secret_date = _hmac_sha256_bytes(f"TC3{secret_key}".encode("utf-8"), date)
    secret_service = _hmac_sha256_bytes(secret_date, service)
    secret_signing = _hmac_sha256_bytes(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Version": version,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Region": region,
        "Authorization": (
            f"TC3-HMAC-SHA256 Credential={secret_id}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


def _resolve_tencent_url(service: str, endpoint_override: Optional[str]) -> str:
    if not endpoint_override:
        return f"https://{service}.tencentcloudapi.com/"
    parsed = urllib.parse.urlsplit(endpoint_override)
    host = parsed.hostname or ""
    for prefix in ("tms.", "ims.", "ams.", "vms."):
        if host.startswith(prefix) and not host.startswith(f"{service}."):
            new_host = f"{service}.{host[len(prefix):]}"
            netloc = f"{new_host}:{parsed.port}" if parsed.port else new_host
            return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, parsed.fragment))
    return endpoint_override


def _call_tencent_api(
    *,
    service: str,
    action: str,
    version: str,
    endpoint_override: Optional[str],
    region: str,
    payload: Dict[str, Any],
    secret_id: str,
    secret_key: str,
    http_requester: Optional[HttpRequester],
) -> Dict[str, Any]:
    url = _resolve_tencent_url(service, endpoint_override)
    host = urllib.parse.urlparse(url).netloc
    body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = _sign_tc3(
        service=service,
        host=host,
        action=action,
        version=version,
        region=region,
        body_bytes=body_bytes,
        secret_id=secret_id,
        secret_key=secret_key,
    )
    status, _h, raw = safe_http_request(
        url,
        method="POST",
        headers=headers,
        body=body_bytes,
        timeout_sec=10.0,
        allow_loopback_http=False,
        http_requester=http_requester,
    )
    if status < 200 or status >= 300:
        raise UpstreamError(f"Tencent {service} HTTP {status}", status_code=status, retryable=(status == 429 or status >= 500))
    data = json.loads(raw.decode("utf-8"))
    resp = data.get("Response") or {}
    if isinstance(resp.get("Error"), dict):
        raise UpstreamError(f"Tencent API error: {resp['Error'].get('Code')}", retryable=True)
    return resp


def run_tencent_tms_moderation(
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
    secret_id = auth.get("TENCENT_SECRET_ID")
    secret_key = auth.get("TENCENT_SECRET_KEY")
    if not secret_id or not secret_key:
        raise UpstreamError("Missing TENCENT_SECRET_ID or TENCENT_SECRET_KEY.", status_code=401, retryable=True)

    resolved_region = region or "ap-guangzhou"
    decision = "allow"
    max_score = 0.04
    categories: List[str] = []
    rule_id: Optional[str] = None
    reason = ""

    def absorb(resp: Dict[str, Any], default_rule: str) -> None:
        nonlocal decision, max_score, rule_id, reason
        suggestion = str(resp.get("Suggestion") or "Pass")
        lbl = str(resp.get("Label") or "")
        if lbl and lbl.lower() != "normal":
            categories.append(sanitize_category(lbl))
        score_raw = resp.get("Score")
        if isinstance(score_raw, (int, float)):
            max_score = max(max_score, float(score_raw) / 100.0 if score_raw > 1 else float(score_raw))
        if suggestion == "Block":
            decision = "block"
            max_score = max(max_score, 0.92)
            rule_id = rule_id or default_rule
            reason = reason or f"Blocked by Tencent moderation ({lbl or 'policy'})."
        elif suggestion == "Review":
            if stage in ("input", "stream_start"):
                if decision == "allow":
                    decision = "escalate"
            else:
                decision = "block"
            max_score = max(max_score, 0.72)
            rule_id = rule_id or f"{default_rule}-REVIEW"
            reason = reason or f"Flagged for review by Tencent moderation ({lbl or 'policy'})."

    if combined_text:
        resp = _call_tencent_api(
            service="tms",
            action="TextModeration",
            version="2020-12-29",
            endpoint_override=endpoint,
            region=resolved_region,
            payload={"Content": base64.b64encode(combined_text.encode("utf-8")).decode("ascii")},
            secret_id=secret_id,
            secret_key=secret_key,
            http_requester=http_requester,
        )
        absorb(resp, "CLOUD-TENCENT-TMS")

    for pkt in packets:
        if pkt.modality == "image" and pkt.raw_bytes:
            resp = _call_tencent_api(
                service="ims",
                action="ImageModeration",
                version="2020-12-29",
                endpoint_override=endpoint,
                region=resolved_region,
                payload={"FileContent": base64.b64encode(pkt.raw_bytes).decode("ascii")},
                secret_id=secret_id,
                secret_key=secret_key,
                http_requester=http_requester,
            )
            absorb(resp, "CLOUD-TENCENT-IMS")
        elif pkt.modality == "audio" and pkt.raw_bytes:
            mime = (pkt.mime_type or "").lower()
            audio_fmt = "wav" if (pkt.raw_bytes[:4] == b"RIFF" or "wav" in mime) else ("aac" if "aac" in mime else ("m4a" if "m4a" in mime else "mp3"))
            resp = _call_tencent_api(
                service="ams",
                action="CreateAudioModerationSyncTask",
                version="2020-12-29",
                endpoint_override=endpoint,
                region=resolved_region,
                payload={
                    "FileFormat": audio_fmt,
                    "FileContent": base64.b64encode(pkt.raw_bytes).decode("ascii"),
                    "DataId": f"loomward-ams-{int(time.time())}",
                },
                secret_id=secret_id,
                secret_key=secret_key,
                http_requester=http_requester,
            )
            absorb(resp, "CLOUD-TENCENT-AMS")
        elif pkt.modality == "video" and pkt.raw_bytes:
            raise UpstreamError(
                "Tencent VMS CreateVideoModerationTask only supports async remote URL tasks; inline raw video bytes are unsupported.",
                status_code=400,
                retryable=False,
            )

    return BackendResult(
        decision=decision,
        score=max(0.0, min(1.0, max_score)),
        categories=list(dict.fromkeys(categories)),
        rule_id=rule_id,
        reason=reason,
        engine_name="cloud-tencent",
        latency_ms=int((time.monotonic() - started) * 1000),
    )

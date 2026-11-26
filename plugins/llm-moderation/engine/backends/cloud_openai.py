# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""OpenAI Moderation Compat (omni-moderation-latest) and generic Cloud Webhook driver."""

from __future__ import annotations

import base64
import time
from typing import Any, Dict, List, Optional

from ..media_sanitizer import SanitizedPacket
from ..net_guard import HttpRequester, UpstreamError
from .common import BackendResult, post_json_safe, sanitize_category

DEFAULT_OPENAI_MODERATION_URL = "https://api.openai.com/v1/moderations"


def run_openai_or_webhook_moderation(
    combined_text: str,
    *,
    packets: List[SanitizedPacket],
    provider: str,
    endpoint: Optional[str],
    stage: str,
    auth: Dict[str, str],
    http_requester: Optional[HttpRequester] = None,
) -> BackendResult:
    started = time.monotonic()
    if provider == "webhook":
        if not endpoint:
            raise UpstreamError("Webhook moderation provider requires cloudEndpoint.", status_code=400, retryable=False)
        token = auth.get("WEBHOOK_API_KEY") or auth.get("OPENAI_API_KEY")
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        body = {
            "stage": stage,
            "text": combined_text,
            "modalities": [
                {
                    "modality": p.modality,
                    "mimeType": p.mime_type,
                    "base64": base64.b64encode(p.raw_bytes).decode("ascii") if p.raw_bytes else None,
                }
                for p in packets
                if p.modality != "text"
            ],
        }
        data = post_json_safe(
            endpoint,
            body,
            headers=headers,
            timeout_sec=10.0,
            allow_loopback_http=False,
            http_requester=http_requester,
        )
        decision = data.get("decision") or ("block" if data.get("flagged") else "allow")
        if decision not in ("allow", "redact", "escalate", "block"):
            decision = "block"
        return BackendResult(
            decision=decision,
            score=float(data.get("score", 0.9 if decision != "allow" else 0.05)),
            categories=[sanitize_category(c) for c in (data.get("categories") or [])[:16]],
            rule_id=str(data.get("ruleId") or "CLOUD-WEBHOOK") if decision != "allow" else None,
            reason=str(data.get("reason") or ("Blocked by cloud webhook moderation." if decision != "allow" else "")),
            redacted_text=data.get("redactedPayload") if isinstance(data.get("redactedPayload"), str) else None,
            engine_name="cloud-webhook",
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    api_key = auth.get("OPENAI_API_KEY")
    if not api_key:
        raise UpstreamError("Missing OPENAI_API_KEY in Trust plugin:secrets@1 store.", status_code=401, retryable=True)
    target_url = endpoint or DEFAULT_OPENAI_MODERATION_URL
    inputs: List[Dict[str, Any]] = []
    if combined_text:
        inputs.append({"type": "text", "text": combined_text})
    unsupported_binary = False
    for pkt in packets:
        if pkt.modality == "image" and pkt.raw_bytes and not (pkt.mime_type or "").endswith("svg+xml"):
            mime = pkt.mime_type or "image/png"
            b64 = base64.b64encode(pkt.raw_bytes).decode("ascii")
            inputs.append({"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}})
        elif pkt.raw_bytes and pkt.modality in ("audio", "video"):
            unsupported_binary = True
    if not inputs:
        if unsupported_binary:
            raise UpstreamError(
                "OpenAI /v1/moderations only supports text and non-SVG image inputs; inline audio/video bytes require upstream transcription or frame extraction.",
                status_code=400,
                retryable=False,
            )
        inputs.append({"type": "text", "text": "(empty)"})

    data = post_json_safe(
        target_url,
        {"model": "omni-moderation-latest", "input": inputs},
        headers={"Authorization": f"Bearer {api_key}"},
        timeout_sec=10.0,
        allow_loopback_http=False,
        http_requester=http_requester,
    )
    results = data.get("results") or []
    first = results[0] if isinstance(results, list) and results else {}
    flagged = bool(first.get("flagged", False))
    scores = first.get("category_scores") or {}
    max_score = max([float(v) for v in scores.values() if isinstance(v, (int, float))], default=(0.94 if flagged else 0.04))
    cats = [sanitize_category(k) for k, v in (first.get("categories") or {}).items() if v]
    return BackendResult(
        decision="block" if flagged else "allow",
        score=max(0.0, min(1.0, max_score)),
        categories=cats,
        rule_id="CLOUD-OPENAI-MOD" if flagged else None,
        reason="Flagged unsafe by OpenAI omni-moderation API." if flagged else "",
        engine_name="cloud-openai",
        latency_ms=int((time.monotonic() - started) * 1000),
    )

# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Zero-Tool Sandbox Prompt Inducement Canary Probe orchestration."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from .backends.small_model import query_canary_small_model
from .net_guard import HttpRequester
from .policy_eval import detect_canary_inducement


@dataclass(frozen=True)
class CanaryProbeOutcome:
    tested: bool
    canary_induced: bool
    canary_model: str
    output_risk_score: float
    rule_id: Optional[str]
    reason: str
    latency_ms: int


def run_inducement_canary(
    payload_text: str,
    *,
    canary_cfg: Dict[str, Any],
    auth: Optional[Dict[str, str]] = None,
    guard_rescore_fn: Optional[Callable[[str], Tuple[float, bool]]] = None,
    http_requester: Optional[HttpRequester] = None,
) -> CanaryProbeOutcome:
    started = time.monotonic()
    nonce = secrets.token_hex(12)
    model_name = str(canary_cfg.get("model") or "qwen2.5-0.5b")

    # Canary execution stays strictly isolated: zero tools, zero session memory, nonce-fenced target.
    canary_reaction = query_canary_small_model(
        payload_text,
        nonce=nonce,
        canary_cfg=canary_cfg,
        auth=auth,
        http_requester=http_requester,
    )

    extra_score = 0.0
    extra_unsafe = False
    if guard_rescore_fn is not None and canary_reaction:
        extra_score, extra_unsafe = guard_rescore_fn(canary_reaction)

    induced, risk_score, rule_id, reason = detect_canary_inducement(
        canary_reaction,
        nonce,
        extra_guard_score=extra_score,
        extra_guard_unsafe=extra_unsafe,
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)

    return CanaryProbeOutcome(
        tested=True,
        canary_induced=induced,
        canary_model=model_name,
        output_risk_score=round(float(risk_score), 4),
        rule_id=rule_id,
        reason=reason,
        latency_ms=elapsed_ms,
    )

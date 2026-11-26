# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Moderation router orchestrating Local Guard, Canary Inducement Probe, Cloud Safety APIs, and policyProfile fallbacks."""

from __future__ import annotations

import atexit
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from .backends.cloud_aliyun import run_aliyun_green_moderation
from .backends.cloud_baidu import run_baidu_aip_moderation
from .backends.cloud_openai import run_openai_or_webhook_moderation
from .backends.cloud_tencent import run_tencent_tms_moderation
from .backends.common import BackendResult
from .backends.local_guard import run_local_guard
from .canary_probe import CanaryProbeOutcome, run_inducement_canary
from .media_sanitizer import MediaValidationError, SanitizedPacket, sanitize_modality_packets
from .net_guard import HttpRequester, SecurityPolicyError, UpstreamError
from .policy_eval import evaluate_local_policy

_SHADOW_LOCK = threading.Lock()
_SHADOW_STATS: Dict[str, int] = {"runs": 0, "induced": 0, "errors": 0}
_SHADOW_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="lw-mod-shadow")
atexit.register(lambda: _SHADOW_POOL.shutdown(wait=False, cancel_futures=True))


def get_shadow_stats() -> Dict[str, int]:
    with _SHADOW_LOCK:
        return dict(_SHADOW_STATS)


def _extract_combined_text(raw_payload: Any, packets: List[SanitizedPacket]) -> str:
    parts: List[str] = []
    for pkt in packets:
        if pkt.modality == "text" and pkt.inline_text:
            parts.append(pkt.inline_text)
        elif pkt.extracted_text:
            parts.append(pkt.extracted_text)
    if not parts and raw_payload not in (None, {}, "", []):
        if isinstance(raw_payload, str):
            parts.append(raw_payload)
        elif isinstance(raw_payload, dict):
            if isinstance(raw_payload.get("text"), str):
                parts.append(raw_payload["text"])
            elif raw_payload.get("inputDigest") or raw_payload.get("result"):
                import json
                parts.append(json.dumps(raw_payload, ensure_ascii=False)[:12000])
            else:
                import json
                parts.append(json.dumps(raw_payload, ensure_ascii=False)[:12000])
    return "\n".join(parts).strip()


def _canary_has_target(canary_cfg: Dict[str, Any]) -> bool:
    return bool(canary_cfg.get("endpoint") or canary_cfg.get("kind") == "ollama")


def _schedule_shadow_canary(
    text: str,
    *,
    canary_cfg: Dict[str, Any],
    auth: Dict[str, str],
    guard_cfg: Dict[str, Any],
    http_requester: Optional[HttpRequester],
) -> None:
    if not text or not _canary_has_target(canary_cfg):
        return

    def task() -> None:
        try:
            outcome = run_inducement_canary(
                text,
                canary_cfg=canary_cfg,
                auth=auth,
                guard_rescore_fn=lambda reaction: _rescore_with_guard(reaction, guard_cfg, auth, http_requester),
                http_requester=http_requester,
            )
            with _SHADOW_LOCK:
                _SHADOW_STATS["runs"] += 1
                if outcome.canary_induced:
                    _SHADOW_STATS["induced"] += 1
        except Exception:
            with _SHADOW_LOCK:
                _SHADOW_STATS["errors"] += 1

    try:
        _SHADOW_POOL.submit(task)
    except RuntimeError:
        pass


def _rescore_with_guard(
    reaction_text: str,
    guard_cfg: Dict[str, Any],
    auth: Dict[str, str],
    http_requester: Optional[HttpRequester],
) -> Tuple[float, bool]:
    try:
        res = run_local_guard(
            reaction_text,
            packets=[],
            stage="output",
            guard_cfg=guard_cfg,
            auth=auth,
            http_requester=http_requester,
        )
        return res.score, res.decision in ("block", "escalate")
    except Exception:
        ev = evaluate_local_policy(reaction_text, stage="output")
        return ev.score, ev.decision == "block"


def _dispatch_cloud_backend(
    combined_text: str,
    *,
    packets: List[SanitizedPacket],
    config: Dict[str, Any],
    stage: str,
    auth: Dict[str, str],
    http_requester: Optional[HttpRequester],
) -> BackendResult:
    if config.get("cloudOptIn") is not True:
        raise UpstreamError("Cloud moderation disabled because cloudOptIn is false.", status_code=403, retryable=True)
    provider = str(config.get("cloudProvider") or "openai-compat")
    endpoint = config.get("cloudEndpoint")
    region = config.get("cloudRegion")
    if provider in ("openai-compat", "webhook"):
        return run_openai_or_webhook_moderation(
            combined_text,
            packets=packets,
            provider=provider,
            endpoint=endpoint,
            stage=stage,
            auth=auth,
            http_requester=http_requester,
        )
    if provider == "aliyun-green":
        return run_aliyun_green_moderation(
            combined_text,
            packets=packets,
            endpoint=endpoint,
            region=region,
            stage=stage,
            auth=auth,
            http_requester=http_requester,
        )
    if provider == "tencent-tms":
        return run_tencent_tms_moderation(
            combined_text,
            packets=packets,
            endpoint=endpoint,
            region=region,
            stage=stage,
            auth=auth,
            http_requester=http_requester,
        )
    if provider == "baidu-aip":
        return run_baidu_aip_moderation(
            combined_text,
            packets=packets,
            endpoint=endpoint,
            stage=stage,
            auth=auth,
            http_requester=http_requester,
        )
    raise UpstreamError(f"Unsupported cloudProvider: {provider}", status_code=400, retryable=False)


def _format_verdict(
    result: BackendResult,
    *,
    request_id: str,
    stage: str,
    inducement: Optional[CanaryProbeOutcome] = None,
    guard_primary_score: Optional[float] = None,
    fail_closed: Optional[bool] = None,
    fallback_used: bool = False,
) -> Dict[str, Any]:
    verdict: Dict[str, Any] = {
        "protocolVersion": 2,
        "decision": result.decision,
        "categories": result.categories[:32],
        "score": round(max(0.0, min(1.0, float(result.score))), 4),
        "latencyMs": max(0, int(result.latency_ms)),
    }
    if result.rule_id:
        verdict["ruleId"] = result.rule_id
    if result.reason:
        verdict["reason"] = result.reason[:240]
    if request_id:
        verdict["requestId"] = request_id
    if fail_closed is not None:
        verdict["failClosed"] = fail_closed
    if result.decision == "redact":
        verdict["redactedPayload"] = result.redacted_text if result.redacted_text is not None else "[REDACTED]"
    if inducement is not None:
        ind_obj: Dict[str, Any] = {
            "tested": inducement.tested,
            "canaryInduced": inducement.canary_induced,
            "canaryModel": inducement.canary_model,
            "canaryOutputRiskScore": inducement.output_risk_score,
        }
        if guard_primary_score is not None:
            ind_obj["guardPrimaryScore"] = round(max(0.0, min(1.0, float(guard_primary_score))), 4)
        verdict["inducement"] = ind_obj
    if result.decision == "redact" and stage in ("input", "stream_start"):
        verdict["decision"] = "block"
        verdict.pop("redactedPayload", None)
    if result.decision == "escalate" and stage not in ("input", "stream_start"):
        verdict["decision"] = "block"

    return {
        "verdict": verdict,
        "telemetry": {
            "engineUsed": result.engine_name,
            "fallbackUsed": fallback_used,
            "shadowStats": get_shadow_stats(),
        },
    }


def _handle_all_failed(
    *,
    stage: str,
    request_id: str,
    config: Dict[str, Any],
    error_reason: str,
    started: float,
) -> Dict[str, Any]:
    fallback_cfg = config.get("fallback") or {}
    profile = str(config.get("policyProfile") or "balanced")
    elapsed = int((time.monotonic() - started) * 1000)

    if stage in ("input", "stream_start"):
        on_fail_input = str(fallback_cfg.get("onAllFailedInput") or ("block" if profile == "strict" else "escalate"))
        decision = "block" if (profile == "strict" or on_fail_input == "block") else "escalate"
        return _format_verdict(
            BackendResult(
                decision=decision,
                score=0.95 if decision == "block" else 0.75,
                categories=["moderation.fail_closed"],
                rule_id="MODERATION-ALL-ENGINES-FAILED",
                reason=f"Moderation engines failed ({error_reason}); applying {decision}.",
                engine_name="fallback-terminal",
                latency_ms=elapsed,
            ),
            request_id=request_id,
            stage=stage,
            fail_closed=True,
            fallback_used=True,
        )

    on_fail_output = str(fallback_cfg.get("onAllFailedOutput") or "block")
    if profile != "strict" and on_fail_output == "warn-experimental":
        return _format_verdict(
            BackendResult(
                decision="allow",
                score=0.5,
                categories=["moderation.degraded_allow"],
                rule_id="MODERATION-EXPERIMENTAL-WARN",
                reason=f"Output allowed under experimental-resilient warning ({error_reason}).",
                engine_name="fallback-experimental-warn",
                latency_ms=elapsed,
            ),
            request_id=request_id,
            stage=stage,
            fail_closed=False,
            fallback_used=True,
        )

    return _format_verdict(
        BackendResult(
            decision="block",
            score=0.98,
            categories=["moderation.fail_closed"],
            rule_id="MODERATION-OUTPUT-FAIL-CLOSED",
            reason=f"Output blocked fail-closed after moderation failure ({error_reason}).",
            engine_name="fallback-terminal",
            latency_ms=elapsed,
        ),
        request_id=request_id,
        stage=stage,
        fail_closed=True,
        fallback_used=True,
    )


def evaluate_inspection(
    *,
    inspect_request: Dict[str, Any],
    config: Dict[str, Any],
    auth: Optional[Dict[str, str]] = None,
    workspace_roots: Optional[List[str]] = None,
    http_requester: Optional[HttpRequester] = None,
) -> Dict[str, Any]:
    started = time.monotonic()
    stage = str(inspect_request.get("stage") or "input")
    request_id = str(inspect_request.get("requestId") or "")
    mode = str(config.get("mode") or "local-only")
    policy_profile = str(config.get("policyProfile") or "experimental-resilient")
    guard_cfg = config.get("localGuard") or {}
    canary_cfg = config.get("canary") or {}
    thresh = config.get("thresholds") or {}
    gray_low = float(thresh.get("grayZoneLow", 0.25))
    gray_high = float(thresh.get("grayZoneHigh", 0.80))
    auth_map = dict(auth or {})

    allow_remote_cloud = bool(config.get("cloudOptIn") is True and mode in ("cloud-first", "hybrid-tiered"))
    try:
        packets = sanitize_modality_packets(
            inspect_request.get("modalityPackets"),
            media_cfg=config.get("media") or {},
            workspace_roots=list(workspace_roots or []),
            allow_remote_cloud=allow_remote_cloud,
        )
    except MediaValidationError as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        return _format_verdict(
            BackendResult(
                decision="block",
                score=0.98,
                categories=["moderation.fail_closed" if exc.fail_closed else "media.unsafe"],
                rule_id=exc.rule_id,
                reason=str(exc),
                engine_name="media-sanitizer",
                latency_ms=elapsed,
            ),
            request_id=request_id,
            stage=stage,
            fail_closed=exc.fail_closed,
        )

    combined_text = _extract_combined_text(inspect_request.get("payload"), packets)

    def try_local_guard() -> BackendResult:
        return run_local_guard(
            combined_text,
            packets=packets,
            stage=stage,
            guard_cfg=guard_cfg,
            auth=auth_map,
            http_requester=http_requester,
        )

    def try_cloud() -> BackendResult:
        return _dispatch_cloud_backend(
            combined_text,
            packets=packets,
            config=config,
            stage=stage,
            auth=auth_map,
            http_requester=http_requester,
        )

    def try_canary(guard_res: Optional[BackendResult]) -> Optional[CanaryProbeOutcome]:
        return run_inducement_canary(
            combined_text,
            canary_cfg=canary_cfg,
            auth=auth_map,
            guard_rescore_fn=lambda reaction: _rescore_with_guard(reaction, guard_cfg, auth_map, http_requester),
            http_requester=http_requester,
        )

    def run_fallback_chain(skip_target: str, initial_error: str) -> Dict[str, Any]:
        chain = list((config.get("fallback") or {}).get("chain") or [])
        last_err = initial_error
        for target in chain:
            if target == skip_target:
                continue
            try:
                if target == "local-guard":
                    res = try_local_guard()
                    return _format_verdict(res, request_id=request_id, stage=stage, fallback_used=True)
                if target == "cloud":
                    res = try_cloud()
                    return _format_verdict(res, request_id=request_id, stage=stage, fallback_used=True)
            except (UpstreamError, SecurityPolicyError) as err:
                last_err = str(err)
        return _handle_all_failed(
            stage=stage,
            request_id=request_id,
            config=config,
            error_reason=last_err,
            started=started,
        )

    # Mode: cloud-first
    if mode == "cloud-first":
        try:
            cloud_res = try_cloud()
            return _format_verdict(cloud_res, request_id=request_id, stage=stage)
        except SecurityPolicyError as sec_err:
            elapsed = int((time.monotonic() - started) * 1000)
            return _format_verdict(
                BackendResult(
                    decision="block",
                    score=0.99,
                    categories=["moderation.ssrf_blocked"],
                    rule_id="MODERATION-SSRF-BLOCKED",
                    reason=str(sec_err),
                    engine_name="net-guard",
                    latency_ms=elapsed,
                ),
                request_id=request_id,
                stage=stage,
                fail_closed=True,
            )
        except UpstreamError as cloud_err:
            return run_fallback_chain("cloud", str(cloud_err))

    # Primary Local Guard run (for local-only, guard-plus-canary, and hybrid-tiered)
    try:
        guard_res = try_local_guard()
    except UpstreamError as guard_err:
        return run_fallback_chain("local-guard", str(guard_err))

    # Fast deny/redact from Local Guard
    if guard_res.decision in ("block", "redact") or guard_res.score >= gray_high:
        final_decision = "block" if guard_res.decision == "allow" else guard_res.decision
        return _format_verdict(
            BackendResult(
                decision=final_decision,
                score=guard_res.score,
                categories=guard_res.categories or ["guard.unsafe"],
                rule_id=guard_res.rule_id or "GUARD-SCORE-HIGH",
                reason=guard_res.reason or "Blocked by local Guard safety score threshold.",
                redacted_text=guard_res.redacted_text,
                engine_name=guard_res.engine_name,
                latency_ms=guard_res.latency_ms,
            ),
            request_id=request_id,
            stage=stage,
        )

    # Mode: local-only
    if mode == "local-only":
        return _format_verdict(guard_res, request_id=request_id, stage=stage)

    # Mode: guard-plus-canary
    if mode == "guard-plus-canary":
        in_gray_zone = gray_low <= guard_res.score <= gray_high
        shadow_mode = bool(canary_cfg.get("shadowMode", True))
        should_sync_canary = bool(canary_cfg.get("enabled", True)) and (
            not shadow_mode or in_gray_zone or stage in ("input", "stream_start")
        )
        # Note: if stage is safe fast-path below gray_low AND shadow_mode is True on output chunks, run async shadow only to preserve low latency.
        if stage in ("output", "stream_chunk", "stream_end") and shadow_mode and not in_gray_zone:
            should_sync_canary = False
            _schedule_shadow_canary(
                combined_text,
                canary_cfg=canary_cfg,
                auth=auth_map,
                guard_cfg=guard_cfg,
                http_requester=http_requester,
            )

        if should_sync_canary and _canary_has_target(canary_cfg):
            try:
                canary_out = try_canary(guard_res)
                if canary_out and canary_out.canary_induced:
                    decision = (
                        "block"
                        if (policy_profile == "strict" or stage not in ("input", "stream_start") or not canary_cfg.get("escalateOnInduced", True))
                        else "escalate"
                    )
                    return _format_verdict(
                        BackendResult(
                            decision=decision,
                            score=max(guard_res.score, canary_out.output_risk_score),
                            categories=["prompt.inducement", *guard_res.categories],
                            rule_id=canary_out.rule_id or "CANARY-INDUCED",
                            reason=canary_out.reason or "Canary small model was induced by hidden payload instruction.",
                            engine_name="guard+canary-inducement",
                            latency_ms=guard_res.latency_ms + canary_out.latency_ms,
                        ),
                        request_id=request_id,
                        stage=stage,
                        inducement=canary_out,
                        guard_primary_score=guard_res.score,
                    )
                return _format_verdict(
                    guard_res,
                    request_id=request_id,
                    stage=stage,
                    inducement=canary_out,
                    guard_primary_score=guard_res.score,
                )
            except UpstreamError as canary_err:
                unavail_policy = str(canary_cfg.get("onCanaryUnavailable") or "ignore-if-guard-confident")
                if unavail_policy == "ignore-if-guard-confident" and not in_gray_zone and policy_profile != "strict":
                    return _format_verdict(guard_res, request_id=request_id, stage=stage, fallback_used=True)
                dec = "block" if (unavail_policy == "block" or policy_profile == "strict" or stage not in ("input", "stream_start")) else "escalate"
                return _format_verdict(
                    BackendResult(
                        decision=dec,
                        score=max(guard_res.score, 0.72),
                        categories=["canary.unavailable"],
                        rule_id="CANARY-UNAVAILABLE",
                        reason=f"Canary probe unavailable ({canary_err}); policy applied {dec}.",
                        engine_name="guard+canary-fallback",
                        latency_ms=int((time.monotonic() - started) * 1000),
                    ),
                    request_id=request_id,
                    stage=stage,
                    fail_closed=(dec == "block"),
                    fallback_used=True,
                )

        if not canary_cfg.get("endpoint") and shadow_mode:
            pass
        return _format_verdict(guard_res, request_id=request_id, stage=stage)

    # Mode: hybrid-tiered
    if mode == "hybrid-tiered":
        in_gray_zone = gray_low <= guard_res.score <= gray_high
        has_media = any(p.modality != "text" for p in packets)
        if not in_gray_zone and not has_media:
            if canary_cfg.get("enabled") and _canary_has_target(canary_cfg):
                _schedule_shadow_canary(
                    combined_text,
                    canary_cfg=canary_cfg,
                    auth=auth_map,
                    guard_cfg=guard_cfg,
                    http_requester=http_requester,
                )
            return _format_verdict(guard_res, request_id=request_id, stage=stage)

        if config.get("cloudOptIn") is True:
            try:
                cloud_res = try_cloud()
                return _format_verdict(cloud_res, request_id=request_id, stage=stage)
            except SecurityPolicyError as sec_err:
                return _format_verdict(
                    BackendResult(
                        decision="block",
                        score=0.99,
                        categories=["moderation.ssrf_blocked"],
                        rule_id="MODERATION-SSRF-BLOCKED",
                        reason=str(sec_err),
                        engine_name="net-guard",
                        latency_ms=int((time.monotonic() - started) * 1000),
                    ),
                    request_id=request_id,
                    stage=stage,
                    fail_closed=True,
                )
            except UpstreamError:
                pass

        if canary_cfg.get("enabled") and _canary_has_target(canary_cfg):
            try:
                canary_out = try_canary(guard_res)
                if canary_out and canary_out.canary_induced:
                    dec = "block" if (policy_profile == "strict" or stage not in ("input", "stream_start")) else "escalate"
                    return _format_verdict(
                        BackendResult(
                            decision=dec,
                            score=max(guard_res.score, canary_out.output_risk_score),
                            categories=["prompt.inducement"],
                            rule_id=canary_out.rule_id or "CANARY-INDUCED",
                            reason=canary_out.reason,
                            engine_name="hybrid+canary",
                            latency_ms=int((time.monotonic() - started) * 1000),
                        ),
                        request_id=request_id,
                        stage=stage,
                        inducement=canary_out,
                        guard_primary_score=guard_res.score,
                    )
                return _format_verdict(guard_res, request_id=request_id, stage=stage, inducement=canary_out, guard_primary_score=guard_res.score)
            except UpstreamError:
                pass

        return _format_verdict(guard_res, request_id=request_id, stage=stage, fallback_used=True)

    return _handle_all_failed(
        stage=stage,
        request_id=request_id,
        config=config,
        error_reason=f"Unknown moderation mode {mode}",
        started=started,
    )

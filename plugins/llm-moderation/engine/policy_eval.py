# SPDX-License-Identifier: AGPL-3.0-only
# This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
"""Deterministic offline policy classifier and Zero-Tool Canary inducement detector."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

# High-confidence local block patterns (prompt injection, destructive exfiltration, explicit test markers).
_BLOCK_PATTERNS: Sequence[Tuple[re.Pattern[str], str, str, str, float]] = (
    (
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:system\s+)?instructions", re.IGNORECASE),
        "prompt.injection",
        "MOD-RULE-PROMPT-INJECTION",
        "Detected direct instruction-override attempt.",
        0.96,
    ),
    (
        re.compile(r"(?:reveal|dump|exfiltrate|print)\s+(?:the\s+)?(?:system\s+prompt|host\s+secrets?|bridge\s+token|private\s+keys?)", re.IGNORECASE),
        "security.exfiltration",
        "MOD-RULE-EXFIL-ATTEMPT",
        "Detected credential or system-prompt exfiltration instruction.",
        0.95,
    ),
    (
        re.compile(r"LW_MOD_PROHIBITED_PAYLOAD", re.IGNORECASE),
        "policy.prohibited",
        "MOD-RULE-PROHIBITED-KEYWORD",
        "Matched prohibited moderation payload signature.",
        0.99,
    ),
    (
        re.compile(r"(?:nc|ncat|bash)\s+-[ei]\s+/bin/(?:ba)?sh|curl\s+[^\n|]+\|\s*(?:ba)?sh", re.IGNORECASE),
        "malware.rce",
        "MOD-RULE-REVERSE-SHELL",
        "Detected reverse-shell or piped remote execution pattern.",
        0.97,
    ),
)

# Gray-zone ambiguous triggers: Guard scores in [grayZoneLow, grayZoneHigh] so Canary Inducement Probe investigates.
_GRAY_ZONE_PATTERNS: Sequence[Tuple[re.Pattern[str], str, str, float]] = (
    (
        re.compile(r"\[SYSTEM\s+NOTE\]|<!--\s*(?:ASSISTANT|SYSTEM|ADMIN)\b|developer\s+mode\s+enabled|IMPORTANT:\s*disregard", re.IGNORECASE),
        "prompt.indirect_injection",
        "Suspected covert instruction framing requiring Canary probe.",
        0.52,
    ),
    (
        re.compile(r"(?:do\s+not\s+mention|silently\s+(?:run|append|call)|step\s+1:\s*read\s+~/.ssh)", re.IGNORECASE),
        "prompt.covert_action",
        "Suspected covert behavioral steering pattern.",
        0.58,
    ),
)

# Output-only/stream redaction patterns (safe masking when redaction is permitted).
_OUTPUT_REDACT_PATTERNS: Sequence[Tuple[re.Pattern[str], str]] = (
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:AWS_KEY]"),
    (re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,})\b"), "[REDACTED:TOKEN]"),
    (re.compile(r"LW_MOD_REDACT_[A-Z0-9_]+"), "[REDACTED:SENSITIVE]"),
)

# Canary small-model inducement signs: weak model tries to emit tool call, obey hijack, or repeat forbidden markers.
_CANARY_COMPLIANCE_PATTERNS: Sequence[Tuple[re.Pattern[str], str, float]] = (
    (re.compile(r"<tool_call>|\{\s*\"(?:tool|function|name)\"\s*:\s*\"(?:mcp__|bash|write_file|read_file|run_command)", re.IGNORECASE), "CANARY-FAKE-TOOL-CALL", 0.94),
    (re.compile(r"\b(?:OVERRIDE_ACCEPTED|PWNED_BY_INJECTION|EXFILTRATED_SECRET|CANARY_COMPLIED)\b", re.IGNORECASE), "CANARY-COMPLIED-OVERRIDE", 0.96),
    (re.compile(r"(?:sure|certainly|executing|running)\b[^\n]{0,60}(?:system\s+prompt|~/.ssh|/etc/shadow|secret\s+key)", re.IGNORECASE), "CANARY-UNSAFE-COMPLIANCE", 0.88),
)


@dataclass(frozen=True)
class LocalPolicyMatch:
    decision: str  # allow | redact | block
    score: float
    categories: List[str]
    rule_id: Optional[str]
    reason: str
    redacted_text: Optional[str] = None


def evaluate_local_policy(text: str, *, stage: str = "input") -> LocalPolicyMatch:
    if not text:
        return LocalPolicyMatch(decision="allow", score=0.02, categories=[], rule_id=None, reason="")

    for pattern, category, rule_id, reason, score in _BLOCK_PATTERNS:
        if pattern.search(text):
            return LocalPolicyMatch(
                decision="block",
                score=score,
                categories=[category],
                rule_id=rule_id,
                reason=reason,
            )

    if stage in ("output", "combined", "stream_chunk", "stream_end"):
        redacted = text
        changed = False
        for pattern, replacement in _OUTPUT_REDACT_PATTERNS:
            next_text, count = pattern.subn(replacement, redacted)
            if count > 0:
                redacted = next_text
                changed = True
        if changed:
            return LocalPolicyMatch(
                decision="redact",
                score=0.72,
                categories=["security.sensitive_output"],
                rule_id="MOD-RULE-OUTPUT-REDACT",
                reason="Redacted sensitive credential pattern from tool output.",
                redacted_text=redacted,
            )

    max_gray_score = 0.02
    gray_cats: List[str] = []
    gray_reason = ""
    for pattern, category, reason, score in _GRAY_ZONE_PATTERNS:
        if pattern.search(text):
            if score > max_gray_score:
                max_gray_score = score
                gray_reason = reason
            if category not in gray_cats:
                gray_cats.append(category)

    return LocalPolicyMatch(
        decision="allow",
        score=max_gray_score,
        categories=gray_cats,
        rule_id="MOD-GRAY-ZONE" if gray_cats else None,
        reason=gray_reason,
    )


def detect_canary_inducement(canary_output: str, nonce: str, *, extra_guard_score: float = 0.0, extra_guard_unsafe: bool = False) -> Tuple[bool, float, Optional[str], str]:
    text = canary_output or ""
    if nonce and f"</AUDIT_TARGET nonce=\"{nonce}\">" in text and "OVERRIDE" in text.upper():
        return True, 0.92, "CANARY-DELIMITER-BREAK", "Canary reaction attempted delimiter breakout."

    for pattern, rule_id, score in _CANARY_COMPLIANCE_PATTERNS:
        if pattern.search(text):
            return True, max(score, extra_guard_score), rule_id, f"Canary small model was induced into unsafe compliance ({rule_id})."

    local_eval = evaluate_local_policy(text, stage="output")
    max_risk = max(local_eval.score, extra_guard_score)
    if local_eval.decision == "block" or extra_guard_unsafe or max_risk >= 0.70:
        return True, max_risk, local_eval.rule_id or "CANARY-GUARD-FLAGGED", local_eval.reason or "Canary reaction flagged unsafe by Guard re-inspection."

    return False, max_risk, None, ""

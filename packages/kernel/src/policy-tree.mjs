// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

const EFFECT_PRECEDENCE = Object.freeze({
  deny: 3,
  escalate: 2,
  allow: 1,
});

function matchSegments(pattern, target) {
  if (pattern.length === 1 && pattern[0] === '*') return 10;
  let score = 0;
  for (let i = 0; i < pattern.length; i++) {
    const seg = pattern[i];
    if (seg === '*') {
      if (i === pattern.length - 1) return score + 10;
      if (i >= target.length) return -1;
      score += 10;
      continue;
    }
    if (i >= target.length || seg !== target[i]) return -1;
    score += 100;
  }
  return pattern.length === target.length ? score : -1;
}

export function matchPermissionNode(pattern, targetNode) {
  if (typeof pattern !== 'string' || typeof targetNode !== 'string') return -1;
  if (pattern === targetNode) return 10_000 + pattern.length;
  if (pattern === '*') return 1;

  const pColon = pattern.indexOf(':');
  const tColon = targetNode.indexOf(':');
  if (pColon === -1 || tColon === -1) return -1;

  const actionScore = matchSegments(pattern.slice(0, pColon).split('.'), targetNode.slice(0, tColon).split('.'));
  if (actionScore < 0) return -1;

  const pRes = pattern.slice(pColon + 1);
  const tRes = targetNode.slice(tColon + 1);
  if (pRes === '*') return actionScore + 5;

  const pHash = pRes.indexOf('#');
  const tHash = tRes.indexOf('#');
  const pTarget = pHash === -1 ? pRes : pRes.slice(0, pHash);
  const tTarget = tHash === -1 ? tRes : tRes.slice(0, tHash);
  const pSub = pHash === -1 ? undefined : pRes.slice(pHash + 1);
  const tSub = tHash === -1 ? undefined : tRes.slice(tHash + 1);

  const targetScore = pTarget === '*' ? 10 : matchSegments(pTarget.split(':'), tTarget.split(':'));
  if (targetScore < 0) return -1;

  if (pSub === undefined && tSub === undefined) return actionScore + targetScore + 50;
  if (pSub === undefined || tSub === undefined) {
    return pSub === '*' ? actionScore + targetScore + 5 : -1;
  }
  const subScore = pSub === tSub ? 120 : pSub === '*' ? 15 : -1;
  if (subScore < 0) return -1;
  return actionScore + targetScore + subScore;
}

export function matchesCondition(condition, subject = {}, request = {}) {
  if (!condition) return true;
  if (condition.signedOnly && !subject.signed) return false;
  if (condition.outOfProcessOnly && subject.executionBoundary !== 'out-of-process') return false;
  if (condition.trustLevels && !condition.trustLevels.includes(subject.trustLevel)) return false;
  if (condition.requireApproval === false && request.requiresApproval === true) return false;
  return true;
}

export function evaluatePermissionTree(tree, subject, targetNode, { defaultEffect = 'deny', request = {} } = {}) {
  let bestScore = -1;
  let bestEntry;
  for (const entry of tree) {
    if (!entry || !EFFECT_PRECEDENCE[entry.effect]) continue;
    const score = matchPermissionNode(entry.node, targetNode);
    if (score < 0 || !matchesCondition(entry.condition, subject, request)) continue;
    if (
      score > bestScore
      || (score === bestScore && bestEntry && EFFECT_PRECEDENCE[entry.effect] > EFFECT_PRECEDENCE[bestEntry.effect])
    ) {
      bestScore = score;
      bestEntry = entry;
    }
  }
  return {
    effect: bestEntry?.effect ?? defaultEffect,
    node: targetNode,
    ...(bestEntry ? { matched: bestEntry } : {}),
  };
}

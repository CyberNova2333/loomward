// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import {
  VAULT_SLOT,
  formatActionNode,
  mechanismActionKind,
  serviceInvokeActionKind,
} from '@loomward/shared';

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
  if (condition.isolatedOnly && !subject.isolated) return false;
  if (condition.asyncOnly && request.async !== true) return false;
  if (condition.trustLevels && !condition.trustLevels.includes(subject.trustLevel)) return false;
  if (condition.requireApproval === false && request.requiresApproval === true) return false;
  return true;
}

export function evaluatePermissionTree(tree, subject, targetNodeOrReq, { defaultEffect = 'deny', request } = {}) {
  const targetNode = typeof targetNodeOrReq === 'string'
    ? targetNodeOrReq
    : formatActionNode(targetNodeOrReq);
  const effectiveRequest = request ?? (typeof targetNodeOrReq === 'object' && targetNodeOrReq !== null ? targetNodeOrReq : {});
  let bestScore = -1;
  let bestEntry;
  for (const entry of tree) {
    if (!entry || !EFFECT_PRECEDENCE[entry.effect]) continue;
    const score = matchPermissionNode(entry.node, targetNode);
    if (score < 0 || !matchesCondition(entry.condition, subject, effectiveRequest)) continue;
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

export function compileUnitGrant(
  subject,
  contract,
  slotRegistry = new Map(),
  { approvedActions = [], extraNodes = [], serviceMethods = {} } = {},
) {
  const tree = [
    // Closed vault slot and user selection are unconditionally denied for extension units.
    { node: `impl.register:${VAULT_SLOT}`, effect: 'deny' },
    { node: `impl.select:${VAULT_SLOT}`, effect: 'deny' },
    { node: `service.intercept:${VAULT_SLOT}`, effect: 'deny' },
    { node: `service.isolate-provide:${VAULT_SLOT}`, effect: 'deny' },
    { node: `service.invoke.*:${VAULT_SLOT}#*`, effect: 'deny' },
    { node: 'impl.select:*', effect: 'deny' },
  ];
  const trustedActionNodes = new Set();
  const allowedWriteTargets = new Set();

  for (const reg of contract.registers ?? []) {
    const slot = slotRegistry.get(reg.slot);
    if (!slot || slot.decl?.policy === 'closed') continue;
    const node = formatActionNode({ kind: 'impl.register', target: reg.slot });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(reg.slot);
    if (slot.decl?.policy === 'trusted') trustedActionNodes.add(node);
  }

  for (const hook of contract.writes?.hooks ?? []) {
    const slot = slotRegistry.get(hook.slot);
    if (!slot || slot.decl?.policy === 'closed') continue;
    const node = formatActionNode({ kind: mechanismActionKind(hook.phase), target: hook.slot });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(hook.slot);
    if (slot.decl?.policy === 'trusted') trustedActionNodes.add(node);
  }

  for (const svcName of contract.writes?.intercepts ?? []) {
    if (svcName === VAULT_SLOT) continue;
    const node = formatActionNode({ kind: 'service.intercept', target: svcName });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(svcName);
    trustedActionNodes.add(node);
  }

  for (const svcName of contract.writes?.isolateProvides ?? []) {
    if (svcName === VAULT_SLOT) continue;
    const node = formatActionNode({ kind: 'service.isolate-provide', target: svcName });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(svcName);
    trustedActionNodes.add(node);
  }

  const normalizedServiceMethods = {};
  for (const [svcName, rules] of Object.entries(serviceMethods ?? {})) {
    if (!rules || typeof rules !== 'object') continue;
    const frozenRules = {};
    for (const [methodName, rule] of Object.entries(rules)) {
      if (!rule || typeof rule !== 'object') continue;
      frozenRules[methodName] = Object.freeze({ ...rule });
      const kind = serviceInvokeActionKind(rule.mode || 'read');
      const node = formatActionNode({ kind, target: svcName, method: methodName });
      if (svcName === VAULT_SLOT || rule.policy === 'closed') {
        tree.push({ node, effect: 'deny' });
      } else if (rule.policy === 'public') {
        tree.push({ node, effect: 'allow' });
      } else if (rule.policy === 'trusted') {
        trustedActionNodes.add(node);
        tree.push({ node, effect: approvedActions.includes(node) ? 'allow' : 'deny' });
      } else if (rule.policy === 'ask-on-use') {
        trustedActionNodes.add(node);
        tree.push({
          node,
          effect: rule.async === true ? 'escalate' : 'deny',
          ...(rule.async === true ? { condition: { asyncOnly: true } } : {}),
        });
      }
    }
    normalizedServiceMethods[svcName] = Object.freeze(frozenRules);
  }

  for (const extra of extraNodes ?? []) {
    if (extra && typeof extra.node === 'string') {
      tree.push(Object.freeze({ ...extra }));
    }
  }

  return Object.freeze({
    unitId: subject.unitId,
    trustLevel: subject.trustLevel,
    isolated: subject.isolated,
    tree: Object.freeze(tree.map(n => Object.freeze({ ...n }))),
    allowedWriteTargets: Object.freeze([...allowedWriteTargets]),
    trustedActionNodes: Object.freeze([...trustedActionNodes]),
    approvedActions: Object.freeze([...new Set(approvedActions)]),
    serviceMethods: Object.freeze(normalizedServiceMethods),
  });
}

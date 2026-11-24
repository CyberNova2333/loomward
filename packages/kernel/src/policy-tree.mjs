// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import {
  CLOSED_SLOTS,
  ROOT_ONLY_SERVICES,
  VAULT_SLOT,
  formatActionNode,
  mechanismActionKind,
  serviceInvokeActionKind,
} from '@loomward/shared';

const EFFECT_PRECEDENCE = Object.freeze(Object.assign(Object.create(null), {
  deny: 3,
  escalate: 2,
  allow: 1,
}));

const KNOWN_CONDITION_KEYS = new Set([
  'signedOnly',
  'outOfProcessOnly',
  'isolatedOnly',
  'asyncOnly',
  'trustLevels',
  'requireApproval',
]);
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function matchSegments(pattern, target) {
  if (pattern.length === 1 && pattern[0] === '*') {
    return target.length >= 1 ? 10 : -1;
  }
  let score = 0;
  for (let i = 0; i < pattern.length; i++) {
    const seg = pattern[i];
    if (seg === '*') {
      if (i >= target.length) return -1;
      if (i === pattern.length - 1) return score + 10;
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
  if (pattern === targetNode) return 100_000_000 + pattern.length;
  if (pattern === '*') return 1;

  const pColon = pattern.indexOf(':');
  const tColon = targetNode.indexOf(':');
  if (pColon === -1 || tColon === -1) return -1;

  const actionScore = matchSegments(pattern.slice(0, pColon).split('.'), targetNode.slice(0, tColon).split('.'));
  if (actionScore < 0) return -1;

  const pRes = pattern.slice(pColon + 1);
  const tRes = targetNode.slice(tColon + 1);
  if (pRes === '*') return actionScore * 100_000 + 5;

  const pHash = pRes.indexOf('#');
  const tHash = tRes.indexOf('#');
  const pTarget = pHash === -1 ? pRes : pRes.slice(0, pHash);
  const tTarget = tHash === -1 ? tRes : tRes.slice(0, tHash);
  const pSub = pHash === -1 ? undefined : pRes.slice(pHash + 1);
  const tSub = tHash === -1 ? undefined : tRes.slice(tHash + 1);

  const pTargetParts = pTarget.split(':');
  const targetScore = pTarget === '*' ? 10 : matchSegments(pTargetParts, tTarget.split(':'));
  if (targetScore < 0) return -1;

  // Lexicographic dominance: action specificity > target specificity > method specificity.
  const baseScore = actionScore * 100_000 + targetScore * 1_000;

  if (pSub === undefined && tSub === undefined) return baseScore + 50;
  if (pSub === undefined && tSub !== undefined) {
    // Namespace wildcard target (e.g. `service.invoke.write:host:*`) also covers `#method` targets.
    if (pTarget === '*' || pTargetParts[pTargetParts.length - 1] === '*') {
      return baseScore + 10;
    }
    return -1;
  }
  if (pSub !== undefined && tSub === undefined) {
    return pSub === '*' ? baseScore + 5 : -1;
  }
  const subScore = pSub === tSub ? 120 : pSub === '*' ? 15 : -1;
  if (subScore < 0) return -1;
  return baseScore + subScore;
}

export function matchesCondition(condition, subject = {}, request = {}) {
  if (!condition) return true;
  if (typeof condition !== 'object' || Array.isArray(condition)) return false;
  for (const key of Object.keys(condition)) {
    if (!KNOWN_CONDITION_KEYS.has(key)) return false;
  }
  if (condition.signedOnly && !subject.signed) return false;
  if (condition.outOfProcessOnly && subject.executionBoundary !== 'out-of-process') return false;
  if (condition.isolatedOnly && !subject.isolated) return false;
  if (condition.asyncOnly && request.async !== true) return false;
  if (condition.trustLevels !== undefined) {
    if (!Array.isArray(condition.trustLevels) || !condition.trustLevels.includes(subject.trustLevel)) return false;
  }
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
    if (!entry || typeof entry.effect !== 'string' || !Object.hasOwn(EFFECT_PRECEDENCE, entry.effect)) continue;
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

function collectClosedTargets(slotRegistry) {
  const closed = new Set([...CLOSED_SLOTS, ...ROOT_ONLY_SERVICES]);
  if (slotRegistry instanceof Map) {
    for (const [name, slot] of slotRegistry.entries()) {
      if (slot?.decl?.policy === 'closed') closed.add(name);
    }
  }
  return closed;
}

function nodeTouchesForbiddenTarget(nodeStr, closedTargets) {
  if (typeof nodeStr !== 'string') return true;
  if (nodeStr === '*' || nodeStr.startsWith('impl.select:')) return true;
  const colonIdx = nodeStr.indexOf(':');
  const candidates = [nodeStr];
  if (colonIdx !== -1) {
    const res = nodeStr.slice(colonIdx + 1);
    const hashIdx = res.indexOf('#');
    if (hashIdx !== -1) {
      const targetPart = nodeStr.slice(0, colonIdx + 1 + hashIdx);
      candidates.push(targetPart, `${targetPart}#*`);
    }
  }
  for (const cand of candidates) {
    if (matchPermissionNode(cand, 'impl.select:__probe__') >= 0) return true;
  }
  for (const closedName of closedTargets) {
    const probes = [
      `impl.register:${closedName}`,
      `impl.select:${closedName}`,
      `service.intercept:${closedName}`,
      `service.isolate-provide:${closedName}`,
      `service.invoke.read:${closedName}`,
      `service.invoke.write:${closedName}`,
      `service.invoke.admin:${closedName}`,
      `service.invoke.read:${closedName}#__probe__`,
      `service.invoke.write:${closedName}#__probe__`,
      `service.invoke.admin:${closedName}#__probe__`,
      `mechanism.hook.before:${closedName}`,
      `mechanism.hook.after:${closedName}`,
      `mechanism.hook.replace:${closedName}`,
    ];
    for (const probe of probes) {
      for (const cand of candidates) {
        if (matchPermissionNode(cand, probe) >= 0) return true;
      }
    }
  }
  return false;
}

export function compileUnitGrant(
  subject,
  contract,
  slotRegistry = new Map(),
  { approvedActions = [], extraNodes = [], serviceMethods = {}, autoApproveTrusted = false } = {},
) {
  const closedTargets = collectClosedTargets(slotRegistry);
  const tree = [
    { node: 'impl.select:*', effect: 'deny' },
  ];
  for (const closedName of closedTargets) {
    tree.push(
      { node: `impl.register:${closedName}`, effect: 'deny' },
      { node: `impl.select:${closedName}`, effect: 'deny' },
      { node: `service.intercept:${closedName}`, effect: 'deny' },
      { node: `service.isolate-provide:${closedName}`, effect: 'deny' },
      { node: `service.invoke.*:${closedName}#*`, effect: 'deny' },
      { node: `service.invoke.read:${closedName}#*`, effect: 'deny' },
      { node: `service.invoke.write:${closedName}#*`, effect: 'deny' },
      { node: `service.invoke.admin:${closedName}#*`, effect: 'deny' },
      { node: `mechanism.hook.before:${closedName}`, effect: 'deny' },
      { node: `mechanism.hook.after:${closedName}`, effect: 'deny' },
      { node: `mechanism.hook.replace:${closedName}`, effect: 'deny' },
    );
  }

  const trustedActionNodes = new Set();
  const allowedWriteTargets = new Set();

  for (const reg of contract.registers ?? []) {
    const slot = slotRegistry.get(reg.slot);
    if (!slot || slot.decl?.policy === 'closed' || closedTargets.has(reg.slot)) continue;
    const node = formatActionNode({ kind: 'impl.register', target: reg.slot });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(reg.slot);
    if (slot.decl?.policy === 'trusted') trustedActionNodes.add(node);
  }

  for (const hook of contract.writes?.hooks ?? []) {
    const slot = slotRegistry.get(hook.slot);
    if (!slot || slot.decl?.policy === 'closed' || closedTargets.has(hook.slot)) continue;
    const node = formatActionNode({ kind: mechanismActionKind(hook.phase), target: hook.slot });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(hook.slot);
    if (slot.decl?.policy === 'trusted') trustedActionNodes.add(node);
  }

  for (const svcName of contract.writes?.intercepts ?? []) {
    if (closedTargets.has(svcName)) continue;
    const node = formatActionNode({ kind: 'service.intercept', target: svcName });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(svcName);
    trustedActionNodes.add(node);
  }

  for (const svcName of contract.writes?.isolateProvides ?? []) {
    if (closedTargets.has(svcName)) continue;
    const node = formatActionNode({ kind: 'service.isolate-provide', target: svcName });
    tree.push({ node, effect: 'allow' });
    allowedWriteTargets.add(svcName);
    trustedActionNodes.add(node);
  }

  const normalizedServiceMethods = Object.create(null);
  const declaredConsumes = new Set(contract.consumes ?? []);
  for (const [svcName, rules] of Object.entries(serviceMethods ?? {})) {
    if (PROTO_KEYS.has(svcName) || !declaredConsumes.has(svcName) || !rules || typeof rules !== 'object' || Array.isArray(rules)) continue;
    const frozenRules = Object.create(null);
    for (const [methodName, rule] of Object.entries(rules)) {
      if (PROTO_KEYS.has(methodName) || !rule || typeof rule !== 'object' || Array.isArray(rule)) continue;
      frozenRules[methodName] = Object.freeze({ ...rule });
      const kind = serviceInvokeActionKind(rule.mode || 'read');
      const node = formatActionNode({ kind, target: svcName, method: methodName });
      if (svcName === VAULT_SLOT || closedTargets.has(svcName) || rule.policy === 'closed') {
        tree.push({ node, effect: 'deny' });
      } else if (rule.policy === 'public') {
        tree.push({ node, effect: 'allow' });
      } else if (rule.policy === 'trusted') {
        trustedActionNodes.add(node);
        tree.push({
          node,
          effect: (autoApproveTrusted === true || approvedActions.includes(node)) ? 'allow' : 'deny',
        });
      } else if (rule.policy === 'ask-on-use') {
        trustedActionNodes.add(node);
        tree.push({
          node,
          effect: rule.async === true ? 'escalate' : 'deny',
          ...(rule.async === true ? { condition: { asyncOnly: true } } : {}),
        });
      } else {
        // Fail closed on unrecognized method policy.
        tree.push({ node, effect: 'deny' });
      }
    }
    normalizedServiceMethods[svcName] = Object.freeze(frozenRules);
  }

  for (const extra of extraNodes ?? []) {
    if (!extra || typeof extra.node !== 'string') continue;
    // Extra nodes can never grant access to closed slots or impl.select.
    if (extra.effect !== 'deny' && nodeTouchesForbiddenTarget(extra.node, closedTargets)) continue;
    tree.push(Object.freeze({ ...extra }));
  }

  return Object.freeze({
    unitId: subject.unitId,
    trustLevel: subject.trustLevel,
    isolated: subject.isolated,
    closedTargets: Object.freeze([...closedTargets]),
    tree: Object.freeze(tree.map(n => Object.freeze({ ...n }))),
    allowedWriteTargets: Object.freeze([...allowedWriteTargets]),
    trustedActionNodes: Object.freeze([...trustedActionNodes]),
    approvedActions: Object.freeze([...new Set(approvedActions)]),
    serviceMethods: Object.freeze(normalizedServiceMethods),
  });
}

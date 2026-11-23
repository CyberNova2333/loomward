// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { VAULT_SLOT } from '@loomward/shared';
import { LocalApprovals } from '../../../local/approvals.mjs';
import { RequestReceipts, TransientReceipts, StopReceipts } from '../../../local/receipts.mjs';
import { createHostVaultBackend } from './vault.mjs';
import { ToolBlockedError, createCapabilityPolicyRule, createToolDispatchPipeline } from './pipeline.mjs';
import { createCloudflareRelayIngress } from './ingress-relay.mjs';
import { createLocalMcpIngress } from './ingress-local.mjs';

export { contract } from './contract.mjs';
export { createHostVaultBackend } from './vault.mjs';
export { ToolBlockedError, createCapabilityPolicyRule, createToolDispatchPipeline } from './pipeline.mjs';
export { createCloudflareRelayIngress } from './ingress-relay.mjs';
export { createLocalMcpIngress } from './ingress-local.mjs';

export const name = 'host';

function canonicalizeOrigin(rawOrigin) {
  try {
    return new URL(rawOrigin).origin;
  } catch {
    return 'http://127.0.0.1';
  }
}

export function apply(ctx, config = {}) {
  const stateDir = config.stateDir ?? null;
  const origin = canonicalizeOrigin(config.origin || config.relay?.origin || 'http://127.0.0.1');

  const vaultSlot = ctx.get(VAULT_SLOT);
  const policySlot = ctx.get('policy:rule@1');
  const approvalSlot = ctx.get('approval:channel@1');
  const providerSlot = ctx.get('tool:provider@1');
  const invokeSlot = ctx.get('tool:invoke@1');
  const ingressSlot = ctx.get('gateway:ingress@1');

  const vaultBackend = config.vaultBackend ?? createHostVaultBackend({
    stateDir,
    loader: config.secretLoader,
  });
  if (vaultSlot) {
    vaultSlot.register('host-vault', vaultBackend);
  }

  if (policySlot) {
    policySlot.register('host-capabilities', createCapabilityPolicyRule());
  }

  const approvals = config.approvals ?? (stateDir ? new LocalApprovals(stateDir, origin) : null);
  approvals?.ready?.catch(() => {});
  if (approvalSlot && approvals) {
    approvalSlot.register('local-approvals', approvals);
  }

  const receipts = config.receipts ?? (stateDir ? new RequestReceipts(stateDir) : null);
  receipts?.ready?.catch(() => {});
  const controlReceipts = config.controlReceipts ?? new TransientReceipts();
  const stopReceipts = config.stopReceipts ?? new StopReceipts();

  const pipeline = createToolDispatchPipeline({
    slots: {
      toolProvider: providerSlot,
      toolInvoke: invokeSlot,
      policyRule: policySlot,
      approvalChannel: approvalSlot,
    },
    origin,
    stateDir,
    receipts,
    controlReceipts,
    stopReceipts,
    approvals,
    record: config.record,
  });

  const localIngress = createLocalMcpIngress({
    pipeline,
    clientId: config.localClientId,
  });
  if (ingressSlot) {
    ingressSlot.register('local-mcp-direct', localIngress);
  }

  let relayIngress = null;
  if (config.relay?.origin && config.relay?.bridgeToken) {
    relayIngress = createCloudflareRelayIngress({
      origin: config.relay.origin,
      bridgeToken: config.relay.bridgeToken,
      pipeline,
      proxyProvider: config.relay.proxyProvider,
      socketFactory: config.relay.socketFactory,
      record: config.record,
      status: config.status,
    });
    if (ingressSlot) {
      ingressSlot.register('cloudflare-wss', relayIngress);
    }
  }

  ctx.effect(() => async () => {
    await Promise.allSettled([
      localIngress.stop(),
      relayIngress ? relayIngress.stop() : Promise.resolve(),
    ]);
  }, 'host:stop-ingresses');

  ctx.provide('host:vault', Object.freeze({
    describe: () => vaultBackend.describe(),
  }));

  ctx.provide('host:approval-ledger', Object.freeze({
    configured: Boolean(approvals),
    origin,
  }));

  ctx.provide('host:dispatch', pipeline);

  ctx.provide('host:platform', Object.freeze({
    status: 'ready',
    legacyEntry: 'scripts/host-cli.mjs',
    stateDir,
    origin,
    ingresses: {
      local: localIngress,
      relay: relayIngress,
    },
  }));
}

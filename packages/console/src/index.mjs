// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
export { contract } from './contract.mjs';
export { createControlChannel, connectControlSocket } from './control-channel.mjs';
export { createConsolePanelCollector } from './panel-registry.mjs';
export { createDualOriginSessionBroker } from './session-broker.mjs';
export {
  DEFAULT_CONSOLE_PORT,
  DEFAULT_TRUST_PORT,
  startDualOriginConsole,
} from './server.mjs';

import { startDualOriginConsole } from './server.mjs';
import { createControlChannel } from './control-channel.mjs';
import { createConsolePanelCollector } from './panel-registry.mjs';

export const name = 'console';

export async function apply(ctx, config = {}) {
  const panelSlot = ctx.get('console:panel@1');
  const controlChannel = config.controlChannel ?? createControlChannel({
    socketPath: config.enableControlSocket && config.stateDir
      ? config.controlSocketPath
      : null,
  });
  const panelCollector = createConsolePanelCollector({
    panelSlot,
    staticPanels: config.staticPanels ?? [],
  });

  let instance = null;
  if (config.enabled === true && config.stateDir) {
    instance = await startDualOriginConsole({
      ...config,
      panelSlot,
      controlChannel,
    });
  }

  ctx.effect(() => () => {
    if (instance) void instance.close();
    else if (!config.controlChannel) void controlChannel.close();
  }, 'console:close');

  ctx.provide('console:loopback', Object.freeze({
    status: instance ? 'listening' : 'standby',
    legacyEntry: 'local/webui.mjs',
    url: instance?.console?.url ?? null,
    port: instance?.console?.port ?? null,
    controlChannel,
    panelCollector,
    publishEvent: event => controlChannel.publish(event),
  }));

  ctx.provide('console:trust-origin', Object.freeze({
    status: instance ? 'listening' : 'standby',
    url: instance?.trust?.url ?? null,
    port: instance?.trust?.port ?? null,
    close: async () => {
      if (instance) await instance.close();
    },
  }));
}

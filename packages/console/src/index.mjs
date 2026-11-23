// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
export { contract } from './contract.mjs';

export const name = 'console';

export function apply(ctx) {
  ctx.provide('console:loopback', {
    status: 'migrating',
    legacyEntry: 'local/webui.mjs',
  });
}

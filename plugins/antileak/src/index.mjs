// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
export { contract } from './contract.mjs';

export const name = 'plugin-antileak';

export function createAntileakAdapterDescriptor() {
  return Object.freeze({
    id: 'antileak',
    boundary: 'out-of-process',
    rules: ['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7'],
    archiveBranch: 'archive/claude-code-antileak-hooks',
  });
}

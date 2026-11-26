// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { PLUGIN_SECRETS_SLOT, validateContractDecl } from '@loomward/shared';

export const contract = validateContractDecl({
  schemaVersion: 1,
  id: 'llm-moderation',
  kind: 'extension-plugin',
  version: '3.0.0-alpha.0',
  executionBoundary: 'out-of-process',
  provides: ['policy:llm-moderation'],
  consumes: ['tool:invoke@1', 'tool:stream@1', 'console:panel@1', PLUGIN_SECRETS_SLOT],
  registers: [
    { slot: 'console:panel@1', name: 'llm-moderation' },
  ],
  writes: {
    hooks: [
      { slot: 'tool:invoke@1', phase: 'before' },
      { slot: 'tool:invoke@1', phase: 'after' },
      { slot: 'tool:stream@1', phase: 'before' },
      { slot: 'tool:stream@1', phase: 'after' },
    ],
    intercepts: [],
    isolateProvides: [],
  },
});

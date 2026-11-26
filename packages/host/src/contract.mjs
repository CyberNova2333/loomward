// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { PLUGIN_SECRETS_ADMIN_SERVICE, PLUGIN_SECRETS_SLOT, validateContractDecl } from '@loomward/shared';

export const contract = validateContractDecl({
  schemaVersion: 1,
  id: 'host',
  kind: 'root-plugin',
  version: '3.0.0-alpha.0',
  executionBoundary: 'in-process-root',
  provides: [
    'host:platform',
    'host:vault',
    'host:approval-ledger',
    'host:dispatch',
    PLUGIN_SECRETS_ADMIN_SERVICE,
    PLUGIN_SECRETS_SLOT,
  ],
  consumes: [
    'vault:backend@1',
    'approval:channel@1',
    'policy:rule@1',
    'tool:provider@1',
    'tool:invoke@1',
    'tool:stream@1',
    'gateway:ingress@1',
  ],
  archiveSource: 'archive/agentdock-worker-remote',
});

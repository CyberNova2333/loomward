// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { validateContractDecl } from '@loomward/shared';

export const contract = validateContractDecl({
  schemaVersion: 1,
  id: 'decisions',
  kind: 'extension-plugin',
  version: '3.0.0-alpha.0',
  executionBoundary: 'out-of-process',
  provides: ['decisions:ledger'],
  consumes: ['tool:provider@1', 'console:panel@1'],
  archiveSource: 'archive/agent-decisions-dashboard',
});

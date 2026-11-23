// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export {
  PLATFORM_SLOTS,
  StartupRejectedError,
  createLoomWardKernel,
} from './boot.mjs';
export {
  matchPermissionNode,
  matchesCondition,
  evaluatePermissionTree,
  compileUnitGrant,
} from './policy-tree.mjs';
export {
  GUARD_UNIT_STATE,
  resolveUnitState,
  unwrapCordisOriginal,
  createGuardedUnitState,
  KernelGuard,
} from './guard.mjs';
export {
  executionBoundaryRule,
  closedSlotRule,
  slotDeclarationRule,
  trustedApprovalRule,
  BUILTIN_GUARD_RULES,
  createGuardPipeline,
  evaluateGuard,
} from './rules.mjs';
export {
  DEFAULT_ROOT_PLUGIN_SPECS,
  buildWorkspaceRpm,
  verifyWorkspaceRpm,
  loadWorkspaceRootRefs,
} from './rpm-builder.mjs';

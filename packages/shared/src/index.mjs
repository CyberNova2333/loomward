// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export {
  CONTRACT_SCHEMA_VERSION,
  CONTRACT_KINDS,
  EXECUTION_BOUNDARIES,
  SLOT_POLICIES,
  SLOT_CARDINALITIES,
  validateContractDecl,
} from './contracts.mjs';
export {
  RPM_FORMAT_VERSION,
  canonicalJson,
  sha256Tagged,
  hashedRpmFields,
  computeManifestHash,
  isRpmShape,
  createFrozenRpm,
} from './rpm.mjs';
export {
  BOOT_DEADLINE_MS,
  BootDeadlineError,
  BootRun,
  withDeadline,
} from './deadline.mjs';
export {
  SlotError,
  ImplSlot,
  MechanismSlot,
} from './slots.mjs';
export {
  VAULT_SLOT,
  CLOSED_SLOTS,
  AUDIT_CODES,
  REJECT_CODES,
  FORBIDDEN_AUDIT_KEYS,
  mechanismActionKind,
  serviceInvokeActionKind,
  formatActionNode,
  buildPermissionSubject,
  isSafeUnicodeString,
  sanitizeAuditMetadata,
} from './guard-types.mjs';
export {
  CONSOLE_PANEL_SCHEMA_VERSION,
  PANEL_CATEGORIES,
  PANEL_STATUSES,
  PANEL_TONES,
  validateConsolePanelDecl,
  sanitizeConsolePanelSnapshot,
} from './panel-schema.mjs';
export {
  CONTENT_INSPECT_PROTOCOL_VERSION,
  CONTENT_INSPECT_STAGES,
  CONTENT_INSPECT_DECISIONS,
  buildContentInspectRequest,
  validateContentInspectVerdict,
} from './content-guard.mjs';

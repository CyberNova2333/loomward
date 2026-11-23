// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import { loadSecrets as loadLegacySecrets } from '../../../local/connector.mjs';
import { exportSecretsSync as exportPosixSecretsSync } from '../../../local/host-secrets.mjs';

export function createHostVaultBackend({ stateDir = null, loader = null } = {}) {
  function readSecrets({ fields } = {}) {
    if (typeof loader === 'function') {
      return loader({ stateDir, fields });
    }
    if (!stateDir) {
      throw new Error('Protected credential loading failed. Check the trusted local installation.');
    }
    if (process.platform === 'win32') {
      return loadLegacySecrets(stateDir, { fields });
    }
    return exportPosixSecretsSync(stateDir, { fields });
  }

  return Object.freeze({
    id: 'host-vault',
    platform: process.platform,
    loadSecrets: readSecrets,
    exportSecretsSync: readSecrets,
    describe() {
      return Object.freeze({
        id: 'host-vault',
        platform: process.platform,
        configured: Boolean(stateDir || loader),
      });
    },
  });
}

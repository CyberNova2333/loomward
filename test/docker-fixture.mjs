// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of AgentDock Bridge and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).
import fs from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { defaultDockerContext } from '../local/sandbox.mjs';

const exec = promisify(execFile);

async function resolveTestDocker() {
  if (process.env.AGENTDOCK_TEST_DOCKER) return process.env.AGENTDOCK_TEST_DOCKER;
  if (process.platform === 'win32') return 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe';
  for (const candidate of ['/usr/bin/docker', '/usr/local/bin/docker', '/opt/homebrew/bin/docker', '/Applications/Docker.app/Contents/Resources/bin/docker']) {
    try { return await fs.realpath(candidate); } catch {}
  }
  throw new Error('Set AGENTDOCK_TEST_DOCKER to the Docker CLI path for this test host.');
}

export async function resolveTestSandbox() {
  const ref = process.env.AGENTDOCK_TEST_IMAGE;
  if (!ref?.trim()) throw new Error('Set AGENTDOCK_TEST_IMAGE to the local image to use for Docker integration tests.');
  const dockerPath = await resolveTestDocker();
  const context = process.env.AGENTDOCK_TEST_CONTEXT || defaultDockerContext();
  const { stdout } = await exec(dockerPath, ['--context', context, 'image', 'inspect', '--format', '{{.Id}}', '--', ref], { timeout: 15000 });
  return { dockerPath, context, image: stdout.trim() };
}

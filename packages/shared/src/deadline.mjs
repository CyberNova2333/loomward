// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const BOOT_DEADLINE_MS = 60_000;
const MAX_TIMEOUT_MS = 2_147_483_647;
const DEFAULT_ROLLBACK_STEP_TIMEOUT_MS = 2_000;

export class BootDeadlineError extends Error {
  constructor(message = 'Kernel boot deadline exceeded.') {
    super(message);
    this.name = 'BootDeadlineError';
    this.code = 'BOOT_DEADLINE_EXCEEDED';
  }
}

async function runBoundedStep(fn, stepTimeoutMs) {
  let timer = null;
  try {
    await Promise.race([
      Promise.resolve().then(() => fn()),
      new Promise(resolve => {
        timer = setTimeout(resolve, stepTimeoutMs);
        timer.unref?.();
      }),
    ]);
  } catch {
    // Rollback continues in strict LIFO order even if one cleanup throws.
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export class BootRun {
  #undos = [];
  #aborted = false;
  #settled = false;
  #rollingBack = false;
  #rollbackPromise = null;
  #rollbackStepTimeoutMs;

  constructor({ rollbackStepTimeoutMs = DEFAULT_ROLLBACK_STEP_TIMEOUT_MS } = {}) {
    this.#rollbackStepTimeoutMs = Number.isSafeInteger(rollbackStepTimeoutMs) && rollbackStepTimeoutMs >= 10
      ? Math.min(rollbackStepTimeoutMs, MAX_TIMEOUT_MS)
      : DEFAULT_ROLLBACK_STEP_TIMEOUT_MS;
  }

  get aborted() {
    return this.#aborted;
  }

  add(undo) {
    if (typeof undo !== 'function') throw new TypeError('Rollback hook must be a function.');
    if (this.#settled) {
      throw new Error('Cannot register rollback hook after BootRun has settled.');
    }
    if (this.#aborted) {
      if (this.#rollingBack) {
        // Integrated into the active LIFO drain loop.
        this.#undos.push(undo);
        return;
      }
      // Late registration after rollback completed runs immediately to prevent leaked resources.
      void runBoundedStep(undo, this.#rollbackStepTimeoutMs);
      return;
    }
    this.#undos.push(undo);
  }

  live() {
    if (this.#aborted) throw new BootDeadlineError();
  }

  async rollback() {
    this.#aborted = true;
    if (this.#rollbackPromise) return this.#rollbackPromise;
    this.#rollingBack = true;
    this.#rollbackPromise = (async () => {
      try {
        while (this.#undos.length > 0) {
          const undo = this.#undos.pop();
          await runBoundedStep(undo, this.#rollbackStepTimeoutMs);
        }
      } finally {
        this.#rollingBack = false;
      }
    })();
    return this.#rollbackPromise;
  }

  finish() {
    this.#settled = true;
    this.#undos.length = 0;
  }

  get settled() {
    return this.#settled;
  }
}

export async function withDeadline(timeoutMs, task, { rollbackStepTimeoutMs } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new RangeError(`timeoutMs must be a safe integer in 1..${MAX_TIMEOUT_MS}.`);
  }
  const effectiveStepTimeout = rollbackStepTimeoutMs ?? Math.min(DEFAULT_ROLLBACK_STEP_TIMEOUT_MS, Math.max(50, timeoutMs));
  const run = new BootRun({ rollbackStepTimeoutMs: effectiveStepTimeout });
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      void run.rollback().finally(() => reject(new BootDeadlineError(`Boot exceeded ${timeoutMs}ms deadline.`)));
    }, timeoutMs);
    timer.unref?.();
  });

  const workPromise = (async () => {
    try {
      const value = await task(run);
      run.live();
      return value;
    } catch (error) {
      await run.rollback();
      throw error;
    }
  })();

  try {
    const result = await Promise.race([workPromise, timeoutPromise]);
    clearTimeout(timer);
    run.finish();
    return result;
  } catch (error) {
    clearTimeout(timer);
    // Swallow late rejections from the losing race arm after rollback has begun.
    workPromise.catch(() => {});
    await run.rollback();
    throw error;
  }
}

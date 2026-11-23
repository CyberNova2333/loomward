// SPDX-License-Identifier: AGPL-3.0-only
// This file is part of LoomWard (织盾) and is licensed under GNU AGPLv3 with Additional Terms (see LICENSE and LICENSE-ADDITIONAL_TERMS-zh-CN.md; ref: LICENSE-ADDITIONAL_TERMS-en.md).

export const BOOT_DEADLINE_MS = 60_000;

export class BootDeadlineError extends Error {
  constructor(message = 'Kernel boot deadline exceeded.') {
    super(message);
    this.name = 'BootDeadlineError';
    this.code = 'BOOT_DEADLINE_EXCEEDED';
  }
}

export class BootRun {
  #undos = [];
  #aborted = false;
  #settled = false;
  #rollbackPromise = null;

  get aborted() {
    return this.#aborted;
  }

  add(undo) {
    if (typeof undo !== 'function') throw new TypeError('Rollback hook must be a function.');
    if (this.#aborted) {
      // Late registration after timeout/failure runs immediately to prevent leaked resources.
      void Promise.resolve().then(() => undo()).catch(() => {});
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
    this.#rollbackPromise = (async () => {
      while (this.#undos.length > 0) {
        const undo = this.#undos.pop();
        try {
          await undo();
        } catch {
          // Rollback continues in strict LIFO order even if one cleanup throws.
        }
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

export async function withDeadline(timeoutMs, task) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new RangeError('timeoutMs must be a positive safe integer.');
  }
  const run = new BootRun();
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      void run.rollback().finally(() => reject(new BootDeadlineError(`Boot exceeded ${timeoutMs}ms deadline.`)));
    }, timeoutMs);
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

// Minimal assertions (no remote test dependency: the runtime is vendored and runs --cached-only).

export class AssertionError extends Error {}

export function assert(condition: unknown, message = 'Assertion failed'): asserts condition {
  if (!condition) throw new AssertionError(message);
}

export function assertEquals<T>(actual: T, expected: T, message = '') {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a !== e) throw new AssertionError(`${message ? message + ': ' : ''}expected ${e}, got ${a}`);
}

export function assertMatch(actual: string, pattern: RegExp, message = '') {
  if (!pattern.test(actual)) {
    throw new AssertionError(
      `${message ? message + ': ' : ''}${JSON.stringify(actual)} does not match ${pattern}`,
    );
  }
}

export function assertNotIncludes(haystack: string, needle: string, message = '') {
  if (haystack.includes(needle)) {
    const at = haystack.indexOf(needle);
    throw new AssertionError(
      `${message ? message + ': ' : ''}${JSON.stringify(needle)} found in ${
        JSON.stringify(haystack.slice(Math.max(0, at - 300), at + 100))
      }`,
    );
  }
}

export async function assertRejects(fn: () => Promise<unknown>, pattern?: RegExp) {
  try {
    await fn();
  } catch (error) {
    if (pattern && !pattern.test((error as Error).message)) {
      throw new AssertionError(`rejected with ${(error as Error).message}, expected ${pattern}`);
    }
    return;
  }
  throw new AssertionError('expected a rejection');
}

export function assertThrows(fn: () => unknown, pattern?: RegExp) {
  try {
    fn();
  } catch (error) {
    if (pattern && !pattern.test((error as Error).message)) {
      throw new AssertionError(`threw ${(error as Error).message}, expected ${pattern}`);
    }
    return;
  }
  throw new AssertionError('expected an exception');
}

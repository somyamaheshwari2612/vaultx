/**
 * test/e2e/helpers/test-runner-core.mjs
 * Lightweight, zero-dependency test harness and assertion library for VaultX.
 * Compatible with Node.js 22 native ESM.
 */
import assert from 'node:assert/strict';

// Terminal color helpers (ANSI)
export const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
};

// Augmented assertion library
export const expect = assert;
export { assert };

// Custom assertion helpers
assert.includes = (collection, item, message) => {
  if (typeof collection === 'string') {
    assert.ok(collection.includes(item), message || `Expected string to include "${item}"`);
  } else if (Array.isArray(collection) || collection instanceof Set) {
    const arr = Array.from(collection);
    assert.ok(arr.includes(item), message || `Expected collection to include item`);
  } else if (collection && typeof collection === 'object') {
    assert.ok(item in collection, message || `Expected object to have key "${item}"`);
  } else {
    assert.fail(`Invalid collection type for assert.includes: ${typeof collection}`);
  }
};

assert.notIncludes = (collection, item, message) => {
  if (typeof collection === 'string') {
    assert.ok(!collection.includes(item), message || `Expected string NOT to include "${item}"`);
  } else if (Array.isArray(collection) || collection instanceof Set) {
    const arr = Array.from(collection);
    assert.ok(!arr.includes(item), message || `Expected collection NOT to include item`);
  } else if (collection && typeof collection === 'object') {
    assert.ok(!(item in collection), message || `Expected object NOT to have key "${item}"`);
  }
};

assert.greaterThan = (actual, expected, message) => {
  assert.ok(actual > expected, message || `Expected ${actual} > ${expected}`);
};

assert.lessThan = (actual, expected, message) => {
  assert.ok(actual < expected, message || `Expected ${actual} < ${expected}`);
};

assert.isBase64Url = (str, message) => {
  assert.ok(typeof str === 'string' && str.length > 0, message || 'Expected non-empty string');
  assert.match(str, /^[A-Za-z0-9_-]+$/, message || 'Expected string to be valid Base64URL without padding');
};

assert.isHexDigest = (str, expectedLength = 64, message) => {
  assert.ok(typeof str === 'string', message || 'Expected string');
  const re = new RegExp(`^[0-9a-fA-F]{${expectedLength}}$`);
  assert.match(str, re, message || `Expected hex string of length ${expectedLength}`);
};

/**
 * Asynchronously polls a predicate condition until it evaluates to truthy or times out.
 * Prevents race conditions and timing flakiness in async state transitions.
 *
 * @param {Function} predicate - Async or sync function returning a boolean or truthy value
 * @param {Object} options - Configuration options { timeout, interval }
 * @returns {Promise<any>} The result of predicate()
 */
export async function waitFor(predicate, { timeout = 2500, interval = 10 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const res = await predicate();
      if (res) return res;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, interval));
  }
  return predicate();
}

/**
 * Creates an isolated Test Suite instance.
 */
export function createSuite(suiteName, suiteOptions = {}) {
  const tests = [];
  const beforeHooks = [];
  const afterHooks = [];
  const beforeEachHooks = [];
  const afterEachHooks = [];

  let currentGroup = '';

  const suite = {
    name: suiteName,

    describe(groupName, fn) {
      const prevGroup = currentGroup;
      currentGroup = prevGroup ? `${prevGroup} > ${groupName}` : groupName;
      try {
        fn();
      } finally {
        currentGroup = prevGroup;
      }
    },

    it(testName, fn, options = {}) {
      const fullName = currentGroup ? `${currentGroup} > ${testName}` : testName;
      tests.push({
        name: fullName,
        fn,
        skip: options.skip || false,
        timeoutMs: options.timeoutMs || 10000,
      });
    },

    before(fn) {
      beforeHooks.push(fn);
    },

    after(fn) {
      afterHooks.push(fn);
    },

    beforeEach(fn) {
      beforeEachHooks.push(fn);
    },

    afterEach(fn) {
      afterEachHooks.push(fn);
    },

    async run(runOptions = {}) {
      const verbose = runOptions.verbose ?? true;
      const filter = runOptions.filter ? new RegExp(runOptions.filter, 'i') : null;

      console.log(`\n${colors.bold}${colors.cyan}▶ RUNNING SUITE: ${suiteName}${colors.reset}`);
      const startTime = performance.now();

      const results = {
        suiteName,
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0,
        durationMs: 0,
        errors: [],
      };

      try {
        // Run before hooks
        for (const hook of beforeHooks) {
          await hook();
        }

        // Run tests
        for (const test of tests) {
          if (filter && !filter.test(test.name)) {
            continue;
          }

          results.total++;

          if (test.skip) {
            results.skipped++;
            if (verbose) {
              console.log(`  ${colors.yellow}○ [SKIP]${colors.reset} ${colors.gray}${test.name}${colors.reset}`);
            }
            continue;
          }

          // Run beforeEach hooks
          for (const hook of beforeEachHooks) {
            await hook();
          }

          const testStart = performance.now();
          let testPassed = false;
          let testError = null;

          let timeoutId;
          try {
            const timeoutPromise = new Promise((_, reject) => {
              timeoutId = setTimeout(() => {
                reject(new Error(`Test timed out after ${test.timeoutMs}ms`));
              }, test.timeoutMs);
            });

            await Promise.race([test.fn(), timeoutPromise]);
            testPassed = true;
          } catch (err) {
            testPassed = false;
            testError = err;
          } finally {
            if (timeoutId) {
              clearTimeout(timeoutId);
            }
          }

          const testDuration = Math.round(performance.now() - testStart);

          // Run afterEach hooks
          for (const hook of afterEachHooks) {
            try {
              await hook();
            } catch (hookErr) {
              console.error(`  ${colors.red}Error in afterEach hook:${colors.reset}`, hookErr);
            }
          }

          if (testPassed) {
            results.passed++;
            if (verbose) {
              console.log(`  ${colors.green}✔${colors.reset} ${test.name} ${colors.gray}(${testDuration}ms)${colors.reset}`);
            }
          } else {
            results.failed++;
            results.errors.push({ testName: test.name, error: testError });
            console.log(`  ${colors.red}✘ [FAIL] ${test.name}${colors.reset} ${colors.gray}(${testDuration}ms)${colors.reset}`);
            console.log(`    ${colors.red}${testError?.name || 'Error'}: ${testError?.message || testError}${colors.reset}`);
            if (testError?.stack) {
              const cleanedStack = testError.stack
                .split('\n')
                .slice(1, 4)
                .map((l) => `      ${colors.gray}${l.trim()}${colors.reset}`)
                .join('\n');
              console.log(cleanedStack);
            }
          }
        }

        // Run after hooks
        for (const hook of afterHooks) {
          await hook();
        }
      } catch (fatalErr) {
        console.error(`${colors.red}Fatal Suite Error in ${suiteName}:${colors.reset}`, fatalErr);
        results.errors.push({ testName: 'SUITE_FATAL', error: fatalErr });
      }

      results.durationMs = Math.round(performance.now() - startTime);

      const color = results.failed === 0 ? colors.green : colors.red;
      console.log(
        `${color}${colors.bold}  Summary for ${suiteName}: ${results.passed} passed, ${results.failed} failed, ${results.skipped} skipped (${results.durationMs}ms)${colors.reset}`
      );

      return results;
    },
  };

  return suite;
}

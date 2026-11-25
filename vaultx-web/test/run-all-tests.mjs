/**
 * test/run-all-tests.mjs
 * Main offline CLI test runner orchestrating Tiers 1-4 for VaultX.
 * Usage:
 *   node test/run-all-tests.mjs
 *   node test/run-all-tests.mjs --tier=1
 *   node test/run-all-tests.mjs --filter="Mode B"
 */
import { performance } from 'node:perf_hooks';

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

// Parse command line arguments flexibly
const args = process.argv.slice(2);
let selectedTier = null;
let selectedFilter = null;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg.startsWith('--tier=')) {
    selectedTier = arg.split('=')[1];
  } else if (arg === '--tier' || arg === '-t') {
    selectedTier = args[++i];
  } else if (arg.startsWith('-t=')) {
    selectedTier = arg.split('=')[1];
  } else if (arg.startsWith('--filter=')) {
    selectedFilter = arg.split('=')[1];
  } else if (arg === '--filter' || arg === '-f') {
    selectedFilter = args[++i];
  } else if (arg.startsWith('-f=')) {
    selectedFilter = arg.split('=')[1];
  }
}

const suiteConfigs = [
  { tier: '1', file: './e2e/tier1-feature-coverage.test.mjs', label: 'Tier 1: Feature Coverage (40 Tests)' },
  { tier: '2', file: './e2e/tier2-boundary-corner.test.mjs', label: 'Tier 2: Boundary & Corner Cases (40 Tests)' },
  { tier: '3', file: './e2e/tier3-cross-feature.test.mjs', label: 'Tier 3: Cross-Feature Combinations (8 Tests)' },
  { tier: '4', file: './e2e/tier4-real-world.test.mjs', label: 'Tier 4: Real-World Scenarios (5 Scenarios)' },
];

async function main() {
  console.log(`\n${colors.bold}${colors.magenta}======================================================================`);
  console.log(`                     VaultX E2E Test Suite Runner                     `);
  console.log(`   Offline Node.js 22 Native Harness | Category-Partition & BVA       `);
  console.log(`======================================================================${colors.reset}`);
  if (selectedTier) console.log(`  Filtered by Tier: ${selectedTier}`);
  if (selectedFilter) console.log(`  Filtered by Name: "${selectedFilter}"`);
  console.log();

  const globalStart = performance.now();
  let totalSuites = 0;
  let suitesPassed = 0;
  let suitesFailed = 0;
  let totalTests = 0;
  let testsPassed = 0;
  let testsFailed = 0;
  let testsSkipped = 0;
  const failureDetails = [];

  for (const config of suiteConfigs) {
    if (selectedTier && selectedTier !== config.tier) {
      continue;
    }

    totalSuites++;
    try {
      const module = await import(config.file);
      const suite = module.default || module.suite;
      if (!suite || typeof suite.run !== 'function') {
        throw new Error(`Suite file ${config.file} does not export a valid Suite object with a run() method`);
      }

      const result = await suite.run({ filter: selectedFilter, verbose: true });
      totalTests += result.total;
      testsPassed += result.passed;
      testsFailed += result.failed;
      testsSkipped += result.skipped;

      if (result.failed === 0) {
        suitesPassed++;
      } else {
        suitesFailed++;
        failureDetails.push(...result.errors.map((e) => ({ ...e, suite: config.label })));
      }
    } catch (err) {
      suitesFailed++;
      console.error(`${colors.red}Failed to load or execute ${config.file}:${colors.reset}`, err);
      failureDetails.push({ suite: config.label, testName: 'SUITE_IMPORT_ERROR', error: err });
    }
  }

  const globalDuration = Math.round(performance.now() - globalStart);

  // Print Grand Summary Table
  console.log(`\n${colors.bold}======================================================================`);
  console.log(`                         TEST EXECUTION SUMMARY                       `);
  console.log(`======================================================================${colors.reset}`);
  console.log(`  Suites:    ${suitesPassed === totalSuites ? colors.green : colors.red}${suitesPassed} passed${colors.reset}, ${totalSuites} total`);
  console.log(`  Tests:     ${testsFailed === 0 ? colors.green : colors.red}${testsPassed} passed${colors.reset}, ${testsFailed > 0 ? `${colors.red}${testsFailed} failed, ` : ''}${testsSkipped} skipped, ${totalTests} total`);
  console.log(`  Duration:  ${colors.cyan}${globalDuration} ms${colors.reset}`);
  console.log(`======================================================================`);

  if (testsFailed > 0 || suitesFailed > 0) {
    console.log(`\n${colors.bold}${colors.red}FAILED TESTS BREAKDOWN (${failureDetails.length}):${colors.reset}`);
    for (const fail of failureDetails) {
      console.log(`  ${colors.red}✘ [${fail.suite}] ${fail.testName}${colors.reset}`);
      console.log(`    ${fail.error?.message || fail.error}`);
    }
    console.log(`\n${colors.red}${colors.bold}OVERALL RESULT: FAIL (Exit Code 1)${colors.reset}\n`);
    process.exit(1);
  } else {
    console.log(`\n${colors.green}${colors.bold}OVERALL RESULT: ALL TESTS PASSED (100% SUCCESS, Exit Code 0)${colors.reset}\n`);
    process.exit(0);
  }
}

main().catch((fatal) => {
  console.error(`${colors.red}Unhandled Fatal Runner Error:${colors.reset}`, fatal);
  process.exit(1);
});

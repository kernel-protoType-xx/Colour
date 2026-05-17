'use strict';

const { execSync } = require('child_process');
const path = require('path');

const tests = [
  'tests/verifier.test.js',
  'tests/audit.test.js',
  'tests/interceptor.test.js',
];

const T = {
  bold  : s => `\x1b[1m${s}\x1b[0m`,
  red   : s => `\x1b[31m${s}\x1b[0m`,
  green : s => `\x1b[32m${s}\x1b[0m`,
  cyan  : s => `\x1b[36m${s}\x1b[0m`,
  dim   : s => `\x1b[2m${s}\x1b[0m`,
};

console.log('\n' + T.cyan(T.bold('  ◆ COLOUR SHIELD — Test Suite')));
console.log(T.dim('  Colour Foundation · Cure53 audited'));

let allPassed = true;
for (const testFile of tests) {
  try { execSync(`node ${path.join(__dirname, '..', testFile)}`, { stdio: 'inherit' }); }
  catch { allPassed = false; }
}

if (allPassed) { console.log(T.green(T.bold('  ✓  All tests passed\n'))); process.exit(0); }
else { console.log(T.red(T.bold('  ✗  Some tests failed\n'))); process.exit(1); }

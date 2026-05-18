'use strict';

const { verifyPackage, checkTyposquat, levenshtein, BUNDLED_THREATS, SEVERITY } = require('../src/verifier');

let passed = 0; let failed = 0;

async function test(name, fn) {
  try { await fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (err) { console.log(`  ✗  ${name}\n     ${err.message}`); failed++; }
}

function assert(condition, msg) { if (!condition) throw new Error(msg || 'Assertion failed'); }

(async () => {
  console.log('\n  verifier.js\n');
  await test('levenshtein: identical = 0', () => assert(levenshtein('express','express') === 0));
  await test('levenshtein: one char off = 1', () => assert(levenshtein('expresss','express') === 1));
  await test('levenshtein: empty string', () => { assert(levenshtein('','abc') === 3); assert(levenshtein('abc','') === 3); });
  await test('checkTyposquat: exact hit', () => { const r = checkTyposquat('axois'); assert(r.detected); assert(r.likely_target === 'axios'); });
  await test('checkTyposquat: fuzzy hit', () => { const r = checkTyposquat('expresss'); assert(r.detected); assert(r.likely_target === 'express'); });
  await test('checkTyposquat: safe not flagged', () => assert(!checkTyposquat('express').detected));
  await test('checkTyposquat: unrelated not flagged', () => assert(!checkTyposquat('colour-shield').detected));
  await test('BUNDLED_THREATS has event-stream@3.3.6', () => assert(BUNDLED_THREATS.has('event-stream@3.3.6')));
  await test('blocks known malicious', async () => { const r = await verifyPackage('event-stream','3.3.6','npm'); assert(!r.passed); assert(r.threats.some(t=>t.type==='KNOWN_MALICIOUS')); });
  await test('blocks typosquat', async () => { const r = await verifyPackage('axois',null,'npm'); assert(!r.passed); assert(r.threats.some(t=>t.type==='TYPOSQUATTING')); });
  await test('passes safe package', async () => { const r = await verifyPackage('express',null,'npm'); assert(r.passed); assert(r.threats.length === 0); });
  await test('result has required fields', async () => { const r = await verifyPackage('chalk',null,'npm'); assert(typeof r.package==='string'); assert(typeof r.passed==='boolean'); assert(Array.isArray(r.threats)); assert(Array.isArray(r.warnings)); });
  await test('pip ecosystem warning', async () => { const r = await verifyPackage('numpy',null,'pip'); assert(r.passed); assert(r.warnings.some(w=>w.type==='PIP_LIMITED_VERIFICATION')); });
  await test('cargo ecosystem warning', async () => { const r = await verifyPackage('serde',null,'cargo'); assert(r.passed); assert(r.warnings.some(w=>w.type==='CARGO_LIMITED_VERIFICATION')); });
  console.log(`\n  ${passed} passed · ${failed} failed\n`);
  if (failed > 0) process.exit(1);
})();

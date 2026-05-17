'use strict';

const { logVerification, readAuditLog, getAuditSummary, verifyAuditChain, exportAuditReport, clearAuditLog, computeChainHash, AUDIT_FILE } = require('../src/audit');

let passed = 0; let failed = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (err) { console.log(`  ✗  ${name}\n     ${err.message}`); failed++; }
}

function assert(condition, msg) { if (!condition) throw new Error(msg || 'Assertion failed'); }

function mockResult(overrides = {}) {
  return { package:'test-pkg', version:'1.0.0', ecosystem:'npm', passed:true, threats:[], warnings:[], hash:'abc123', signature:{verified:false,method:'classical-sha256'}, timestamp:new Date().toISOString(), ...overrides };
}

clearAuditLog('CONFIRM_CLEAR');
console.log('\n  audit.js\n');

test('empty after clear', () => assert(readAuditLog().length === 0));
test('rejects wrong confirm', () => { try { clearAuditLog('WRONG'); throw new Error('Should throw'); } catch(err) { assert(err.message.includes('CONFIRM_CLEAR')); } });
test('writes entry', () => { logVerification(mockResult()); assert(readAuditLog().length === 1); });
test('entry has correct fields', () => { const e = readAuditLog()[0]; assert(e.package==='test-pkg'); assert(typeof e.chainHash==='string'); assert(e.chainHash.length===64); });
test('returns chain hash', () => { const h = logVerification(mockResult({package:'pkg2'})); assert(typeof h==='string' && h.length===64); });
test('chain valid on untampered log', () => { assert(verifyAuditChain().valid); });
test('detects tampering', () => {
  const fs = require('fs'); const raw = fs.readFileSync(AUDIT_FILE,'utf8');
  fs.writeFileSync(AUDIT_FILE, raw.slice(0,50) + (raw[50]==='a'?'b':'a') + raw.slice(51));
  assert(!verifyAuditChain().valid);
  fs.writeFileSync(AUDIT_FILE, raw);
});
test('summary counts correct', () => {
  clearAuditLog('CONFIRM_CLEAR');
  logVerification(mockResult({passed:true}));
  logVerification(mockResult({passed:false,threats:[{type:'KNOWN_MALICIOUS',severity:'CRITICAL',message:'test'}]}));
  logVerification(mockResult({passed:true,warnings:[{type:'SINGLE_MAINTAINER',severity:'MEDIUM',message:'w'}]}));
  const s = getAuditSummary();
  assert(s.total===3); assert(s.blocked===1); assert(s.warnings===1); assert(s.clean===2);
});
test('export report has required keys', () => { const r = exportAuditReport(); assert(r.report!==undefined); assert(r.summary!==undefined); assert(r.entries!==undefined); });
test('chainHash deterministic', () => { const e={package:'x',version:'1.0.0'}; assert(computeChainHash(e,'prev')===computeChainHash(e,'prev')); });
test('different prev = different hash', () => { const e={package:'x',version:'1.0.0'}; assert(computeChainHash(e,'prev1')!==computeChainHash(e,'prev2')); });

clearAuditLog('CONFIRM_CLEAR');
console.log(`\n  ${passed} passed · ${failed} failed\n`);
if (failed > 0) process.exit(1);

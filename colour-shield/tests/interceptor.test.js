'use strict';

const { parsePackageArg, detectEcosystem, extractPackages, ECOSYSTEM_MAP } = require('../src/interceptor');

let passed = 0; let failed = 0;

function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (err) { console.log(`  ✗  ${name}\n     ${err.message}`); failed++; }
}

function assert(condition, msg) { if (!condition) throw new Error(msg || 'Assertion failed'); }

console.log('\n  interceptor.js\n');

test('plain name', () => { const r=parsePackageArg('express'); assert(r.name==='express'); assert(r.version===null); });
test('name@version', () => { const r=parsePackageArg('express@4.18.0'); assert(r.name==='express'); assert(r.version==='4.18.0'); });
test('scoped package', () => { const r=parsePackageArg('@scope/pkg'); assert(r.name==='@scope/pkg'); assert(r.version===null); });
test('scoped with version', () => { const r=parsePackageArg('@scope/pkg@1.2.3'); assert(r.name==='@scope/pkg'); assert(r.version==='1.2.3'); });
test('babel/core scoped', () => { const r=parsePackageArg('@babel/core@7.0.0'); assert(r.name==='@babel/core'); assert(r.version==='7.0.0'); });
test('npm → npm', () => assert(detectEcosystem('npm')==='npm'));
test('yarn → npm', () => assert(detectEcosystem('yarn')==='npm'));
test('pnpm → npm', () => assert(detectEcosystem('pnpm')==='npm'));
test('bun → npm', () => assert(detectEcosystem('bun')==='npm'));
test('pip → pip', () => assert(detectEcosystem('pip')==='pip'));
test('pip3 → pip', () => assert(detectEcosystem('pip3')==='pip'));
test('cargo → cargo', () => assert(detectEcosystem('cargo')==='cargo'));
test('unknown → unknown', () => assert(detectEcosystem('brew')==='unknown'));
test('install extracts packages', () => { const p=extractPackages(['install','express','lodash']); assert(p.includes('express')); assert(p.includes('lodash')); });
test('filters flags', () => { const p=extractPackages(['install','express','--save-dev']); assert(p.includes('express')); assert(!p.includes('--save-dev')); });
test('add subcommand works', () => assert(extractPackages(['add','serde']).includes('serde')));
test('i shorthand works', () => assert(extractPackages(['i','express']).includes('express')));
test('non-install returns empty', () => assert(extractPackages(['run','build']).length===0));
test('filters relative paths', () => { const p=extractPackages(['install','./local','express']); assert(!p.includes('./local')); assert(p.includes('express')); });
test('filters URLs', () => { const p=extractPackages(['install','git+https://github.com/x/y','express']); assert(!p.some(x=>x.includes('://'))); });
test('empty args returns empty', () => assert(extractPackages([]).length===0));
test('scoped package preserved', () => assert(extractPackages(['install','@babel/core@7.0.0']).includes('@babel/core@7.0.0')));
test('ECOSYSTEM_MAP is a Map', () => assert(ECOSYSTEM_MAP instanceof Map));
test('covers major package managers', () => { for (const pm of ['npm','yarn','pnpm','pip','pip3','cargo']) assert(ECOSYSTEM_MAP.has(pm),`Missing: ${pm}`); });

console.log(`\n  ${passed} passed · ${failed} failed\n`);
if (failed > 0) process.exit(1);

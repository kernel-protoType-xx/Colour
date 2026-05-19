'use strict';
const https  = require('https');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const REGISTRY_PATH = path.join(os.homedir(), '.colour-shield', 'registry.json');

const PACKAGES = [...new Set([
  'lodash','chalk','commander','express','react','axios','moment',
  'webpack','eslint','prettier','typescript','jest','mocha','dotenv',
  'cors','helmet','mongoose','next','vue','svelte','vite','rollup',
  'esbuild','socket.io','passport','jsonwebtoken','bcrypt','nodemon',
  'cross-env','rimraf','glob','minimist','yargs','inquirer','ora',
  'boxen','semver','uuid','slugify','validator','date-fns','luxon',
  'dayjs','rxjs','ramda','underscore','async','bluebird','got',
  'node-fetch','superagent','qs','body-parser','cookie-parser','multer',
  'sharp','cheerio','puppeteer','redis','ioredis','pg','mysql2',
  'sqlite3','knex','typeorm','graphql','ws','bull','winston','pino',
  'morgan','debug','chai','sinon','nock','supertest','ts-node',
  'chokidar','fast-glob','execa','open','which','tar','mkdirp',
  'p-limit','p-map','ansi-colors','kleur','signal-exit','is-stream',
])];

function fetchMeta(pkg) {
  return new Promise((resolve) => {
    const req = https.get({
      hostname: 'registry.npmjs.org',
      path: '/' + encodeURIComponent(pkg) + '/latest',
      headers: { 'Accept': 'application/json', 'User-Agent': 'colour-shield/0.1.0' },
      timeout: 8000,
    }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

function hash(name, version, integrity) {
  return crypto.createHash('sha256').update('colour-shield:v1:' + name + ':' + version + ':' + integrity).digest('hex');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log('\n  COLOUR SHIELD — Stamper\n');
  const dir = path.dirname(REGISTRY_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const registry = { entries: [] };
  let stamped = 0; let failed = 0;

  for (const pkg of PACKAGES) {
    process.stdout.write('  > ' + pkg + '... ');
    const meta = await fetchMeta(pkg);
    if (!meta || !meta.version) { console.log('FAILED'); failed++; await sleep(100); continue; }
    const integrity = (meta.dist && meta.dist.integrity) ? meta.dist.integrity : '';
    registry.entries.push({
      package: pkg,
      version: meta.version,
      integrity,
      provenance: hash(pkg, meta.version, integrity),
      algorithm: 'SHA-256-provenance',
      signer: 'colour-foundation',
      stamped_at: new Date().toISOString(),
      pq_signed: false
    });
    stamped++;
    console.log('OK ' + meta.version);
    await sleep(150);
  }

  registry.total = registry.entries.length;
  registry.stamped_at = new Date().toISOString();
  fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2));

  const repoPath = '/content/Colour/colour-shield/registry/registry.json';
  const repoDir  = path.dirname(repoPath);
  if (!fs.existsSync(repoDir)) fs.mkdirSync(repoDir, { recursive: true });
  fs.writeFileSync(repoPath, JSON.stringify(registry, null, 2));

  console.log('\n  Stamped: ' + stamped + ' | Failed: ' + failed);
  console.log('  Total: ' + registry.entries.length);
  console.log('  Saved: ' + REGISTRY_PATH + '\n');
}

main().catch(console.error);

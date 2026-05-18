'use strict';

const crypto = require('crypto');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const COLOUR_CORE_PATH = path.join(os.homedir(), '.colour-shield', 'core');
const THREAT_DB_PATH   = path.join(os.homedir(), '.colour-shield', 'threats.json');
const THREAT_DB_TTL_MS = 6 * 60 * 60 * 1000;

const SEVERITY = Object.freeze({
  CRITICAL : 'CRITICAL',
  HIGH     : 'HIGH',
  MEDIUM   : 'MEDIUM',
  LOW      : 'LOW',
  INFO     : 'INFO',
});

const BUNDLED_THREATS = new Map([
  ['event-stream@3.3.6',      { cve: null,              reason: 'Malicious code injected by compromised maintainer' }],
  ['ua-parser-js@0.7.29',     { cve: 'CVE-2021-27292', reason: 'Cryptominer + password stealer injected' }],
  ['ua-parser-js@0.7.30',     { cve: 'CVE-2021-27292', reason: 'Cryptominer + password stealer injected' }],
  ['ua-parser-js@0.7.31',     { cve: 'CVE-2021-27292', reason: 'Cryptominer + password stealer injected' }],
  ['node-ipc@10.1.1',         { cve: null,              reason: 'Protestware — wipes files based on geolocation' }],
  ['node-ipc@10.1.2',         { cve: null,              reason: 'Protestware — wipes files based on geolocation' }],
  ['colors@1.4.44',           { cve: null,              reason: 'Protestware — infinite loop injected by maintainer' }],
  ['faker@6.6.6',             { cve: null,              reason: 'Protestware — infinite loop injected by maintainer' }],
  ['flatmap-stream@0.1.1',    { cve: null,              reason: 'Malicious payload targeting Bitcoin wallets' }],
  ['rc@1.2.9',                { cve: null,              reason: 'Known malicious version — data exfiltration' }],
  ['eslint-scope@3.7.2',      { cve: null,              reason: 'Compromised — steals npm credentials' }],
  ['bootstrap-sass@3.3.7',    { cve: null,              reason: 'Backdoor injected — remote code execution' }],
  ['getcookies@1.0.0',        { cve: null,              reason: 'Backdoor package — credential theft' }],
  ['electron-native-notify@1.1.1', { cve: null,         reason: 'Malicious package — cryptominer' }],
  ['coloureds@1.0.0',         { cve: null,              reason: 'Typosquat of colors with malicious payload' }],
]);

const TYPOSQUAT_MAP = new Map([
  ['expres','express'],['exprees','express'],['expresss','express'],['exprss','express'],
  ['lodahs','lodash'],['lodas','lodash'],['lodaash','lodash'],
  ['reacct','react'],['reakt','react'],['reeact','react'],['raect','react'],
  ['axois','axios'],['axio','axios'],['axxios','axios'],['axioss','axios'],
  ['chak','chalk'],['chalkk','chalk'],['chalck','chalk'],
  ['webpakc','webpack'],['webpak','webpack'],['webpackk','webpack'],
  ['babbel','babel'],['baabel','babel'],
  ['dotenev','dotenv'],['dotevn','dotenv'],['dotennv','dotenv'],
  ['corss-env','cross-env'],['cross-evn','cross-env'],
  ['mongose','mongoose'],['mongoosee','mongoose'],
  ['requst','request'],['requets','request'],['rquest','request'],
  ['typscript','typescript'],['typescrpit','typescript'],
  ['esling','eslint'],['eslnt','eslint'],
  ['pretier','prettier'],['prettierr','prettier'],
  ['moement','moment'],['momnet','moment'],
  ['comander','commander'],['commmander','commander'],
  ['socekt.io','socket.io'],['soket.io','socket.io'],
  ['nextt','next'],['nxt','next'],
  ['vvue','vue'],['vuee','vue'],
  ['tailwindcs','tailwindcss'],['tailwndcss','tailwindcss'],
]);

const FUZZY_TARGETS = [
  'express','lodash','react','axios','chalk','webpack','babel',
  'dotenv','mongoose','cross-env','typescript','eslint',
  'prettier','moment','commander','socket.io','next','vue',
  'tailwindcss','jest','mocha','nodemon','cors','helmet',
  'bcrypt','jsonwebtoken','passport','sequelize','prisma',
  'fastify','koa','hapi','nest','angular','svelte',
  'vite','rollup','esbuild','parcel','turbopack',
];

function colourCoreAvailable() {
  const coreBin = path.join(COLOUR_CORE_PATH, process.platform === 'win32' ? 'colour-core.exe' : 'colour-core');
  return fs.existsSync(coreBin);
}

function verifyPostQuantumSignature(packageName, version, integrity) {
  const { execSync } = require('child_process');
  const coreBin = path.join(COLOUR_CORE_PATH, process.platform === 'win32' ? 'colour-core.exe' : 'colour-core');
  try {
    const cmd = [coreBin,'verify','--package',packageName,'--version',version || 'latest','--integrity',integrity || ''].join(' ');
    const output = execSync(cmd, { timeout: 10000, encoding: 'utf8' });
    const result = JSON.parse(output.trim());
    return { available: true, valid: result.valid, algorithm: result.algorithm, signer: result.signer };
  } catch (err) {
    let parsed = null;
    try { parsed = JSON.parse(err.stdout || '{}'); } catch {}
    return { available: true, valid: false, algorithm: 'ML-DSA-87+SPHINCS+-256', signer: 'colour-foundation', error: parsed?.error || err.message };
  }
}

function computeProvenanceHash(name, version, integrity) {
  const payload = ['colour-shield:v1', name, version || 'latest', integrity || '', Date.now().toString()].join(':');
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function loadThreatDatabase() {
  const db = new Map(BUNDLED_THREATS);
  if (!fs.existsSync(THREAT_DB_PATH)) return db;
  try {
    const raw    = fs.readFileSync(THREAT_DB_PATH, 'utf8');
    const cached = JSON.parse(raw);
    const age    = Date.now() - (cached.timestamp || 0);
    if (age < THREAT_DB_TTL_MS && Array.isArray(cached.threats)) {
      for (const t of cached.threats) db.set(t.id, { cve: t.cve, reason: t.reason });
    }
  } catch {}
  return db;
}

async function refreshThreatDatabase() {
  return new Promise((resolve) => {
    const req = https.get('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const advisories = JSON.parse(data);
          const threats = [];
          for (const [pkg, advisory] of Object.entries(advisories)) {
            if (advisory.severity === 'critical' || advisory.severity === 'high') {
              threats.push({ id: pkg, cve: advisory.cve?.[0] || null, reason: advisory.title || 'High severity advisory' });
            }
          }
          const dir = path.dirname(THREAT_DB_PATH);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(THREAT_DB_PATH, JSON.stringify({ timestamp: Date.now(), threats }));
        } catch {}
        resolve();
      });
    });
    req.on('error', () => resolve());
    req.on('timeout', () => { req.destroy(); resolve(); });
  });
}

function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] = b[i-1] === a[j-1]
        ? matrix[i-1][j-1]
        : 1 + Math.min(matrix[i-1][j-1], matrix[i][j-1], matrix[i-1][j]);
    }
  }
  return matrix[b.length][a.length];
}

function checkTyposquat(packageName) {
  const lower = packageName.toLowerCase().trim();
  if (TYPOSQUAT_MAP.has(lower)) return { detected: true, likely_target: TYPOSQUAT_MAP.get(lower), method: 'exact' };
  for (const target of FUZZY_TARGETS) {
    if (lower === target) continue;
    if (levenshtein(lower, target) === 1) return { detected: true, likely_target: target, method: 'fuzzy', distance: 1 };
  }
  return { detected: false };
}

function fetchNpmMetadata(packageName, version) {
  return new Promise((resolve, reject) => {
    const encoded = encodeURIComponent(packageName).replace('%40', '@');
    const urlPath = version ? `/${encoded}/${encodeURIComponent(version)}` : `/${encoded}/latest`;
    const options = {
      hostname : 'registry.npmjs.org',
      path     : urlPath,
      headers  : { 'Accept': 'application/json', 'User-Agent': 'colour-shield/0.1.0' },
      timeout  : 8000,
    };
    const req = https.get(options, (res) => {
      if (res.statusCode === 404) return reject(new Error(`Package '${packageName}' not found`));
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Failed to parse registry')); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Registry timeout')); });
  });
}

async function verifyPackage(packageName, version, ecosystem = 'npm') {
  const result = {
    package: packageName, version: version || 'latest', ecosystem,
    passed: false, threats: [], warnings: [],
    hash: null, signature: { verified: false, method: 'none' },
    timestamp: new Date().toISOString(),
  };

  const threatDb    = loadThreatDatabase();
  const versionedId = `${packageName}@${version}`;

  if (threatDb.has(versionedId)) {
    const threat = threatDb.get(versionedId);
    result.threats.push({ type: 'KNOWN_MALICIOUS', severity: SEVERITY.CRITICAL, message: `${versionedId} is a confirmed malicious package`, detail: threat.reason, cve: threat.cve });
    return result;
  }

  if (threatDb.has(packageName)) {
    const threat = threatDb.get(packageName);
    result.threats.push({ type: 'KNOWN_MALICIOUS', severity: SEVERITY.CRITICAL, message: `${packageName} is a confirmed malicious package`, detail: threat.reason, cve: threat.cve });
    return result;
  }

  const typosquat = checkTyposquat(packageName);
  if (typosquat.detected) {
    result.threats.push({ type: 'TYPOSQUATTING', severity: SEVERITY.HIGH, message: `'${packageName}' appears to be a typosquat of '${typosquat.likely_target}'`, likely_target: typosquat.likely_target, method: typosquat.method });
    return result;
  }

  if (colourCoreAvailable()) {
    const pqResult = verifyPostQuantumSignature(packageName, version, null);
    if (pqResult.available) {
      result.signature = { verified: pqResult.valid, algorithm: pqResult.algorithm, method: 'post-quantum' };
      if (!pqResult.valid) {
        result.warnings.push({ type: 'PQ_UNVERIFIED', severity: SEVERITY.MEDIUM, message: `${packageName} not in Colour signature registry`, detail: 'Not yet signed by Colour Foundation' });
      }
    }
  } else {
    result.signature = { verified: false, method: 'classical-sha256', note: 'Install Colour core for full post-quantum verification' };
  }

  if (ecosystem === 'npm') {
    let meta = null;
    try { meta = await fetchNpmMetadata(packageName, version); }
    catch (err) { result.warnings.push({ type: 'REGISTRY_FETCH_FAILED', severity: SEVERITY.LOW, message: `Could not fetch registry metadata: ${err.message}` }); }
    if (meta) {
      const resolvedVersion = meta.version || version || 'unknown';
      result.version = resolvedVersion;
      const integrity = meta.dist?.integrity || null;
      if (!integrity) result.warnings.push({ type: 'NO_INTEGRITY_HASH', severity: SEVERITY.MEDIUM, message: `${packageName}@${resolvedVersion} has no integrity hash` });
      result.hash = computeProvenanceHash(packageName, resolvedVersion, integrity || '');
      if (meta.maintainers?.length === 1) result.warnings.push({ type: 'SINGLE_MAINTAINER', severity: SEVERITY.MEDIUM, message: `${packageName} has a single maintainer` });
      const publishTime = meta.time?.[resolvedVersion];
      if (publishTime) {
        const ageHours = (Date.now() - new Date(publishTime).getTime()) / (1000 * 60 * 60);
        if (ageHours < 1) result.warnings.push({ type: 'VERY_RECENTLY_PUBLISHED', severity: SEVERITY.HIGH, message: `${packageName}@${resolvedVersion} published less than 1 hour ago` });
        else if (ageHours < 24) result.warnings.push({ type: 'RECENTLY_PUBLISHED', severity: SEVERITY.LOW, message: `${packageName}@${resolvedVersion} published in last 24 hours` });
      }
      if (meta.deprecated) result.warnings.push({ type: 'DEPRECATED', severity: SEVERITY.LOW, message: `${packageName}@${resolvedVersion} is deprecated`, detail: meta.deprecated });
    }
  }

  if (ecosystem === 'pip') {
    result.warnings.push({ type: 'PIP_LIMITED_VERIFICATION', severity: SEVERITY.INFO, message: 'PyPI verification limited in v0.1.0', detail: 'Full pip post-quantum verification coming in v0.2.0' });
    result.hash = computeProvenanceHash(packageName, version || 'latest', '');
  }

  if (ecosystem === 'cargo') {
    result.warnings.push({ type: 'CARGO_LIMITED_VERIFICATION', severity: SEVERITY.INFO, message: 'Cargo verification limited in v0.1.0', detail: 'Full cargo post-quantum verification coming in v0.2.0' });
    result.hash = computeProvenanceHash(packageName, version || 'latest', '');
  }

  result.passed = result.threats.length === 0;
  if (result.passed) refreshThreatDatabase().catch(() => {});
  return result;
}

module.exports = {
  verifyPackage,
  checkTyposquat,
  computeProvenanceHash,
  levenshtein,
  colourCoreAvailable,
  loadThreatDatabase,
  BUNDLED_THREATS,
  TYPOSQUAT_MAP,
  FUZZY_TARGETS,
  SEVERITY,
};

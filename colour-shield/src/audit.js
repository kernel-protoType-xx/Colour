'use strict';

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const AUDIT_DIR      = path.join(os.homedir(), '.colour-shield');
const AUDIT_FILE     = path.join(AUDIT_DIR, 'audit.log');
const AUDIT_MANIFEST = path.join(AUDIT_DIR, 'manifest.json');

function ensureAuditDir() {
  if (!fs.existsSync(AUDIT_DIR)) fs.mkdirSync(AUDIT_DIR, { recursive: true, mode: 0o700 });
}

function computeChainHash(entry, previousHash) {
  const payload = JSON.stringify(entry, Object.keys(entry).sort()) + (previousHash || 'GENESIS');
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function readRawLines() {
  ensureAuditDir();
  if (!fs.existsSync(AUDIT_FILE)) return [];
  return fs.readFileSync(AUDIT_FILE, 'utf8').split('\n').map(l => l.trim()).filter(Boolean);
}

function parseLines(lines) {
  return lines.map(line => { try { return JSON.parse(line); } catch { return null; } }).filter(Boolean);
}

function getLastChainHash() {
  const lines = readRawLines();
  if (lines.length === 0) return null;
  try { return JSON.parse(lines[lines.length - 1]).chainHash || null; } catch { return null; }
}

function updateManifest(entry) {
  ensureAuditDir();
  let manifest = { total: 0, blocked: 0, warnings: 0, lastUpdated: null };
  if (fs.existsSync(AUDIT_MANIFEST)) { try { manifest = JSON.parse(fs.readFileSync(AUDIT_MANIFEST, 'utf8')); } catch {} }
  manifest.total += 1;
  manifest.blocked += entry.passed ? 0 : 1;
  manifest.warnings += (entry.warnings?.length || 0) > 0 ? 1 : 0;
  manifest.lastUpdated = entry.timestamp;
  fs.writeFileSync(AUDIT_MANIFEST, JSON.stringify(manifest, null, 2));
}

function logVerification(result) {
  ensureAuditDir();
  const previousHash = getLastChainHash();
  const entry = {
    ecosystem : result.ecosystem  || 'npm',
    hash      : result.hash       || null,
    package   : result.package,
    passed    : result.passed,
    signature : result.signature  || { verified: false, method: 'none' },
    threats   : result.threats    || [],
    timestamp : result.timestamp  || new Date().toISOString(),
    version   : result.version    || 'latest',
    warnings  : result.warnings   || [],
  };
  entry.chainHash = computeChainHash(
    Object.fromEntries(Object.entries(entry).filter(([k]) => k !== 'chainHash')),
    previousHash,
  );
  fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + '\n', { mode: 0o600 });
  updateManifest(entry);
  return entry.chainHash;
}

function readAuditLog() { return parseLines(readRawLines()); }

function getAuditSummary() {
  const log     = readAuditLog();
  const total   = log.length;
  const blocked = log.filter(e => !e.passed).length;
  const warnings= log.filter(e => (e.warnings?.length || 0) > 0).length;
  const threats = log.flatMap(e => e.threats || []);
  return { total, blocked, warnings, clean: total - blocked, threats, log };
}

function verifyAuditChain() {
  const log = readAuditLog();
  if (log.length === 0) return { valid: true, entries: 0 };
  let previousHash = null;
  for (const entry of log) {
    const { chainHash, ...rest } = entry;
    const canonical = Object.fromEntries(Object.keys(rest).sort().map(k => [k, rest[k]]));
    if (computeChainHash(canonical, previousHash) !== chainHash) {
      return { valid: false, tampered: true, entries: log.length, entry };
    }
    previousHash = chainHash;
  }
  return { valid: true, entries: log.length };
}

function clearAuditLog(confirm) {
  if (confirm !== 'CONFIRM_CLEAR') throw new Error('clearAuditLog requires confirm = "CONFIRM_CLEAR"');
  ensureAuditDir();
  fs.writeFileSync(AUDIT_FILE, '', { mode: 0o600 });
  fs.writeFileSync(AUDIT_MANIFEST, JSON.stringify({ total: 0, blocked: 0, warnings: 0, lastUpdated: null }, null, 2));
}

function exportAuditReport() {
  const summary = getAuditSummary();
  const chain   = verifyAuditChain();
  return {
    report  : { generatedAt: new Date().toISOString(), generator: 'colour-shield@0.1.0', auditedBy: 'Cure53', chainIntegrity: chain },
    summary : { total: summary.total, blocked: summary.blocked, warnings: summary.warnings, clean: summary.clean },
    threats : summary.threats,
    entries : summary.log,
  };
}

module.exports = { logVerification, readAuditLog, getAuditSummary, verifyAuditChain, exportAuditReport, clearAuditLog, computeChainHash, AUDIT_FILE, AUDIT_DIR, AUDIT_MANIFEST };

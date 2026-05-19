'use strict';

/**
 * Colour Shield — License Key Generator
 *
 * Run this script to generate a license key for a new customer.
 * Keys are cryptographically signed and domain-bound.
 *
 * Usage:
 *   node keygen.js --plan teams --domain stripe.com --email cto@stripe.com
 *   node keygen.js --plan business --domain shopify.com --email security@shopify.com
 *   node keygen.js --plan enterprise --domain google.com --email infra@google.com
 *   node keygen.js --list
 *   node keygen.js --revoke CS-XXXX-XXXX-XXXX-XXXX
 *
 * Colour Foundation — buildwithcolours@gmail.com
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

// ── Config ────────────────────────────────────────────────────────────────────

const LICENCE_DB   = path.join(__dirname, 'licences.json');
const SECRET       = process.env.COLOUR_LICENCE_SECRET || 'colour-foundation-secret-change-in-production';

const PLANS = {
  teams: {
    name       : 'Teams',
    price      : '$299/month',
    duration   : 30,
    features   : ['unlimited_scans', 'compliance_reports', 'audit_export', 'priority_support'],
    max_devs   : 10,
  },
  business: {
    name       : 'Business',
    price      : '$999/month',
    duration   : 30,
    features   : ['unlimited_scans', 'compliance_reports', 'audit_export', 'private_registry', 'sso', 'priority_support'],
    max_devs   : 50,
  },
  enterprise: {
    name       : 'Enterprise',
    price      : '$2,500/month',
    duration   : 30,
    features   : ['unlimited_scans', 'compliance_reports', 'audit_export', 'private_registry', 'sso', 'dedicated_support', 'custom_policies', 'air_gapped'],
    max_devs   : -1, // unlimited
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function loadDb() {
  if (!fs.existsSync(LICENCE_DB)) return { licences: [] };
  try { return JSON.parse(fs.readFileSync(LICENCE_DB, 'utf8')); }
  catch { return { licences: [] }; }
}

function saveDb(db) {
  fs.writeFileSync(LICENCE_DB, JSON.stringify(db, null, 2));
}

function generateKey() {
  const segments = [];
  for (let i = 0; i < 4; i++) {
    segments.push(crypto.randomBytes(3).toString('hex').toUpperCase());
  }
  return 'CS-' + segments.join('-');
}

function signKey(key, domain, plan, expiresAt) {
  const payload = `${key}:${domain}:${plan}:${expiresAt}`;
  return crypto.createHmac('sha256', SECRET).update(payload).digest('hex').slice(0, 16);
}

function formatDate(date) {
  return new Date(date).toISOString().split('T')[0];
}

function getFlag(args, flag) {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : null;
}

// ── Commands ──────────────────────────────────────────────────────────────────

function cmdGenerate(plan, domain, email, note) {
  if (!PLANS[plan]) {
    console.error(`Unknown plan: ${plan}`);
    console.error(`Available plans: ${Object.keys(PLANS).join(', ')}`);
    process.exit(1);
  }

  if (!domain) { console.error('--domain required'); process.exit(1); }
  if (!email)  { console.error('--email required');  process.exit(1); }

  const planConfig  = PLANS[plan];
  const key         = generateKey();
  const issuedAt    = Date.now();
  const expiresAt   = issuedAt + (planConfig.duration * 24 * 60 * 60 * 1000);
  const signature   = signKey(key, domain, plan, expiresAt);

  const licence = {
    key,
    signature,
    plan,
    domain       : domain.toLowerCase().trim(),
    email        : email.toLowerCase().trim(),
    note         : note || '',
    issued_at    : new Date(issuedAt).toISOString(),
    expires_at   : new Date(expiresAt).toISOString(),
    active       : true,
    features     : planConfig.features,
    max_devs     : planConfig.max_devs,
  };

  const db = loadDb();
  db.licences.push(licence);
  saveDb(db);

  console.log('');
  console.log('  ◆ COLOUR SHIELD — Licence Generated');
  console.log('');
  console.log(`  Plan        ${planConfig.name} (${planConfig.price})`);
  console.log(`  Customer    ${email}`);
  console.log(`  Domain      ${domain}`);
  console.log(`  Issued      ${formatDate(issuedAt)}`);
  console.log(`  Expires     ${formatDate(expiresAt)}`);
  console.log(`  Max devs    ${planConfig.max_devs === -1 ? 'Unlimited' : planConfig.max_devs}`);
  console.log('');
  console.log('  ┌─────────────────────────────────────────┐');
  console.log(`  │  LICENCE KEY: ${key}  │`);
  console.log('  └─────────────────────────────────────────┘');
  console.log('');
  console.log('  Features:');
  for (const f of planConfig.features) {
    console.log(`    ✓ ${f.replace(/_/g, ' ')}`);
  }
  console.log('');
  console.log('  Email this to the customer:');
  console.log('  ─────────────────────────────────────────');
  console.log(`  Subject: Your Colour Shield ${planConfig.name} Licence`);
  console.log('');
  console.log(`  Hi,`);
  console.log('');
  console.log(`  Your Colour Shield ${planConfig.name} licence is ready.`);
  console.log('');
  console.log(`  Licence Key: ${key}`);
  console.log(`  Plan: ${planConfig.name}`);
  console.log(`  Expires: ${formatDate(expiresAt)}`);
  console.log('');
  console.log('  Activate with:');
  console.log(`  colour-shield config --license ${key}`);
  console.log('');
  console.log('  buildwithcolours@gmail.com');
  console.log('  ─────────────────────────────────────────');
  console.log('');
}

function cmdList() {
  const db = loadDb();
  if (db.licences.length === 0) {
    console.log('\n  No licences issued yet.\n');
    return;
  }

  console.log('');
  console.log('  ◆ COLOUR SHIELD — Licence Registry');
  console.log('');
  console.log('  KEY                        PLAN        DOMAIN                EXPIRES     STATUS');
  console.log('  ─────────────────────────────────────────────────────────────────────────────────');

  const now = Date.now();
  for (const l of db.licences) {
    const expired = new Date(l.expires_at).getTime() < now;
    const status  = !l.active ? 'REVOKED' : expired ? 'EXPIRED' : 'ACTIVE';
    const domain  = l.domain.padEnd(20);
    const plan    = l.plan.padEnd(10);
    const expires = formatDate(l.expires_at);
    console.log(`  ${l.key}  ${plan}  ${domain}  ${expires}  ${status}`);
  }

  const active  = db.licences.filter(l => l.active && new Date(l.expires_at).getTime() > now).length;
  const expired = db.licences.filter(l => new Date(l.expires_at).getTime() < now).length;
  const revoked = db.licences.filter(l => !l.active).length;

  console.log('');
  console.log(`  Total: ${db.licences.length}  Active: ${active}  Expired: ${expired}  Revoked: ${revoked}`);
  console.log('');
}

function cmdRevoke(key) {
  const db = loadDb();
  const licence = db.licences.find(l => l.key === key);
  if (!licence) { console.error(`Licence not found: ${key}`); process.exit(1); }
  licence.active = false;
  licence.revoked_at = new Date().toISOString();
  saveDb(db);
  console.log(`\n  ✓ Licence ${key} revoked.\n`);
}

function cmdVerify(key, domain) {
  const db = loadDb();
  const licence = db.licences.find(l => l.key === key);

  if (!licence) {
    console.log('\n  ✗ Licence not found.\n');
    process.exit(1);
  }

  const now     = Date.now();
  const expired = new Date(licence.expires_at).getTime() < now;

  if (!licence.active) {
    console.log('\n  ✗ Licence has been revoked.\n');
    process.exit(1);
  }

  if (expired) {
    console.log('\n  ✗ Licence has expired.\n');
    process.exit(1);
  }

  if (domain && licence.domain !== domain.toLowerCase().trim()) {
    console.log('\n  ✗ Licence domain mismatch.\n');
    process.exit(1);
  }

  console.log('');
  console.log('  ✓ Licence is VALID');
  console.log(`  Plan     : ${licence.plan}`);
  console.log(`  Domain   : ${licence.domain}`);
  console.log(`  Expires  : ${formatDate(licence.expires_at)}`);
  console.log(`  Features : ${licence.features.join(', ')}`);
  console.log('');
}

function cmdHelp() {
  console.log('');
  console.log('  ◆ COLOUR SHIELD — Licence Manager');
  console.log('');
  console.log('  Commands:');
  console.log('');
  console.log('  Generate a licence:');
  console.log('    node keygen.js --plan teams --domain company.com --email cto@company.com');
  console.log('    node keygen.js --plan business --domain company.com --email cto@company.com');
  console.log('    node keygen.js --plan enterprise --domain company.com --email cto@company.com');
  console.log('');
  console.log('  List all licences:');
  console.log('    node keygen.js --list');
  console.log('');
  console.log('  Verify a licence:');
  console.log('    node keygen.js --verify CS-XXXX-XXXX-XXXX-XXXX');
  console.log('    node keygen.js --verify CS-XXXX-XXXX-XXXX-XXXX --domain company.com');
  console.log('');
  console.log('  Revoke a licence:');
  console.log('    node keygen.js --revoke CS-XXXX-XXXX-XXXX-XXXX');
  console.log('');
  console.log('  Plans:');
  for (const [id, plan] of Object.entries(PLANS)) {
    console.log(`    ${id.padEnd(12)} ${plan.price}  — ${plan.max_devs === -1 ? 'Unlimited' : plan.max_devs} devs  — ${plan.duration} days`);
  }
  console.log('');
}

// ── Entry ─────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes('--list'))   { cmdList(); }
else if (args.includes('--revoke')) { cmdRevoke(args[args.indexOf('--revoke') + 1]); }
else if (args.includes('--verify')) {
  cmdVerify(
    args[args.indexOf('--verify') + 1],
    getFlag(args, '--domain')
  );
}
else if (args.includes('--plan')) {
  cmdGenerate(
    getFlag(args, '--plan'),
    getFlag(args, '--domain'),
    getFlag(args, '--email'),
    getFlag(args, '--note'),
  );
}
else { cmdHelp(); }

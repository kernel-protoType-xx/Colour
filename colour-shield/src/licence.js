'use strict';

/**
 * Colour Shield — Licence Validator
 *
 * Validates licence keys for enterprise features.
 * Keys are domain-bound, time-limited, and cryptographically signed.
 *
 * Colour Foundation — buildwithcolours@gmail.com
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const https  = require('https');

// ── Config ────────────────────────────────────────────────────────────────────

const LICENCE_FILE   = path.join(os.homedir(), '.colour-shield', 'licence.json');
const CACHE_FILE     = path.join(os.homedir(), '.colour-shield', 'licence.cache.json');
const VALIDATE_URL   = 'https://api.colour.dev/v1/licence/validate'; // future hosted validation
const CACHE_TTL_MS   = 24 * 60 * 60 * 1000; // 24 hours
const SECRET         = process.env.COLOUR_LICENCE_SECRET || 'colour-foundation-secret-change-in-production';

// ── Feature map ───────────────────────────────────────────────────────────────

const FEATURES = {
  unlimited_scans   : 'Unlimited package scans',
  compliance_reports: 'Compliance report generation',
  audit_export      : 'Full audit log export',
  private_registry  : 'Private package registry',
  sso               : 'SSO integration (Okta, AD)',
  priority_support  : 'Priority support',
  dedicated_support : 'Dedicated support engineer',
  custom_policies   : 'Custom org-wide policies',
  air_gapped        : 'Air-gapped deployment',
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function ensureDir() {
  const dir = path.dirname(LICENCE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function signKey(key, domain, plan, expiresAt) {
  const payload = `${key}:${domain}:${plan}:${expiresAt}`;
  return crypto.createHmac('sha256', SECRET).update(payload).digest('hex').slice(0, 16);
}

function loadStoredLicence() {
  if (!fs.existsSync(LICENCE_FILE)) return null;
  try { return JSON.parse(fs.readFileSync(LICENCE_FILE, 'utf8')); }
  catch { return null; }
}

function loadCache() {
  if (!fs.existsSync(CACHE_FILE)) return null;
  try {
    const cache = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    const age = Date.now() - (cache.cached_at || 0);
    if (age > CACHE_TTL_MS) return null;
    return cache;
  } catch { return null; }
}

function saveCache(result) {
  ensureDir();
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify({ ...result, cached_at: Date.now() }));
  } catch {}
}

// ── Validation ────────────────────────────────────────────────────────────────

/**
 * Validates a licence key locally using HMAC signature verification.
 * Falls back to this when network is unavailable.
 */
function validateLocally(licence) {
  if (!licence || !licence.key || !licence.plan || !licence.domain || !licence.expires_at) {
    return { valid: false, reason: 'Invalid licence format' };
  }

  const now     = Date.now();
  const expires = new Date(licence.expires_at).getTime();

  if (expires < now) {
    return { valid: false, reason: 'Licence expired', expired: true };
  }

  const expectedSig = signKey(licence.key, licence.domain, licence.plan, expires);
  if (licence.signature !== expectedSig) {
    return { valid: false, reason: 'Invalid licence signature' };
  }

  return {
    valid    : true,
    key      : licence.key,
    plan     : licence.plan,
    domain   : licence.domain,
    expires  : licence.expires_at,
    features : licence.features || [],
    max_devs : licence.max_devs || 10,
  };
}

/**
 * Validates a licence key against the Colour Foundation API.
 * Used for online validation with revocation checking.
 */
function validateOnline(key, domain) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ key, domain });
    const options = {
      hostname : 'api.colour.dev',
      path     : '/v1/licence/validate',
      method   : 'POST',
      headers  : {
        'Content-Type'   : 'application/json',
        'Content-Length' : Buffer.byteLength(body),
        'User-Agent'     : 'colour-shield/0.1.0',
      },
      timeout  : 5000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(null); }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Saves a licence key to local storage.
 * Called when developer runs: colour-shield config --license KEY
 */
function storeLicence(key, domain) {
  ensureDir();

  // Parse the key format CS-XXXX-XXXX-XXXX-XXXX
  if (!key.startsWith('CS-')) {
    return { success: false, error: 'Invalid licence key format. Keys start with CS-' };
  }

  const licence = { key, domain: domain || os.hostname(), stored_at: new Date().toISOString() };
  fs.writeFileSync(LICENCE_FILE, JSON.stringify(licence, null, 2));

  return { success: true, message: `Licence ${key} stored successfully` };
}

/**
 * Main validation function.
 * Checks cache first, then local signature, then online.
 */
async function validateLicence(options = {}) {
  const stored = loadStoredLicence();

  // No licence stored
  if (!stored) {
    return {
      valid    : false,
      plan     : 'free',
      features : [],
      reason   : 'No licence key found. Run: colour-shield config --license YOUR_KEY',
    };
  }

  // Check cache
  const cache = loadCache();
  if (cache && cache.key === stored.key) {
    return cache;
  }

  // Try online validation first
  if (!options.offline) {
    const online = await validateOnline(stored.key, stored.domain);
    if (online && online.valid !== undefined) {
      saveCache({ ...online, key: stored.key });
      return online;
    }
  }

  // Fall back to local validation
  const local = validateLocally(stored);
  if (local.valid) saveCache({ ...local, key: stored.key });
  return local;
}

/**
 * Checks if a specific feature is available under the current licence.
 */
async function hasFeature(featureName) {
  const result = await validateLicence();
  if (!result.valid) return false;
  return result.features && result.features.includes(featureName);
}

/**
 * Returns the current licence status for display.
 */
async function getLicenceStatus() {
  const result = await validateLicence();
  const stored = loadStoredLicence();

  if (!result.valid) {
    return {
      status  : 'free',
      plan    : 'Free',
      message : result.reason || 'No licence',
      features: [],
    };
  }

  const daysLeft = Math.ceil(
    (new Date(result.expires).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
  );

  return {
    status   : 'active',
    plan     : result.plan,
    key      : stored?.key,
    domain   : result.domain,
    expires  : result.expires,
    days_left: daysLeft,
    features : result.features,
    max_devs : result.max_devs,
  };
}

/**
 * Clears the stored licence and cache.
 */
function clearLicence() {
  try {
    if (fs.existsSync(LICENCE_FILE)) fs.unlinkSync(LICENCE_FILE);
    if (fs.existsSync(CACHE_FILE))   fs.unlinkSync(CACHE_FILE);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

module.exports = {
  storeLicence,
  validateLicence,
  hasFeature,
  getLicenceStatus,
  clearLicence,
  validateLocally,
  FEATURES,
};

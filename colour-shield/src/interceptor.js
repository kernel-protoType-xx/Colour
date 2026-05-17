'use strict';

const { spawn }           = require('child_process');
const { verifyPackage }   = require('./verifier');
const { logVerification } = require('./audit');

const INSTALL_SUBCOMMANDS = new Set(['install', 'add', 'i', 'isntall']);

const ECOSYSTEM_MAP = new Map([
  ['npm','npm'],['yarn','npm'],['pnpm','npm'],['bun','npm'],['npx','npm'],
  ['pip','pip'],['pip3','pip'],['poetry','pip'],
  ['cargo','cargo'],
]);

function detectEcosystem(command) { return ECOSYSTEM_MAP.get(command.toLowerCase()) || 'unknown'; }

function parsePackageArg(arg) {
  if (arg.startsWith('@')) {
    const rest  = arg.slice(1);
    const atIdx = rest.indexOf('@');
    if (atIdx === -1) return { name: '@' + rest, version: null };
    return { name: '@' + rest.slice(0, atIdx), version: rest.slice(atIdx + 1) || null };
  }
  const atIdx = arg.indexOf('@');
  if (atIdx === -1) return { name: arg, version: null };
  return { name: arg.slice(0, atIdx), version: arg.slice(atIdx + 1) || null };
}

function extractPackages(args) {
  if (!args || args.length === 0) return [];
  const subcommand = args[0]?.toLowerCase();
  if (!INSTALL_SUBCOMMANDS.has(subcommand)) return [];
  return args.slice(1).filter(arg =>
    arg && !arg.startsWith('-') && !arg.startsWith('.') &&
    !arg.startsWith('/') && !arg.startsWith('~') &&
    !arg.includes('://') && arg !== 'install' && arg !== 'add'
  );
}

function runCommand(command, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, { stdio: 'inherit', shell: process.platform === 'win32' });
    proc.on('close', (code) => {
      if (code === 0) resolve(0);
      else reject(Object.assign(new Error(`${command} exited with code ${code}`), { exitCode: code }));
    });
    proc.on('error', (err) => {
      if (err.code === 'ENOENT') reject(new Error(`Command not found: '${command}'`));
      else reject(err);
    });
  });
}

async function intercept(command, args, options = {}) {
  const { logger, onBlock } = options;
  const ecosystem = detectEcosystem(command);
  const packages  = extractPackages(args);
  if (packages.length === 0) return runCommand(command, args);

  const blocked = [];
  const warned  = [];

  for (const pkg of packages) {
    const { name, version } = parsePackageArg(pkg);
    if (logger?.verifying) logger.verifying(name, version);
    let result;
    try { result = await verifyPackage(name, version, ecosystem); }
    catch (err) {
      result = {
        package: name, version: version || 'latest', ecosystem,
        passed: true, threats: [],
        warnings: [{ type: 'VERIFICATION_ERROR', severity: 'LOW', message: `Could not verify: ${err.message}` }],
        hash: null, signature: { verified: false, method: 'error' },
        timestamp: new Date().toISOString(),
      };
    }
    try { logVerification(result); } catch {}
    if (!result.passed) {
      blocked.push({ pkg, result });
      if (logger?.blocked) logger.blocked(result);
    } else if (result.warnings.length > 0) {
      warned.push({ pkg, result });
      if (logger?.warned) logger.warned(result);
    } else {
      if (logger?.verified) logger.verified(result);
    }
  }

  if (blocked.length > 0) {
    if (onBlock) onBlock(blocked);
    throw Object.assign(
      new Error(`BLOCKED: ${blocked.length} package(s) failed: ${blocked.map(b => b.pkg).join(', ')}`),
      { blocked, code: 'CS_BLOCKED' }
    );
  }

  if (warned.length > 0 && logger?.warningsSummary) logger.warningsSummary(warned);
  return runCommand(command, args);
}

module.exports = { intercept, parsePackageArg, detectEcosystem, extractPackages, runCommand, INSTALL_SUBCOMMANDS, ECOSYSTEM_MAP };

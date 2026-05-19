#!/usr/bin/env node
'use strict';

/**
 * Colour Shield — CLI
 *
 * colour-shield npm install express
 * colour-shield pip install requests
 * colour-shield cargo add serde
 * colour-shield scan axios
 * colour-shield audit
 * colour-shield report        [paid]
 * colour-shield config --license KEY
 * colour-shield licence --status
 * colour-shield test
 *
 * Colour Foundation — buildwithcolours@gmail.com
 * Audited by Cure53
 */

const { program } = require('commander');
const { intercept }     = require('./interceptor');
const { verifyPackage } = require('./verifier');
const { getAuditSummary, verifyAuditChain, exportAuditReport, AUDIT_FILE } = require('./audit');
const { storeLicence, getLicenceStatus, clearLicence, validateLicence } = require('./licence');

// ── Terminal helpers ──────────────────────────────────────────────────────────

const T = {
  bold   : s => `\x1b[1m${s}\x1b[0m`,
  dim    : s => `\x1b[2m${s}\x1b[0m`,
  red    : s => `\x1b[31m${s}\x1b[0m`,
  green  : s => `\x1b[32m${s}\x1b[0m`,
  yellow : s => `\x1b[33m${s}\x1b[0m`,
  cyan   : s => `\x1b[36m${s}\x1b[0m`,
  white  : s => `\x1b[37m${s}\x1b[0m`,
};

// ── Banner ────────────────────────────────────────────────────────────────────

function printBanner() {
  console.log('');
  console.log(T.cyan(T.bold('  ◆ COLOUR SHIELD  ')) + T.dim('v0.1.0'));
  console.log(T.dim('  Post-quantum package security'));
  console.log(T.dim('  Colour Foundation · Audited by Cure53'));
  console.log('');
}

// ── Paywall helper ────────────────────────────────────────────────────────────

async function requireFeature(featureName, planRequired) {
  const licence = await validateLicence();
  if (!licence.valid || !licence.features || !licence.features.includes(featureName)) {
    console.log(`  ${T.yellow('⚠')}  ${T.bold('This feature requires a paid plan.')}`);
    console.log('');
    console.log(`  ${T.dim('Required:')}  ${planRequired || 'Teams, Business, or Enterprise'}`);
    console.log(`  ${T.dim('Current:')}   Free`);
    console.log('');
    console.log(`  ${T.dim('To upgrade, email:')} buildwithcolours@gmail.com`);
    console.log(`  ${T.dim('Then activate:')}     colour-shield config --license YOUR_KEY`);
    console.log('');
    return false;
  }
  return true;
}

// ── CLI Logger ────────────────────────────────────────────────────────────────

const cliLogger = {
  verifying(name, version) {
    process.stdout.write(`  ${T.dim('▸')} Verifying ${T.bold(name)}${version ? T.dim('@' + version) : ''}... `);
  },
  verified(result) {
    console.log(T.green('✓ SAFE'));
    for (const w of result.warnings) {
      console.log(`    ${T.yellow('⚠')}  ${T.dim(w.message)}`);
    }
  },
  warned(result) {
    console.log(T.yellow('⚠ WARNING'));
    for (const w of result.warnings) {
      console.log(`    ${T.yellow('⚠')}  ${w.message}`);
      if (w.detail) console.log(`       ${T.dim(w.detail)}`);
    }
  },
  blocked(result) {
    console.log(T.red('✗ BLOCKED'));
    console.log('');
    for (const threat of result.threats) {
      console.log(`    ${T.red('▲')}  ${T.bold(threat.type)} ${T.dim('[' + threat.severity + ']')}`);
      console.log(`       ${T.red(threat.message)}`);
      if (threat.detail)        console.log(`       ${T.dim(threat.detail)}`);
      if (threat.likely_target) console.log(`       ${T.dim('Did you mean:')} ${T.bold(threat.likely_target)}?`);
      if (threat.cve)           console.log(`       ${T.dim('CVE:')} ${threat.cve}`);
    }
    console.log('');
    console.log(`    ${T.dim('Installation prevented. Entry written to audit log.')}`);
    console.log(`    ${T.dim('Enterprise support:')} buildwithcolours@gmail.com`);
    console.log('');
  },
  warningsSummary(warned) {
    console.log('');
    console.log(`  ${T.yellow('⚠')}  ${warned.length} package(s) have warnings — proceeding with installation`);
    console.log('');
  },
};

function onBlock(blocked) {
  console.log('');
  console.log(T.red(T.bold(`  ✗  Installation blocked — ${blocked.length} threat(s) detected`)));
  console.log(T.dim('  Your system is protected. No packages were installed.'));
  console.log('');
}

// ── Ecosystem wrappers ────────────────────────────────────────────────────────

function makeEcosystemCommand(name, description) {
  return program
    .command(`${name} [args...]`)
    .description(description)
    .allowUnknownOption()
    .action(async (args) => {
      printBanner();
      try { await intercept(name, args, { logger: cliLogger, onBlock }); }
      catch (err) {
        if (err.code !== 'CS_BLOCKED') console.error(T.red(`  Error: ${err.message}`));
        process.exit(1);
      }
    });
}

program.name('colour-shield').alias('cs').description('Post-quantum package security').version('0.1.0', '-v, --version');

makeEcosystemCommand('npm',   'Secure npm wrapper');
makeEcosystemCommand('yarn',  'Secure yarn wrapper');
makeEcosystemCommand('pnpm',  'Secure pnpm wrapper');
makeEcosystemCommand('bun',   'Secure bun wrapper');
makeEcosystemCommand('pip',   'Secure pip wrapper');
makeEcosystemCommand('pip3',  'Secure pip3 wrapper');
makeEcosystemCommand('cargo', 'Secure cargo wrapper');

// ── scan ──────────────────────────────────────────────────────────────────────

program
  .command('scan <package>')
  .description('Scan a package without installing it')
  .option('-e, --ecosystem <ecosystem>', 'npm | pip | cargo', 'npm')
  .action(async (pkg, opts) => {
    printBanner();
    let name, version;
    if (pkg.startsWith('@')) {
      const rest = pkg.slice(1); const atIdx = rest.indexOf('@');
      name    = atIdx === -1 ? pkg : '@' + rest.slice(0, atIdx);
      version = atIdx === -1 ? null : rest.slice(atIdx + 1) || null;
    } else {
      const atIdx = pkg.indexOf('@');
      name    = atIdx === -1 ? pkg : pkg.slice(0, atIdx);
      version = atIdx === -1 ? null : pkg.slice(atIdx + 1) || null;
    }
    console.log(`  ${T.dim('Scanning')} ${T.bold(name)}${version ? T.dim('@' + version) : ''} ${T.dim('[' + opts.ecosystem + ']')}`);
    console.log('');
    const result = await verifyPackage(name, version, opts.ecosystem);
    if (result.passed) {
      console.log(`  ${T.green('✓')}  ${T.bold(name)} — ${T.green(T.bold('SAFE'))}`);
      if (result.hash) console.log(`     ${T.dim('Hash:')} ${T.dim(result.hash.slice(0, 16) + '…')}`);
      for (const w of result.warnings) {
        console.log(`  ${T.yellow('⚠')}  ${w.message}`);
        if (w.detail) console.log(`     ${T.dim(w.detail)}`);
      }
    } else {
      console.log(`  ${T.red('✗')}  ${T.bold(name)} — ${T.red(T.bold('UNSAFE'))}`);
      console.log('');
      for (const threat of result.threats) {
        console.log(`  ${T.red('▲')}  ${T.bold(threat.type)} ${T.dim('[' + threat.severity + ']')}`);
        console.log(`     ${threat.message}`);
        if (threat.likely_target) console.log(`     ${T.dim('Did you mean:')} ${T.bold(threat.likely_target)}?`);
      }
    }
    console.log('');
  });

// ── audit ─────────────────────────────────────────────────────────────────────

program
  .command('audit')
  .description('View your local security audit log')
  .option('--verify-chain', 'Verify chain integrity')
  .option('--full',         'Show individual entries')
  .option('--json',         'Output raw JSON')
  .action(async (opts) => {
    printBanner();

    if (opts.verifyChain) {
      const chain = verifyAuditChain();
      console.log(chain.valid
        ? `  ${T.green('✓')}  Chain ${T.green(T.bold('VALID'))} — ${chain.entries} entries verified`
        : `  ${T.red('✗')}  Chain ${T.red(T.bold('TAMPERED'))}`);
      console.log(''); return;
    }

    const summary = getAuditSummary();
    if (opts.json) { console.log(JSON.stringify(summary, null, 2)); return; }

    console.log(`  ${T.bold('Audit Summary')}\n  ${T.dim('Log:')} ${T.dim(AUDIT_FILE)}\n`);
    console.log(`  Total     ${T.bold(summary.total)}`);
    console.log(`  Blocked   ${summary.blocked > 0 ? T.red(T.bold(summary.blocked)) : T.dim('0')}`);
    console.log(`  Warnings  ${summary.warnings > 0 ? T.yellow(summary.warnings) : T.dim('0')}`);
    console.log(`  Clean     ${T.green(summary.clean)}`);
    console.log('');

    if (opts.full && summary.log.length > 0) {
      const recent = summary.log.slice(-20).reverse();
      console.log(`  ${T.bold('Recent entries:')}\n`);
      for (const entry of recent) {
        const icon = entry.passed ? T.green('✓') : T.red('✗');
        console.log(`  ${icon}  ${T.bold(entry.package + '@' + entry.version)} ${T.dim(new Date(entry.timestamp).toLocaleString())}`);
        if (!entry.passed) for (const t of entry.threats) console.log(`     ${T.red('▲')} ${t.type}: ${t.message}`);
      }
      console.log('');
    }

    if (summary.total === 0) {
      console.log(`  ${T.dim('No packages scanned yet. Try: colour-shield scan express')}\n`);
    }
  });

// ── report [PAID] ─────────────────────────────────────────────────────────────

program
  .command('report')
  .description('Export compliance report [Teams, Business, Enterprise]')
  .option('-o, --output <file>', 'Write report to file')
  .action(async (opts) => {
    printBanner();
    const allowed = await requireFeature('compliance_reports', 'Teams, Business, or Enterprise');
    if (!allowed) { process.exit(1); return; }

    const report = exportAuditReport();
    const json   = JSON.stringify(report, null, 2);

    if (opts.output) {
      const fs = require('fs');
      fs.writeFileSync(opts.output, json);
      console.log(`  ${T.green('✓')}  Report written to ${opts.output}\n`);
    } else {
      console.log(json);
    }
  });

// ── config ────────────────────────────────────────────────────────────────────

program
  .command('config')
  .description('Configure Colour Shield settings')
  .option('--license <key>',   'Activate a licence key')
  .option('--domain <domain>', 'Set your organisation domain')
  .action(async (opts) => {
    printBanner();
    if (opts.license) {
      const result = storeLicence(opts.license, opts.domain);
      if (result.success) {
        console.log(`  ${T.green('✓')}  Licence activated: ${T.bold(opts.license)}`);
        console.log(`     ${T.dim('Run: colour-shield licence --status to verify')}`);
      } else {
        console.log(`  ${T.red('✗')}  ${result.error}`);
        process.exit(1);
      }
    } else {
      console.log(`  ${T.dim('Usage: colour-shield config --license CS-XXXX-XXXX-XXXX-XXXX')}`);
    }
    console.log('');
  });

// ── licence ───────────────────────────────────────────────────────────────────

program
  .command('licence')
  .description('View or manage your Colour Shield licence')
  .option('--status', 'Show current licence status')
  .option('--clear',  'Remove stored licence')
  .action(async (opts) => {
    printBanner();

    if (opts.clear) {
      const result = clearLicence();
      console.log(result.success
        ? `  ${T.green('✓')}  Licence cleared. Reverted to free tier.`
        : `  ${T.red('✗')}  ${result.error}`);
      console.log(''); return;
    }

    const status = await getLicenceStatus();

    if (status.status === 'free') {
      console.log(`  ${T.bold('Plan')}        Free`);
      console.log(`  ${T.dim('No licence key active.')}`);
      console.log('');
      console.log(`  ${T.dim('To activate:')}  colour-shield config --license CS-XXXX-XXXX-XXXX-XXXX`);
      console.log(`  ${T.dim('Get a licence:')} buildwithcolours@gmail.com`);
    } else {
      const planColors = { teams: T.cyan, business: T.green, enterprise: T.yellow };
      const colorFn    = planColors[status.plan] || T.white;
      console.log(`  ${T.bold('Plan')}        ${colorFn(T.bold(status.plan.toUpperCase()))}`);
      console.log(`  ${T.bold('Key')}         ${T.dim(status.key)}`);
      console.log(`  ${T.bold('Domain')}      ${status.domain}`);
      console.log(`  ${T.bold('Expires')}     ${new Date(status.expires).toLocaleDateString()}`);
      console.log(`  ${T.bold('Days left')}   ${status.days_left <= 7 ? T.red(status.days_left) : T.green(status.days_left)}`);
      console.log(`  ${T.bold('Max devs')}    ${status.max_devs === -1 ? 'Unlimited' : status.max_devs}`);
      console.log('');
      console.log(`  ${T.bold('Features:')}`);
      for (const f of status.features) console.log(`    ${T.green('✓')}  ${f.replace(/_/g, ' ')}`);
      if (status.days_left <= 7) {
        console.log('');
        console.log(`  ${T.yellow('⚠')}  Expires in ${status.days_left} days. Renew: buildwithcolours@gmail.com`);
      }
    }
    console.log('');
  });

// ── test ──────────────────────────────────────────────────────────────────────

program
  .command('test')
  .description('Run self-test')
  .action(async () => {
    printBanner();
    console.log(`  ${T.bold('Self-test')}\n`);

    const tests = [
      { name: 'Safe package passes',     run: async () => { const r = await verifyPackage('express', null, 'npm'); if (!r.passed) throw new Error('should pass'); } },
      { name: 'Typosquat blocked',       run: async () => { const r = await verifyPackage('axois', null, 'npm'); if (r.passed) throw new Error('should block'); } },
      { name: 'Fuzzy typosquat blocked', run: async () => { const r = await verifyPackage('expresss', null, 'npm'); if (r.passed) throw new Error('should block'); } },
      { name: 'Known malicious blocked', run: async () => { const r = await verifyPackage('event-stream', '3.3.6', 'npm'); if (r.passed) throw new Error('should block'); } },
      { name: 'Audit chain valid',       run: async () => { const { logVerification, verifyAuditChain } = require('./audit'); const r = await verifyPackage('chalk', null, 'npm'); logVerification(r); if (!verifyAuditChain().valid) throw new Error('chain invalid'); } },
      { name: 'Scoped package parsing',  run: async () => { const { parsePackageArg } = require('./interceptor'); const r = parsePackageArg('@scope/pkg@1.0.0'); if (r.name !== '@scope/pkg') throw new Error('name'); if (r.version !== '1.0.0') throw new Error('version'); } },
      { name: 'Flag filtering works',    run: async () => { const { extractPackages } = require('./interceptor'); const p = extractPackages(['install', 'express', '--save-dev', 'lodash']); if (!p.includes('express')) throw new Error('express missing'); if (p.includes('--save-dev')) throw new Error('flag not filtered'); } },
    ];

    let passed = 0; let failed = 0;
    for (const test of tests) {
      process.stdout.write(`  ${T.dim('·')} ${test.name}... `);
      try { await test.run(); console.log(T.green('✓')); passed++; }
      catch (err) { console.log(T.red('✗')); console.log(`    ${T.red(err.message)}`); failed++; }
    }

    console.log('');
    console.log(`  ${T.bold('Results:')} ${T.green(passed + ' passed')} ${failed > 0 ? T.red(failed + ' failed') : T.dim('0 failed')}`);
    console.log('');
    if (failed === 0) console.log(`  ${T.green('✓')}  Colour Shield operational\n`);
    else process.exit(1);
  });

// ── Default ───────────────────────────────────────────────────────────────────

program.parse(process.argv);
if (!process.argv.slice(2).length) { printBanner(); program.outputHelp(); }
